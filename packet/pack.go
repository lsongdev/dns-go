package packet

import (
	"bytes"
	"encoding/binary"
	"strings"
)

const (
	// MaxMessageSize is the largest DNS message any transport can carry.
	MaxMessageSize = 65535
	// MinUDPSize is the payload every UDP client must accept (RFC 1035).
	MinUDPSize = 512

	maxCompressionOffset = 0x3FFF
)

// encoder builds a wire-format message with RFC 1035 §4.1.4 name compression.
type encoder struct {
	buf   []byte
	names map[string]int // lower-cased name suffix -> offset of its first label
}

func newEncoder() *encoder {
	return &encoder{buf: make([]byte, 0, 512), names: make(map[string]int)}
}

func (e *encoder) u16(v uint16) { e.buf = binary.BigEndian.AppendUint16(e.buf, v) }
func (e *encoder) u32(v uint32) { e.buf = binary.BigEndian.AppendUint32(e.buf, v) }
func (e *encoder) raw(b []byte) { e.buf = append(e.buf, b...) }

// name writes a domain name. Every written suffix becomes a pointer target;
// compress controls whether this name may itself be replaced by a pointer,
// which RFC 3597 §4 limits to owner names and RFC 1035 RDATA names.
func (e *encoder) name(name string, compress bool) {
	labels := splitLabels(name)
	for i := range labels {
		suffix := strings.ToLower(strings.Join(labels[i:], "."))
		if off, ok := e.names[suffix]; ok && compress {
			e.u16(0xC000 | uint16(off))
			return
		}
		if off := len(e.buf); off <= maxCompressionOffset {
			if _, ok := e.names[suffix]; !ok {
				e.names[suffix] = off
			}
		}
		e.buf = append(e.buf, byte(len(labels[i])))
		e.buf = append(e.buf, labels[i]...)
	}
	e.buf = append(e.buf, 0)
}

func splitLabels(name string) []string {
	parts := strings.Split(strings.TrimRight(name, "."), ".")
	labels := parts[:0]
	for _, label := range parts {
		if label != "" {
			labels = append(labels, label)
		}
	}
	return labels
}

func (e *encoder) header(h DNSHeader) { e.raw(h.Bytes()) }

func (e *encoder) question(q *DNSQuestion) {
	e.name(q.Name, true)
	e.u16(uint16(q.Type))
	e.u16(uint16(q.Class))
}

// rdataPacker is implemented by the RFC 1035 types whose RDATA names may be
// compressed. All other types use their uncompressed Encode output.
type rdataPacker interface {
	packRData(e *encoder)
}

// resource never mutates r, so shared records can be encoded concurrently.
func (e *encoder) resource(r DNSResource) {
	h := *r.Header()
	if opt, ok := r.(*DNSResourceRecordEDNS); ok {
		h.Name, h.Type, h.Class, h.TTL = ".", DNSTypeEDNS, DNSClass(opt.UDPSize), opt.wireTTL()
	}
	e.name(h.Name, true)
	e.u16(uint16(h.Type))
	e.u16(uint16(h.Class))
	e.u32(h.TTL)
	lengthAt := len(e.buf)
	e.u16(0)
	if p, ok := r.(rdataPacker); ok {
		p.packRData(e)
	} else {
		e.raw(r.Encode())
	}
	binary.BigEndian.PutUint16(e.buf[lengthAt:], uint16(len(e.buf)-lengthAt-2))
}

// Bytes encodes the full message with name compression and no size limit
// beyond the 64 KiB protocol maximum.
func (p *DNSPacket) Bytes() []byte {
	data, _ := p.Pack(MaxMessageSize)
	return data
}

// Pack encodes the message so that it fits in limit bytes, reporting whether
// it had to set TC. Records are dropped in this order:
//  1. additional records other than OPT (TC stays clear unless the message is
//     a referral, whose glue is mandatory per RFC 9471);
//  2. everything except the question and OPT, with TC set.
//
// The packet itself is never modified.
func (p *DNSPacket) Pack(limit int) ([]byte, bool) {
	if limit <= 0 || limit > MaxMessageSize {
		limit = MaxMessageSize
	}
	var h DNSHeader
	if p.Header != nil {
		h = *p.Header
	}
	opt := p.OPT()

	if data := p.encode(h, p.Answers, p.Authorities, p.Additionals); len(data) <= limit {
		return data, false
	}
	var optOnly []DNSResource
	if opt != nil {
		optOnly = []DNSResource{opt}
	}
	if len(p.Additionals) > len(optOnly) {
		truncated := p.isReferral()
		if truncated {
			h.TC = 1
		}
		if data := p.encode(h, p.Answers, p.Authorities, optOnly); len(data) <= limit {
			return data, truncated
		}
	}
	h.TC = 1
	return p.encode(h, nil, nil, optOnly), true
}

func (p *DNSPacket) encode(h DNSHeader, answers, authorities, additionals []DNSResource) []byte {
	h.QDCount = uint16(len(p.Questions))
	h.ANCount = uint16(len(answers))
	h.NSCount = uint16(len(authorities))
	h.ARCount = uint16(len(additionals))
	e := newEncoder()
	e.header(h)
	for _, q := range p.Questions {
		e.question(q)
	}
	for _, section := range [][]DNSResource{answers, authorities, additionals} {
		for _, r := range section {
			e.resource(r)
		}
	}
	return e.buf
}

func (p *DNSPacket) isReferral() bool {
	if len(p.Answers) > 0 || (p.Header != nil && p.Header.AA == 1) {
		return false
	}
	for _, r := range p.Authorities {
		if r.GetType() == DNSTypeNS {
			return true
		}
	}
	return false
}

// OPT returns the message's EDNS OPT pseudo-record, or nil.
func (p *DNSPacket) OPT() *DNSResourceRecordEDNS {
	for _, r := range p.Additionals {
		if opt, ok := r.(*DNSResourceRecordEDNS); ok {
			return opt
		}
	}
	return nil
}

// SetOPT replaces any existing OPT record; nil removes it.
func (p *DNSPacket) SetOPT(opt *DNSResourceRecordEDNS) {
	kept := make([]DNSResource, 0, len(p.Additionals)+1)
	for _, r := range p.Additionals {
		if r.GetType() != DNSTypeEDNS {
			kept = append(kept, r)
		}
	}
	if opt != nil {
		kept = append(kept, opt)
	}
	p.Additionals = kept
}

// RCode returns the full 12-bit response code (header bits plus OPT bits).
func (p *DNSPacket) RCode() uint16 {
	rcode := uint16(p.Header.RCode & 0x0F)
	if opt := p.OPT(); opt != nil {
		rcode |= uint16(opt.ExtRCode) << 4
	}
	return rcode
}

// SetRCode stores rcode across the header and, for extended codes, the OPT
// record (which is created when missing).
func (p *DNSPacket) SetRCode(rcode uint16) {
	p.Header.RCode = uint8(rcode & 0x0F)
	opt := p.OPT()
	if rcode > 0x0F && opt == nil {
		opt = NewEDNSRecord(MinUDPSize)
		p.SetOPT(opt)
	}
	if opt != nil {
		opt.ExtRCode = uint8(rcode >> 4)
	}
}

// CloneResource returns a deep copy of r.
func CloneResource(r DNSResource) (DNSResource, error) {
	return ParseResource(bytes.NewReader(r.Bytes()))
}
