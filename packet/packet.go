package packet

import (
	"bytes"
	"fmt"
)

// DNS contains data from a single Domain Name Service packet.
// DNS is specified in RFC 1034 / RFC 1035
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
type DNSPacket struct {
	Header      *DNSHeader
	Questions   []*DNSQuestion
	Answers     []DNSResource
	Authorities []DNSResource
	Additionals []DNSResource
}

func NewPacket() *DNSPacket {
	return &DNSPacket{
		Header: NewHeader(),
	}
}

// NewReply returns an empty response to req: same ID, opcode, question, and
// RD/CD bits, with QR set. The request is not modified.
func NewReply(req *DNSPacket) *DNSPacket {
	h := &DNSHeader{QR: DNSResponse}
	if req.Header != nil {
		h.ID = req.Header.ID
		h.OpCode = req.Header.OpCode
		h.RD = req.Header.RD
		h.CD = req.Header.CD
	}
	return &DNSPacket{
		Header:    h,
		Questions: append([]*DNSQuestion(nil), req.Questions...),
	}
}

// DecodeFromBytes decodes the slice into the DNS struct.
func FromBytes(data []byte) (d *DNSPacket, err error) {
	d = &DNSPacket{}
	// Create a reader with the data
	reader := bytes.NewReader(data)
	// Decode the DNS header
	d.Header = &DNSHeader{}
	if err := d.Header.Parse(reader); err != nil {
		return nil, fmt.Errorf("error decoding DNS header: %v", err)
	}
	// Decode questions
	for i := 0; i < int(d.Header.QDCount); i++ {
		question := &DNSQuestion{}
		if err := question.Parse(reader); err != nil {
			return nil, fmt.Errorf("error decoding DNS question: %v", err)
		}
		d.Questions = append(d.Questions, question)
	}
	// Decode answers
	for i := 0; i < int(d.Header.ANCount); i++ {
		answer, err := ParseResource(reader)
		if err != nil {
			return nil, fmt.Errorf("error decoding DNS answer: %v", err)
		}
		d.Answers = append(d.Answers, answer)
	}
	// Decode authorities
	for i := 0; i < int(d.Header.NSCount); i++ {
		authority, err := ParseResource(reader)
		if err != nil {
			return nil, fmt.Errorf("error decoding DNS authority: %v", err)
		}
		d.Authorities = append(d.Authorities, authority)
	}
	// Decode additionals
	for i := 0; i < int(d.Header.ARCount); i++ {
		additional, err := ParseResource(reader)
		if err != nil {
			return nil, fmt.Errorf("error decoding DNS additional: %v", err)
		}
		d.Additionals = append(d.Additionals, additional)
	}
	return d, err
}

func (p *DNSPacket) AddQuestion(question *DNSQuestion) {
	p.Questions = append(p.Questions, question)
	p.Header.QDCount = uint16(len(p.Questions))
}

func (p *DNSPacket) AddAnswer(answer DNSResource) {
	p.Answers = append(p.Answers, answer)
	p.Header.ANCount = uint16(len(p.Answers))
}

func (p *DNSPacket) AddAuthority(authority DNSResource) {
	p.Authorities = append(p.Authorities, authority)
	p.Header.NSCount = uint16(len(p.Authorities))
}

func (p *DNSPacket) AddAdditional(additional DNSResource) {
	p.Additionals = append(p.Additionals, additional)
	p.Header.ARCount = uint16(len(p.Additionals))
}

func (p *DNSPacket) AddQuestionA(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeA,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionAAAA(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeAAAA,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionCNAME(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeCNAME,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionMX(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeMX,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionNS(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeNS,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionTXT(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeTXT,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionSOA(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeSOA,
		Class: DNSClassIN,
	})
}

func (p *DNSPacket) AddQuestionPTR(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypePTR,
		Class: DNSClassIN,
	})
}

// AddAdditionalEDNS adds an EDNS0 OPT record to the additional section.
func (p *DNSPacket) AddAdditionalEDNS(udpSize uint16, extRCode uint8, version uint8, do bool) {
	opt := NewEDNSRecord(udpSize)
	opt.ExtRCode = extRCode
	opt.Version = version
	opt.SetDNSSECOK(do)
	p.AddAdditional(opt)
}

func (p *DNSPacket) AddQuestionSRV(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeSRV,
		Class: DNSClassIN,
	})
}
