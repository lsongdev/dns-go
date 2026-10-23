package packet

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func aRecord(name, addr string) *DNSResourceRecordA {
	return &DNSResourceRecordA{
		DNSResourceRecord: DNSResourceRecord{Name: name, Type: DNSTypeA, Class: DNSClassIN, TTL: 60},
		Address:           addr,
	}
}

func txtRecord(name string, i int) *DNSResourceRecordTXT {
	return &DNSResourceRecordTXT{
		DNSResourceRecord: DNSResourceRecord{Name: name, Type: DNSTypeTXT, Class: DNSClassIN, TTL: 60},
		Content:           fmt.Sprintf("record-%02d-padding-padding-padding-padding", i),
	}
}

func reply(name string, qtype DNSType) *DNSPacket {
	p := &DNSPacket{Header: &DNSHeader{ID: 7, QR: DNSResponse}}
	p.AddQuestion(&DNSQuestion{Name: name, Type: qtype, Class: DNSClassIN})
	return p
}

func TestNameCompression(t *testing.T) {
	p := reply("ns1.t.test", DNSTypeA)
	p.AddAnswer(aRecord("ns1.t.test", "127.0.0.1"))
	p.AddAnswer(&DNSResourceRecordCNAME{
		DNSResourceRecord: DNSResourceRecord{Name: "alias.t.test", Type: DNSTypeCNAME, Class: DNSClassIN, TTL: 60},
		Domain:            "ns1.T.TEST",
	})
	data := p.Bytes()
	// header 12 + question 16 + A (pointer 2 + 10 + 4) + CNAME ("alias" 6 +
	// pointer 2 + 10 + RDATA pointer 2) = 64.
	if len(data) != 64 {
		t.Fatalf("compressed size = %d, want 64", len(data))
	}
	decoded, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Answers[1].(*DNSResourceRecordCNAME).Domain; got != "ns1.t.test" {
		t.Fatalf("CNAME target decoded as %q", got)
	}
}

func TestSRVTargetIsNotCompressed(t *testing.T) {
	p := reply("_sip._tcp.t.test", DNSTypeSRV)
	p.AddAnswer(&DNSResourceRecordSRV{
		DNSResourceRecord: DNSResourceRecord{Name: "_sip._tcp.t.test", Type: DNSTypeSRV, Class: DNSClassIN, TTL: 60},
		Priority:          1, Weight: 1, Port: 5060, Target: "_sip._tcp.t.test",
	})
	data := p.Bytes()
	decoded, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	srv := decoded.Answers[0].(*DNSResourceRecordSRV)
	if srv.Target != "_sip._tcp.t.test" {
		t.Fatalf("SRV target %q", srv.Target)
	}
	// RFC 2782: the target is written in full (18 bytes), not as a pointer.
	if n := len(data); n != 12+22+2+10+6+18 {
		t.Fatalf("size = %d", n)
	}
}

func TestPackTruncatesToLimit(t *testing.T) {
	p := reply("big.t.test", DNSTypeTXT)
	for i := 0; i < 40; i++ {
		p.AddAnswer(txtRecord("big.t.test", i))
	}
	full, truncated := p.Pack(MaxMessageSize)
	if truncated || len(full) <= MinUDPSize {
		t.Fatalf("full message should fit 64K untruncated (len %d)", len(full))
	}
	data, truncated := p.Pack(MinUDPSize)
	if !truncated || len(data) > MinUDPSize {
		t.Fatalf("want truncated message <= 512, got %d bytes, truncated=%v", len(data), truncated)
	}
	decoded, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.TC != 1 || len(decoded.Questions) != 1 || len(decoded.Answers) != 0 {
		t.Fatalf("want TC with question only, got TC=%d an=%d", decoded.Header.TC, len(decoded.Answers))
	}
	if p.Header.TC != 0 || len(p.Answers) != 40 {
		t.Fatal("Pack must not modify the packet")
	}
}

func TestPackKeepsOPTWhenTruncating(t *testing.T) {
	p := reply("big.t.test", DNSTypeTXT)
	for i := 0; i < 40; i++ {
		p.AddAnswer(txtRecord("big.t.test", i))
	}
	p.SetOPT(NewEDNSRecord(1232))
	data, _ := p.Pack(1232)
	decoded, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.OPT() == nil || decoded.Header.TC != 1 {
		t.Fatal("truncated reply must keep OPT and set TC")
	}
}

func TestPackDropsOptionalAdditionalsWithoutTC(t *testing.T) {
	p := reply("t.test", DNSTypeMX)
	p.Header.AA = 1
	p.AddAnswer(&DNSResourceRecordMX{
		DNSResourceRecord: DNSResourceRecord{Name: "t.test", Type: DNSTypeMX, Class: DNSClassIN, TTL: 60},
		Preference:        10, Exchange: "mail.t.test",
	})
	for i := 0; i < 40; i++ {
		p.AddAdditional(txtRecord("mail.t.test", i))
	}
	data, truncated := p.Pack(MinUDPSize)
	decoded, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || decoded.Header.TC != 0 || len(decoded.Answers) != 1 || len(decoded.Additionals) != 0 {
		t.Fatalf("want answer kept, additionals dropped, no TC; got TC=%d an=%d ar=%d",
			decoded.Header.TC, len(decoded.Answers), len(decoded.Additionals))
	}
}

func TestPackSetsTCWhenReferralGlueDoesNotFit(t *testing.T) {
	p := reply("www.child.t.test", DNSTypeA)
	p.AddAuthority(&DNSResourceRecordNS{
		DNSResourceRecord: DNSResourceRecord{Name: "child.t.test", Type: DNSTypeNS, Class: DNSClassIN, TTL: 60},
		NameServer:        "ns.child.t.test",
	})
	for i := 0; i < 40; i++ {
		p.AddAdditional(txtRecord("ns.child.t.test", i))
	}
	data, truncated := p.Pack(MinUDPSize)
	decoded, _ := FromBytes(data)
	if !truncated || decoded.Header.TC != 1 {
		t.Fatal("a referral missing its glue must set TC (RFC 9471)")
	}
}

func TestExtendedRCode(t *testing.T) {
	p := reply("t.test", DNSTypeA)
	p.SetRCode(RCodeBadVersion)
	decoded, err := FromBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.RCode != 0 || decoded.OPT() == nil || decoded.RCode() != RCodeBadVersion {
		t.Fatalf("BADVERS round trip: header=%d full=%d", decoded.Header.RCode, decoded.RCode())
	}
}

func TestHeaderADAndCDBits(t *testing.T) {
	h := DNSHeader{ID: 1, QR: 1, RD: 1, RA: 1, AD: 1, CD: 1, RCode: 3}
	var got DNSHeader
	if err := got.Parse(bytesReader(h.Bytes())); err != nil {
		t.Fatal(err)
	}
	if got.AD != 1 || got.CD != 1 || got.Z != 0 || got.RCode != 3 {
		t.Fatalf("flags round trip: %+v", got)
	}
	if b := h.Bytes()[3]; b != 0x80|0x20|0x10|0x03 {
		t.Fatalf("flag byte = %#x", b)
	}
}

func TestNewReplyDoesNotAliasRequest(t *testing.T) {
	req := NewPacket()
	req.Header.RD, req.Header.CD, req.Header.AD = 1, 1, 1
	req.AddQuestionA("t.test")
	res := NewReply(req)
	res.Header.RCode = 3
	if req.Header.RCode != 0 {
		t.Fatal("reply shares the request header")
	}
	if res.Header.QR != DNSResponse || res.Header.RD != 1 || res.Header.CD != 1 || res.Header.AD != 0 {
		t.Fatalf("reply header %+v", res.Header)
	}
}

// Encoding must not write to records, so shared records (zone data, cache
// entries) can be encoded concurrently. Run with -race.
func TestConcurrentEncodingIsReadOnly(t *testing.T) {
	p := reply("t.test", DNSTypeA)
	p.AddAnswer(aRecord("t.test", "192.0.2.1"))
	opt := NewEDNSRecord(1232)
	opt.SetDNSSECOK(true)
	p.SetOPT(opt)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				q := &DNSPacket{Header: &DNSHeader{}, Questions: p.Questions, Answers: p.Answers, Additionals: p.Additionals}
				q.Bytes()
			}
		}()
	}
	wg.Wait()
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
