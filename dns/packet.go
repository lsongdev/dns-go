package dns

import (
	"bytes"
	"fmt"
)

// DNSType defines the type of data being requested/returned in a
// question/answer.
type DNSType uint16

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
const (
	DNSTypeA     DNSType = 0x01 // a host address
	DNSTypeNS    DNSType = 0x02 // an authoritative name server
	DNSTypeMD    DNSType = 0x03 // a mail destination (Obsolete - use MX)
	DNSTypeMF    DNSType = 0x04 // a mail forwarder (Obsolete - use MX)
	DNSTypeCNAME DNSType = 0x05 // the canonical name for an alias
	DNSTypeSOA   DNSType = 0x06 // marks the start of a zone of authority
	DNSTypeMB    DNSType = 0x07 // a mailbox domain name (EXPERIMENTAL)
	DNSTypeMG    DNSType = 0x08 // a mail group member (EXPERIMENTAL)
	DNSTypeMR    DNSType = 0x09 // a mail rename domain name (EXPERIMENTAL)
	DNSTypeNULL  DNSType = 0x0A // a null RR (EXPERIMENTAL)
	DNSTypeWKS   DNSType = 0x0B // a well known service description
	DNSTypePTR   DNSType = 0x0C // a domain name pointer
	DNSTypeHINFO DNSType = 0x0D // host information
	DNSTypeMINFO DNSType = 0x0E // mailbox or mail list information
	DNSTypeMX    DNSType = 0x0F // mail exchange
	DNSTypeTXT   DNSType = 0x10 // text strings
	DNSTypeAAAA  DNSType = 0x1C // a ipv6 host address
	DNSTypeSRV   DNSType = 0x21 // a service location
	DNSTypeEDNS  DNSType = 0x29 // extensible dns
	DNSTypeSPF   DNSType = 0x63 // a Sender Policy Framework record
	DNSTypeAXFR  DNSType = 0xFC // A request for a transfer of an entire zone
	DNSTypeMAILB DNSType = 0xFD // A request for mailbox-related records (MB, MG or MR)
	DNSTypeMAILA DNSType = 0xFE // A request for mail agent RRs (Obsolete - see MX)
	DNSTypeAny   DNSType = 0xFF // A request for all records
)

// DNSClass defines the class associated with a request/response.  Different DNS
// classes can be thought of as an array of parallel namespace trees.
type DNSClass uint16

// DNSClass known values.
const (
	DNSClassIN  DNSClass = 0x01 // Internet
	DNSClassCS  DNSClass = 0x02 // the CSNET class (Obsolete)
	DNSClassCH  DNSClass = 0x03 // the CHAOS class
	DNSClassHS  DNSClass = 0x04 // Hesiod [Dyer 87]
	DNSClassAny DNSClass = 0xFF // AnyClass
)

func (dc DNSClass) String() string {
	switch dc {
	default:
		return "Unknown"
	case DNSClassIN:
		return "IN"
	case DNSClassCS:
		return "CS"
	case DNSClassCH:
		return "CH"
	case DNSClassHS:
		return "HS"
	case DNSClassAny:
		return "Any"
	}
}

// DNSOpCode defines a set of different operation types.
type DNSOpCode uint8

// DNSOpCode known values.
const (
	DNSOpCodeQuery  DNSOpCode = 0 // Query                  [RFC1035]
	DNSOpCodeIQuery DNSOpCode = 1 // Inverse Query Obsolete [RFC3425]
	DNSOpCodeStatus DNSOpCode = 2 // Status                 [RFC1035]
	DNSOpCodeNotify DNSOpCode = 4 // Notify                 [RFC1996]
	DNSOpCodeUpdate DNSOpCode = 5 // Update                 [RFC2136]
)

func (code DNSOpCode) String() string {
	switch code {
	case DNSOpCodeQuery:
		return "Query"
	case DNSOpCodeIQuery:
		return "Inverse Query"
	case DNSOpCodeStatus:
		return "Status"
	case DNSOpCodeNotify:
		return "Notify"
	case DNSOpCodeUpdate:
		return "Update"
	default:
		return "Unknown"
	}
}

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

func (packet *DNSPacket) Bytes() []byte {
	var buf bytes.Buffer
	buf.Write(packet.Header.Bytes())
	for _, question := range packet.Questions {
		buf.Write(question.Bytes())
	}
	for _, answer := range packet.Answers {
		buf.Write(answer.Bytes())
	}
	for _, authority := range packet.Authorities {
		buf.Write(authority.Bytes())
	}
	for _, additional := range packet.Additionals {
		buf.Write(additional.Bytes())
	}
	return buf.Bytes()
}

func (p *DNSPacket) AddQuestion(question *DNSQuestion) {
	p.Questions = append(p.Questions, question)
	p.Header.QDCount = uint16(len(p.Questions))
}

func (p *DNSPacket) AddAnswer(answer DNSResource) {
	p.Answers = append(p.Answers, answer)
}

func (p *DNSPacket) AddAuthority(authority DNSResource) {
	p.Authorities = append(p.Authorities, authority)
}

func (p *DNSPacket) AddAdditional(additional DNSResource) {
	p.Additionals = append(p.Additionals, additional)
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

func (p *DNSPacket) AddQuestionSRV(domain string) {
	p.AddQuestion(&DNSQuestion{
		Name:  domain,
		Type:  DNSTypeSRV,
		Class: DNSClassIN,
	})
}
