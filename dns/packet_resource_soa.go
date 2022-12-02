package dns

import (
	"bytes"
	"encoding/binary"
)

// SOA RDATA format
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     MNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     RNAME                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    SERIAL                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    REFRESH                    |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     RETRY                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    EXPIRE                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    MINIMUM                    |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSResourceRecordSOA represents the SOA resource record data.
type DNSResourceRecordSOA struct {
	DNSResourceRecord
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (d *DNSResourceRecordSOA) Decode(reader *bytes.Reader, length uint16) {
	d.MName, _ = decodeDomainName(reader)
	d.RName, _ = decodeDomainName(reader)
	binary.Read(reader, binary.BigEndian, &d.Serial)
	binary.Read(reader, binary.BigEndian, &d.Refresh)
	binary.Read(reader, binary.BigEndian, &d.Retry)
	binary.Read(reader, binary.BigEndian, &d.Expire)
	binary.Read(reader, binary.BigEndian, &d.Minimum)
}

func (d *DNSResourceRecordSOA) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, d.MName)
	encodeDomainName(&buf, d.RName)
	// Serial
	binary.Write(&buf, binary.BigEndian, d.Serial)
	// Refresh
	binary.Write(&buf, binary.BigEndian, d.Refresh)
	// Retry
	binary.Write(&buf, binary.BigEndian, d.Retry)
	// Expire
	binary.Write(&buf, binary.BigEndian, d.Expire)
	// Minimum
	binary.Write(&buf, binary.BigEndian, d.Minimum)
	return buf.Bytes()
}
