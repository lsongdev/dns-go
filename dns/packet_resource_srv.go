package dns

import (
	"bytes"
	"encoding/binary"
)

type DNSResourceRecordSRV struct {
	DNSResourceRecord

	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordSRV) Decode(reader *bytes.Reader, length uint16) {
	binary.Read(reader, binary.BigEndian, &d.Priority)
	binary.Read(reader, binary.BigEndian, &d.Weight)
	binary.Read(reader, binary.BigEndian, &d.Port)
	d.Target, _ = decodeDomainName(reader)
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordSRV.DNSResourceRecord.
func (d *DNSResourceRecordSRV) Encode() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, d.Priority)
	binary.Write(&buf, binary.BigEndian, d.Weight)
	binary.Write(&buf, binary.BigEndian, d.Port)
	encodeDomainName(&buf, d.Target)
	return buf.Bytes()
}
