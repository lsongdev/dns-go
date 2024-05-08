package packet

import (
	"bytes"
)

type DNSResourceRecordNS struct {
	DNSResourceRecord

	NameServer string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordNS) Decode(reader *bytes.Reader, length uint16) {
	d.NameServer, _ = decodeDomainName(reader)
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordNS.DNSResourceRecord.
func (d *DNSResourceRecordNS) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, d.NameServer)
	return buf.Bytes()
}
