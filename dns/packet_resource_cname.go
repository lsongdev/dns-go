package dns

import "bytes"

type DNSResourceRecordCNAME struct {
	DNSResourceRecord

	Domain string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordCNAME) Decode(reader *bytes.Reader, length uint16) {
	d.Domain, _ = decodeDomainName(reader)
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordCNAME.DNSResourceRecord.
func (d *DNSResourceRecordCNAME) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, d.Domain)
	return buf.Bytes()
}
