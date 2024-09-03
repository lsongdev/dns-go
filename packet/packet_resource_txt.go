package packet

import (
	"bytes"
)

type DNSResourceRecordTXT struct {
	DNSResourceRecord

	Content string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordTXT) Decode(reader *bytes.Reader, length uint16) {
	data := make([]byte, length)
	reader.Read(data)
	d.Content = string(data)
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordTXT.DNSResourceRecord.
func (d *DNSResourceRecordTXT) Encode() []byte {
	var buf bytes.Buffer
	buf.Write([]byte(d.Content))
	return buf.Bytes()
}

func (a *DNSResourceRecordTXT) Bytes() []byte {
	return a.WrapData(a.Encode())
}
