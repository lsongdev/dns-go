package packet

import (
	"bytes"
	"net"
)

type DNSResourceRecordAAAA struct {
	DNSResourceRecord

	Address string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordAAAA) Decode(reader *bytes.Reader, length uint16) {
	data := make([]byte, length)
	reader.Read(data)
	d.Address = net.IP(data).String()
}

func (d *DNSResourceRecordAAAA) Encode() []byte {
	return net.ParseIP(d.Address).To16()
}

func (a *DNSResourceRecordAAAA) Bytes() []byte {
	return a.WrapData(a.Encode())
}
