package packet

import (
	"bytes"
	"net"
)

type DNSResourceRecordA struct {
	DNSResourceRecord

	Address string
}

// decode implements DNSResourceRecordData.
func (a *DNSResourceRecordA) Decode(reader *bytes.Reader, length uint16) {
	data := make([]byte, length)
	reader.Read(data)
	a.Address = net.IP(data).String()
}

func (a *DNSResourceRecordA) Encode() []byte {
	return net.ParseIP(a.Address).To4()
}

func (a *DNSResourceRecordA) Bytes() []byte {
	return a.WrapData(a.Encode())
}
