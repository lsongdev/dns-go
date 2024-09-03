package packet

import (
	"bytes"
	"encoding/binary"
)

type DNSResourceRecordEDNS struct {
	DNSResourceRecord

	UDPSize  uint16
	ExtRCode uint8
	Version  uint8
	Flags    uint16
	Options  []EDNSOption
}

type EDNSOption struct {
	Code uint16
	Data []byte
}

// Decode implements DNSResource.
func (d *DNSResourceRecordEDNS) Decode(reader *bytes.Reader, length uint16) {
	d.UDPSize = uint16(d.Class)
	d.ExtRCode = uint8(d.TTL >> 24)
	d.Version = uint8((d.TTL >> 16) & 0xFF)
	d.Flags = uint16(d.TTL & 0xFFFF)

	for reader.Len() > 0 {
		var option EDNSOption
		binary.Read(reader, binary.BigEndian, &option.Code)
		var optionLength uint16
		binary.Read(reader, binary.BigEndian, &optionLength)
		option.Data = make([]byte, optionLength)
		reader.Read(option.Data)
		d.Options = append(d.Options, option)
	}
}

// Encode implements DNSResource.
func (d *DNSResourceRecordEDNS) Encode() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, d.UDPSize)
	binary.Write(&buf, binary.BigEndian, d.ExtRCode)
	binary.Write(&buf, binary.BigEndian, d.Version)
	binary.Write(&buf, binary.BigEndian, d.Flags)

	for _, option := range d.Options {
		binary.Write(&buf, binary.BigEndian, option.Code)
		binary.Write(&buf, binary.BigEndian, uint16(len(option.Data)))
		buf.Write(option.Data)
	}

	return buf.Bytes()
}

func (a *DNSResourceRecordEDNS) Bytes() []byte {
	return a.WrapData(a.Encode())
}
