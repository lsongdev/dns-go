package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type DNSResource interface {
	Bytes() []byte
	GetType() DNSType
	Encode() []byte
	Decode(reader *bytes.Reader, length uint16)
}

// DNSResourceRecord
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type DNSResourceRecord struct {
	Name  string
	Type  DNSType
	Class DNSClass
	TTL   uint32
}

func (r *DNSResourceRecord) GetType() DNSType {
	return r.Type
}

func ParseResource(reader *bytes.Reader) (record DNSResource, err error) {
	r := DNSResourceRecord{}
	if r.Name, err = decodeDomainName(reader); err != nil {
		return
	}
	if err = binary.Read(reader, binary.BigEndian, &r.Type); err != nil {
		return
	}
	if err = binary.Read(reader, binary.BigEndian, &r.Class); err != nil {
		return
	}
	if err = binary.Read(reader, binary.BigEndian, &r.TTL); err != nil {
		return
	}
	switch r.Type {
	case DNSTypeA:
		record = &DNSResourceRecordA{
			DNSResourceRecord: r,
		}
	case DNSTypeAAAA:
		record = &DNSResourceRecordAAAA{
			DNSResourceRecord: r,
		}
	case DNSTypeSOA:
		record = &DNSResourceRecordSOA{
			DNSResourceRecord: r,
		}
	case DNSTypeTXT:
		record = &DNSResourceRecordTXT{
			DNSResourceRecord: r,
		}
	case DNSTypeNS:
		record = &DNSResourceRecordNS{
			DNSResourceRecord: r,
		}
	case DNSTypeSRV:
		record = &DNSResourceRecordSRV{
			DNSResourceRecord: r,
		}
	case DNSTypeCNAME:
		record = &DNSResourceRecordCNAME{
			DNSResourceRecord: r,
		}
	default:
		err = fmt.Errorf("unknown resource record type: %d", r.Type)
		return
	}
	// Read RDLENGTH
	var rdLength uint16
	if err = binary.Read(reader, binary.BigEndian, &rdLength); err != nil {
		return
	}
	// // Read Data
	// data := make([]byte, rdLength)
	// if _, err = reader.Read(data); err != nil {
	// 	return
	// }
	record.Decode(reader, rdLength)
	return
}

func (r *DNSResourceRecord) Encode() []byte {
	panic("unimplemented")
}

func (r *DNSResourceRecord) Bytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(r.Name)
	binary.Write(&buf, binary.BigEndian, r.Type)
	binary.Write(&buf, binary.BigEndian, r.Class)
	binary.Write(&buf, binary.BigEndian, r.TTL)
	// RDATA
	rdData := r.Encode()
	// RDLENGTH (2 bytes)
	rdLength := uint16(len(rdData))
	buf.WriteByte(byte(rdLength >> 8))
	buf.WriteByte(byte(rdLength))
	// // Write Data
	buf.Write(rdData)
	return buf.Bytes()
}

func encodeDomainName(buf *bytes.Buffer, name string) {
	labels := strings.Split(name, ".")
	for _, label := range labels {
		// Write label length
		buf.WriteByte(byte(len(label)))
		// Write label content
		buf.WriteString(label)
	}
	// Write null terminator
	buf.WriteByte(0x00)
}

func decodeDomainName(reader *bytes.Reader) (name string, err error) {
	var parts []string
	for {
		labelLen, err := reader.ReadByte()
		if err != nil {
			return "", fmt.Errorf("error reading label length: %v", err)
		}
		if labelLen == 0 {
			break
		}
		var part string
		if labelLen&0xc0 == 0xc0 {
			part, err = readPointer(reader, labelLen)
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
			break
		}

		labelBytes := make([]byte, labelLen)
		if _, err := io.ReadFull(reader, labelBytes); err != nil {
			return "", fmt.Errorf("error reading label: %v", err)
		}
		parts = append(parts, string(labelBytes))
	}
	name = strings.Join(parts, ".")
	return
}

func readPointer(reader *bytes.Reader, labelLen byte) (name string, err error) {
	pointerByte, err := reader.ReadByte()
	if err != nil {
		return "", fmt.Errorf("error reading pointer byte: %v", err)
	}
	pointer := (uint16(labelLen&0x3f) << 8) | uint16(pointerByte) // 14 bits
	offset, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("error saving current position: %v", err)
	}
	_, err = reader.Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("error seeking to pointer position: %v", err)
	}
	defer func() {
		_, _ = reader.Seek(offset, io.SeekStart)
	}()
	return decodeDomainName(reader)
}
