package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Assuming DNSType and DNSClass are defined elsewhere.
type DNSQuestion struct {
	Name  string
	Type  DNSType
	Class DNSClass
}

func (q *DNSQuestion) Parse(reader *bytes.Reader) error {
	// Decode domain name
	name, err := decodeDomainName(reader)
	if err != nil {
		return err
	}
	q.Name = name
	// Decode type
	typeBytes := make([]byte, 2)
	if _, err := reader.Read(typeBytes); err != nil {
		return err
	}
	q.Type = DNSType(binary.BigEndian.Uint16(typeBytes))
	// Decode class
	classBytes := make([]byte, 2)
	if _, err := reader.Read(classBytes); err != nil {
		return err
	}
	q.Class = DNSClass(binary.BigEndian.Uint16(classBytes))
	return nil
}

func (q *DNSQuestion) Bytes() []byte {
	var buf bytes.Buffer
	// Encode domain name
	encodeDomainName(&buf, q.Name, true)
	// Encode type
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, uint16(q.Type))
	buf.Write(typeBytes)
	// Encode class
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, uint16(q.Class))
	buf.Write(classBytes)
	return buf.Bytes()
}

func encodeDomainName(buf *bytes.Buffer, domain string, addNullTerminator bool) {
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		// Write label length
		buf.WriteByte(byte(len(label)))
		// Write label content
		buf.WriteString(label)
	}
	if addNullTerminator {
		buf.WriteByte(0x00)
	}
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
