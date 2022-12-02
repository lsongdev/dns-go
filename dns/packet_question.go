package dns

import (
	"bytes"
	"encoding/binary"
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
	encodeDomainName(&buf, q.Name)
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
