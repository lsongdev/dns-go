package packet

import (
	"bytes"
	"reflect"
	"testing"
)

func TestEncodeDecodeDNSHeader(t *testing.T) {
	// Create a sample DNS Header
	header := DNSHeader{
		ID:      123,
		QR:      0,
		OpCode:  0,
		AA:      0,
		TC:      0,
		RD:      1,
		RA:      0,
		Z:       0,
		RCode:   0,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	// Encode the DNS header
	encodedBytes := header.Bytes()

	// Decode the encoded bytes
	decodedPacket := DNSHeader{}
	decodedPacket.Parse(bytes.NewReader(encodedBytes))

	if !reflect.DeepEqual(header, decodedPacket) {
		t.Errorf("Decoded header does not match original header")
	}
}

func TestEncodeDecodeDNSQuestion(t *testing.T) {
	// Create a sample DNS packet
	q := DNSQuestion{
		Name:  "example.com",
		Type:  DNSTypeA,
		Class: DNSClassIN,
	}
	// Encode the DNS packet
	encodedBytes := q.Bytes()
	// Decode the encoded bytes
	decodedPacket := DNSQuestion{}
	decodedPacket.Parse(bytes.NewReader(encodedBytes))
	// Compare original and decoded DNS packets
	if !reflect.DeepEqual(q, decodedPacket) {
		t.Errorf("Decoded DNS question does not match original:\nOriginal: %+v\nDecoded: %+v", q, decodedPacket)
	}
}
