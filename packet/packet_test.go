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

func TestEncodeDecodeMXRecord(t *testing.T) {
	mx := &DNSResourceRecordMX{
		DNSResourceRecord: DNSResourceRecord{
			Name:  "example.com",
			Type:  DNSTypeMX,
			Class: DNSClassIN,
			TTL:   300,
		},
		Preference: 10,
		Exchange:   "mail.example.com",
	}

	// Test full packet encoding/decoding
	pkt := NewPacket()
	pkt.AddAnswer(mx)
	
	encoded := pkt.Bytes()
	decoded, err := FromBytes(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	if len(decoded.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(decoded.Answers))
	}
	
	decodedMX, ok := decoded.Answers[0].(*DNSResourceRecordMX)
	if !ok {
		t.Fatalf("Expected MX record, got %T", decoded.Answers[0])
	}
	
	if decodedMX.Preference != mx.Preference {
		t.Errorf("Preference mismatch: expected %d, got %d", mx.Preference, decodedMX.Preference)
	}
	if decodedMX.Exchange != mx.Exchange {
		t.Errorf("Exchange mismatch: expected %s, got %s", mx.Exchange, decodedMX.Exchange)
	}
}

func TestEncodeDecodePTRRecord(t *testing.T) {
	ptr := &DNSResourceRecordPTR{
		DNSResourceRecord: DNSResourceRecord{
			Name:  "1.0.0.127.in-addr.arpa",
			Type:  DNSTypePTR,
			Class: DNSClassIN,
			TTL:   3600,
		},
		PtrDomainName: "localhost",
	}

	// Test full packet encoding/decoding
	pkt := NewPacket()
	pkt.AddAnswer(ptr)
	
	encoded := pkt.Bytes()
	decoded, err := FromBytes(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	if len(decoded.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(decoded.Answers))
	}
	
	decodedPTR, ok := decoded.Answers[0].(*DNSResourceRecordPTR)
	if !ok {
		t.Fatalf("Expected PTR record, got %T", decoded.Answers[0])
	}
	
	if decodedPTR.PtrDomainName != ptr.PtrDomainName {
		t.Errorf("PtrDomainName mismatch: expected %s, got %s", ptr.PtrDomainName, decodedPTR.PtrDomainName)
	}
}

func TestEncodeDecodeARecord(t *testing.T) {
	a := &DNSResourceRecordA{
		DNSResourceRecord: DNSResourceRecord{
			Name:  "example.com",
			Type:  DNSTypeA,
			Class: DNSClassIN,
			TTL:   300,
		},
		Address: "192.168.1.1",
	}

	// Test full packet encoding/decoding
	pkt := NewPacket()
	pkt.AddAnswer(a)
	
	encoded := pkt.Bytes()
	decoded, err := FromBytes(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	if len(decoded.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(decoded.Answers))
	}
	
	decodedA, ok := decoded.Answers[0].(*DNSResourceRecordA)
	if !ok {
		t.Fatalf("Expected A record, got %T", decoded.Answers[0])
	}
	
	if decodedA.Address != a.Address {
		t.Errorf("Address mismatch: expected %s, got %s", a.Address, decodedA.Address)
	}
}

func TestEncodeDecodeNSRecord(t *testing.T) {
	ns := &DNSResourceRecordNS{
		DNSResourceRecord: DNSResourceRecord{
			Name:  "example.com",
			Type:  DNSTypeNS,
			Class: DNSClassIN,
			TTL:   300,
		},
		NameServer: "ns1.example.com",
	}

	// Test full packet encoding/decoding
	pkt := NewPacket()
	pkt.AddAnswer(ns)
	
	encoded := pkt.Bytes()
	decoded, err := FromBytes(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	if len(decoded.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(decoded.Answers))
	}
	
	decodedNS, ok := decoded.Answers[0].(*DNSResourceRecordNS)
	if !ok {
		t.Fatalf("Expected NS record, got %T", decoded.Answers[0])
	}
	
	if decodedNS.NameServer != ns.NameServer {
		t.Errorf("NameServer mismatch: expected %s, got %s", ns.NameServer, decodedNS.NameServer)
	}
}
