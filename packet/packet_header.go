package packet

import (
	"bytes"
	"encoding/binary"
	"math/rand"
)

const (
	DNSQuery    uint8 = 0
	DNSResponse uint8 = 1
)

//  DNS Header
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type DNSHeader struct {
	ID      uint16
	QR      uint8  // 0: query, 1: response
	OpCode  uint8  // 0: standard query, 1: inverse query, 2: server status request, 3-15: reserved
	AA      uint8  // 0: not authoritative, 1: authoritative
	TC      uint8  // 0: truncated, 1: not truncated
	RD      uint8  // 0: recursion desired, 1: recursion not desired
	RA      uint8  // 0: recursion available, 1: recursion not available
	Z       uint8  // 0: reserved, 1-255: code
	RCode   uint8  // 0: no error, 1: format error, 2: server failure, 3: name error, 4: not implemented, 5: refused, 6-15: reserved
	QDCount uint16 // Number of questions to expect
	ANCount uint16 // Number of answers to expect
	NSCount uint16 // Number of authorities to expect
	ARCount uint16 // Number of additional records to expect
}

func NewHeader() *DNSHeader {
	id := rand.Uint32()
	return &DNSHeader{
		ID:      uint16(id),
		QR:      DNSQuery,
		QDCount: 0,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
}

func (h *DNSHeader) Parse(reader *bytes.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &h.ID); err != nil {
		return err
	}
	// Read the first byte containing flags
	flagsByte, err := reader.ReadByte()
	if err != nil {
		return err
	}
	h.QR = (flagsByte & 0x80) >> 7
	h.OpCode = (flagsByte >> 3) & 0x0F
	h.AA = (flagsByte & 0x04) >> 2
	h.TC = (flagsByte & 0x02) >> 1
	h.RD = flagsByte & 0x01

	// Read the second byte containing flags
	flagsByte, err = reader.ReadByte()
	if err != nil {
		return err
	}
	h.RA = (flagsByte & 0x80) >> 7
	h.Z = (flagsByte >> 4) & 0x07
	h.RCode = flagsByte & 0x0F

	if err := binary.Read(reader, binary.BigEndian, &h.QDCount); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &h.ANCount); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &h.NSCount); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &h.ARCount); err != nil {
		return err
	}
	return nil
}

func (h *DNSHeader) Bytes() []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[:2], h.ID)
	data[2] = h.QR<<7 | h.OpCode<<3 | h.AA<<2 | h.TC<<1 | h.RD
	data[3] = h.RA<<7 | h.Z<<4 | h.RCode
	binary.BigEndian.PutUint16(data[4:6], h.QDCount)
	binary.BigEndian.PutUint16(data[6:8], h.ANCount)
	binary.BigEndian.PutUint16(data[8:10], h.NSCount)
	binary.BigEndian.PutUint16(data[10:12], h.ARCount)
	return data
}
