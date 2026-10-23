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
//  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
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
	TC      uint8  // 1: message was truncated
	RD      uint8  // 1: recursion desired
	RA      uint8  // 1: recursion available
	Z       uint8  // reserved, must be zero
	AD      uint8  // 1: authentic data (RFC 4035)
	CD      uint8  // 1: checking disabled (RFC 4035)
	RCode   uint8  // low 4 bits of the response code; see RCode* constants
	QDCount uint16 // Number of questions to expect
	ANCount uint16 // Number of answers to expect
	NSCount uint16 // Number of authority records to expect
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
	h.Z = (flagsByte >> 6) & 0x01
	h.AD = (flagsByte >> 5) & 0x01
	h.CD = (flagsByte >> 4) & 0x01
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
	data[2] = h.QR<<7 | (h.OpCode&0x0F)<<3 | h.AA<<2 | h.TC<<1 | h.RD
	data[3] = h.RA<<7 | h.Z<<6 | h.AD<<5 | h.CD<<4 | h.RCode&0x0F
	binary.BigEndian.PutUint16(data[4:6], h.QDCount)
	binary.BigEndian.PutUint16(data[6:8], h.ANCount)
	binary.BigEndian.PutUint16(data[8:10], h.NSCount)
	binary.BigEndian.PutUint16(data[10:12], h.ARCount)
	return data
}

// Response codes (RFC 1035, RFC 6891). Codes above 15 need an OPT record to
// carry the upper 8 bits; see DNSPacket.SetRCode.
const (
	RCodeSuccess        uint16 = 0
	RCodeFormatError    uint16 = 1
	RCodeServerFailure  uint16 = 2
	RCodeNameError      uint16 = 3
	RCodeNotImplemented uint16 = 4
	RCodeRefused        uint16 = 5
	RCodeBadVersion     uint16 = 16
)
