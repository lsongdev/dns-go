package pipeline

import "github.com/lsongdev/dns-go/packet"

const (
	rcodeNoError  = 0
	rcodeServFail = 2
	rcodeNXDOMAIN = 3

	syntheticTTL = 60
)

func cloneHeader(h *packet.DNSHeader) *packet.DNSHeader {
	cp := *h
	return &cp
}

// emptyResponse returns a fresh response packet that mirrors the request's
// header (with QR=1) and shares the question slice. Header is cloned so the
// caller can mutate RCode / counts without leaking back into the request.
func emptyResponse(req *packet.DNSPacket) *packet.DNSPacket {
	h := cloneHeader(req.Header)
	h.QR = packet.DNSResponse
	h.RA = 1
	h.AA = 0
	return &packet.DNSPacket{Header: h, Questions: req.Questions}
}

// SynthBlock builds a "blocked" response: A→0.0.0.0, AAAA→::, others→NXDOMAIN.
func SynthBlock(req *packet.DNSPacket) *packet.DNSPacket {
	res := emptyResponse(req)
	if len(req.Questions) == 0 {
		res.Header.RCode = rcodeNXDOMAIN
		return res
	}
	q := req.Questions[0]
	switch q.Type {
	case packet.DNSTypeA:
		res.AddAnswer(&packet.DNSResourceRecordA{
			DNSResourceRecord: packet.DNSResourceRecord{Name: q.Name, Type: packet.DNSTypeA, Class: q.Class, TTL: syntheticTTL},
			Address:           "0.0.0.0",
		})
	case packet.DNSTypeAAAA:
		res.AddAnswer(&packet.DNSResourceRecordAAAA{
			DNSResourceRecord: packet.DNSResourceRecord{Name: q.Name, Type: packet.DNSTypeAAAA, Class: q.Class, TTL: syntheticTTL},
			Address:           "::",
		})
	default:
		res.Header.RCode = rcodeNXDOMAIN
	}
	return res
}

// SynthSERVFAIL builds a SERVFAIL response. Used when the upstream pool is
// unavailable or all upstreams errored.
func SynthSERVFAIL(req *packet.DNSPacket) *packet.DNSPacket {
	res := emptyResponse(req)
	res.Header.RCode = rcodeServFail
	return res
}

// buildLocalResponse wraps zone records as an authoritative answer for the
// caller's question.
func buildLocalResponse(req *packet.DNSPacket, records []packet.DNSResource) *packet.DNSPacket {
	res := emptyResponse(req)
	res.Header.AA = 1
	res.Header.RCode = rcodeNoError
	res.Answers = append(res.Answers, records...)
	return res
}
