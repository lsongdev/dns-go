// Package server implements the DNS transports (UDP, TCP, DoT, DoH). Each
// transport decodes requests, hands them to a Handler, and enforces its own
// size limit when writing the reply, so handlers never deal with framing or
// truncation.
package server

import (
	"context"
	"net"

	"github.com/lsongdev/dns-go/packet"
)

// Transport identifies how a request arrived.
type Transport string

const (
	TransportUDP Transport = "udp"
	TransportTCP Transport = "tcp"
	TransportDoT Transport = "dot"
	TransportDoH Transport = "doh"
)

// DefaultUDPSize is the largest UDP payload the server sends, regardless of
// what a client advertises (DNS Flag Day 2020). It is also the size a handler
// should advertise in its own OPT record.
const DefaultUDPSize = 1232

// ResponseWriter sends exactly one reply to a request.
type ResponseWriter interface {
	// WriteMsg encodes res, truncating it when the transport requires.
	WriteMsg(res *packet.DNSPacket) error
	RemoteAddr() net.Addr
	Transport() Transport
}

// Handler answers DNS requests. Transports call ServeDNS concurrently; ctx
// is cancelled when the client goes away or the listener shuts down.
type Handler interface {
	ServeDNS(ctx context.Context, w ResponseWriter, req *packet.DNSPacket)
}

// HandlerFunc adapts an ordinary function to Handler.
type HandlerFunc func(ctx context.Context, w ResponseWriter, req *packet.DNSPacket)

func (f HandlerFunc) ServeDNS(ctx context.Context, w ResponseWriter, req *packet.DNSPacket) {
	f(ctx, w, req)
}

// UDPLimit returns the largest response that may be sent to req over UDP:
// the client's advertised EDNS size, clamped to [512, max].
func UDPLimit(req *packet.DNSPacket, max int) int {
	if max < packet.MinUDPSize {
		max = DefaultUDPSize
	}
	opt := req.OPT()
	if opt == nil {
		return packet.MinUDPSize
	}
	size := int(opt.UDPSize)
	if size < packet.MinUDPSize {
		return packet.MinUDPSize
	}
	if size > max {
		return max
	}
	return size
}
