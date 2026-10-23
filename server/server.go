// Package server implements the DNS transports (UDP, TCP, DoT, DoH). Each
// transport decodes requests, hands them to a Handler, and enforces its own
// size limit when writing the reply, so handlers never deal with framing or
// truncation.
package server

import (
	"context"
	"net"
	"net/netip"
	"strings"

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
	// RemoteAddr is the client address. IPv4-mapped addresses are unmapped;
	// for DoH behind a trusted proxy it is the forwarded client (port 0).
	RemoteAddr() netip.AddrPort
	Transport() Transport
	// ClientID is the client identifier presented by the transport (DoH
	// path "/dns-query/{id}" or a DoT/DoH SNI label "{id}.<hostname>"),
	// lower-cased; empty when none was given.
	ClientID() string
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

// ValidClientID reports whether id can be used as a client identifier: a
// DNS label (letters, digits, hyphens; 1-63 bytes) so it also works in SNI.
func ValidClientID(id string) bool {
	if len(id) == 0 || len(id) > 63 || id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// clientIDFromSNI extracts "{id}" from a server name "{id}.<hostname>".
func clientIDFromSNI(serverName, hostname string) string {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	serverName = strings.ToLower(strings.TrimSuffix(serverName, "."))
	if hostname == "" {
		return ""
	}
	label, ok := strings.CutSuffix(serverName, "."+hostname)
	if !ok || strings.Contains(label, ".") || !ValidClientID(label) {
		return ""
	}
	return label
}

func addrPortOf(addr net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		ap = a.AddrPort()
	case *net.TCPAddr:
		ap = a.AddrPort()
	default:
		ap, _ = netip.ParseAddrPort(addr.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
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
