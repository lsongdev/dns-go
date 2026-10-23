package server

import (
	"context"
	"errors"
	"net"

	"github.com/lsongdev/dns-go/packet"
)

// UDPServer serves DNS over a packet connection.
type UDPServer struct {
	Handler Handler
	// MaxUDPSize caps response size regardless of the client's EDNS buffer
	// size. Zero means DefaultUDPSize.
	MaxUDPSize int
	// MaxConcurrent bounds in-flight queries; when reached the read loop
	// stops reading and the kernel socket buffer absorbs (or drops) bursts.
	// Zero means 1024.
	MaxConcurrent int
}

// ListenUDP serves h on addr until the socket fails.
func ListenUDP(addr string, h Handler) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return (&UDPServer{Handler: h}).Serve(conn)
}

// Serve reads queries from conn until it is closed. Closing conn makes Serve
// return nil and cancels in-flight handlers.
func (s *UDPServer) Serve(conn net.PacketConn) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limit := s.MaxConcurrent
	if limit <= 0 {
		limit = 1024
	}
	sem := make(chan struct{}, limit)
	buf := make([]byte, packet.MaxMessageSize)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		// Decoded records may alias their input, and buf is reused.
		req, err := packet.FromBytes(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue // not a DNS message; replying would aid reflection
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			s.Handler.ServeDNS(ctx, &udpWriter{conn: conn, remote: remote, req: req, max: s.MaxUDPSize}, req)
		}()
	}
}

type udpWriter struct {
	conn   net.PacketConn
	remote net.Addr
	req    *packet.DNSPacket
	max    int
}

func (w *udpWriter) WriteMsg(res *packet.DNSPacket) error {
	data, _ := res.Pack(UDPLimit(w.req, w.max))
	_, err := w.conn.WriteTo(data, w.remote)
	return err
}

func (w *udpWriter) RemoteAddr() net.Addr { return w.remote }
func (w *udpWriter) Transport() Transport { return TransportUDP }
