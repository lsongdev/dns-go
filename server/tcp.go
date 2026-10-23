package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// TCPServer serves DNS over TCP (RFC 7766) or, with a TLS listener, DNS over
// TLS (RFC 7858). Queries on one connection are answered in order.
type TCPServer struct {
	Handler Handler
	// IdleTimeout closes connections with no complete query in this window.
	// Zero means 30s.
	IdleTimeout time.Duration
	// Transport labels requests; ListenTLS sets it to TransportDoT.
	Transport Transport
}

// ListenTCP serves h over plain TCP on addr.
func ListenTCP(addr string, h Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return (&TCPServer{Handler: h}).Serve(ln)
}

// ListenTLS serves h over DNS-over-TLS on addr.
func ListenTLS(addr string, config *tls.Config, h Handler) error {
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	defer ln.Close()
	return (&TCPServer{Handler: h, Transport: TransportDoT}).Serve(ln)
}

// Serve accepts connections until ln is closed, then returns nil.
func (s *TCPServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
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
		go s.serveConn(conn)
	}
}

func (s *TCPServer) serveConn(conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = 30 * time.Second
	}
	transport := s.Transport
	if transport == "" {
		transport = TransportTCP
	}
	var length [2]byte
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		buf := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		req, err := packet.FromBytes(buf)
		if err != nil {
			return // stream framing can no longer be trusted
		}
		w := &tcpWriter{conn: conn, transport: transport}
		s.Handler.ServeDNS(ctx, w, req)
		if w.err != nil {
			return
		}
	}
}

type tcpWriter struct {
	conn      net.Conn
	transport Transport
	err       error
}

func (w *tcpWriter) WriteMsg(res *packet.DNSPacket) error {
	data, _ := res.Pack(packet.MaxMessageSize)
	frame := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(frame, uint16(len(data)))
	copy(frame[2:], data)
	if err := w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		w.err = err
		return err
	}
	_, w.err = w.conn.Write(frame)
	return w.err
}

func (w *tcpWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }
func (w *tcpWriter) Transport() Transport { return w.transport }
