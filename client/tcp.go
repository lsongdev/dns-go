package client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

const maxIdleConns = 4

// TCPClient is a DNS client over TCP (RFC 7766) or TLS (RFC 7858). It keeps
// a small pool of idle connections; each in-flight query owns a connection,
// so concurrent queries never wait on each other.
type TCPClient struct {
	Server  string
	Timeout time.Duration

	tlsConfig *tls.Config

	mu     sync.Mutex
	idle   []net.Conn
	closed bool
}

func NewTCPClient(server string) *TCPClient {
	return &TCPClient{Server: server, Timeout: defaultTimeout}
}

// NewTLSClient creates a DNS-over-TLS client; the SNI and certificate name
// come from the host part of server ("host:853").
func NewTLSClient(server string) *TCPClient {
	serverName, _, _ := net.SplitHostPort(server)
	return NewTLSClientWithConfig(server, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
}

func NewTLSClientWithConfig(server string, config *tls.Config) *TCPClient {
	return &TCPClient{Server: server, Timeout: defaultTimeout, tlsConfig: config}
}

func (c *TCPClient) Query(ctx context.Context, req *packet.DNSPacket) (*packet.DNSPacket, error) {
	data := req.Bytes()
	frame := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(frame, uint16(len(data)))
	copy(frame[2:], data)

	// A pooled connection may have been closed by the server while idle; in
	// that case retry once on a fresh connection.
	conn, reused, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.exchange(ctx, conn, req, frame)
	if err != nil && reused && ctx.Err() == nil {
		conn.Close()
		if conn, err = c.dial(ctx); err != nil {
			return nil, err
		}
		res, err = c.exchange(ctx, conn, req, frame)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	c.put(conn)
	return res, nil
}

func (c *TCPClient) exchange(ctx context.Context, conn net.Conn, req *packet.DNSPacket, frame []byte) (*packet.DNSPacket, error) {
	if err := conn.SetDeadline(deadline(ctx, c.Timeout)); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	res, err := packet.FromBytes(buf)
	if err != nil {
		return nil, err
	}
	if err := validateResponse(req, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *TCPClient) get(ctx context.Context) (net.Conn, bool, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, fmt.Errorf("client: closed")
	}
	if n := len(c.idle); n > 0 {
		conn := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return conn, true, nil
	}
	c.mu.Unlock()
	conn, err := c.dial(ctx)
	return conn, false, err
}

func (c *TCPClient) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithDeadline(ctx, deadline(ctx, c.Timeout))
	defer cancel()
	if c.tlsConfig != nil {
		d := tls.Dialer{Config: c.tlsConfig}
		return d.DialContext(ctx, "tcp", c.Server)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", c.Server)
}

func (c *TCPClient) put(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.idle) >= maxIdleConns {
		conn.Close()
		return
	}
	c.idle = append(c.idle, conn)
}

func (c *TCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, conn := range c.idle {
		conn.Close()
	}
	c.idle = nil
	return nil
}
