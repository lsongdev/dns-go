package client

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// UDPClient sends each query from a fresh socket, so the kernel picks a
// random source port (RFC 5452) and queries never share state. Truncated
// replies are retried over TCP.
type UDPClient struct {
	Server  string
	Timeout time.Duration

	tcpOnce sync.Once
	tcp     *TCPClient
}

func NewUDPClient(server string) *UDPClient {
	return &UDPClient{Server: server, Timeout: defaultTimeout}
}

func (c *UDPClient) Query(ctx context.Context, req *packet.DNSPacket) (*packet.DNSPacket, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", c.Server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline(ctx, c.Timeout)); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := conn.Write(req.Bytes()); err != nil {
		return nil, err
	}
	buf := make([]byte, packet.MaxMessageSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}
		res, err := packet.FromBytes(append([]byte(nil), buf[:n]...))
		if err != nil || validateResponse(req, res) != nil {
			continue // stray or spoofed datagram; keep waiting for ours
		}
		if res.Header.TC == 1 {
			return c.tcpClient().Query(ctx, req)
		}
		return res, nil
	}
}

func (c *UDPClient) tcpClient() *TCPClient {
	c.tcpOnce.Do(func() {
		c.tcp = NewTCPClient(c.Server)
		c.tcp.Timeout = c.Timeout
	})
	return c.tcp
}

func (c *UDPClient) Close() error {
	if c.tcp != nil {
		return c.tcp.Close()
	}
	return nil
}
