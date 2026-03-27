package client

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

type UDPClient struct {
	Server  string
	Timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

func NewUDPClient(server string) *UDPClient {
	return &UDPClient{
		Server:  server,
		Timeout: 5 * time.Second,
	}
}

func (client *UDPClient) Query(req *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	conn, err := client.getConn()
	if err != nil {
		return nil, err
	}

	// Set read deadline for timeout
	if err := conn.SetReadDeadline(time.Now().Add(client.Timeout)); err != nil {
		return nil, err
	}

	_, err = conn.Write(req.Bytes())
	if err != nil {
		client.closeConn()
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		client.closeConn()
		return nil, err
	}

	res, err = packet.FromBytes(buf[:n])
	if err != nil {
		return nil, err
	}

	if res.Header.RCode != 0 {
		return nil, fmt.Errorf("query failed: %v", res.Header.RCode)
	}

	return res, nil
}

// Close closes the underlying UDP connection.
func (client *UDPClient) Close() error {
	return client.closeConn()
}

func (client *UDPClient) getConn() (net.Conn, error) {
	client.mu.Lock()
	defer client.mu.Unlock()

	if client.conn != nil {
		return client.conn, nil
	}

	conn, err := net.Dial("udp", client.Server)
	if err != nil {
		return nil, err
	}

	client.conn = conn
	return conn, nil
}

func (client *UDPClient) closeConn() error {
	client.mu.Lock()
	defer client.mu.Unlock()

	if client.conn != nil {
		err := client.conn.Close()
		client.conn = nil
		return err
	}
	return nil
}
