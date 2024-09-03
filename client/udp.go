package client

import (
	"net"
	"time"

	"github.com/song940/dns-go/packet"
)

type UDPClient struct {
	Server  string
	Timeout time.Duration
}

func NewUDPClient(server string) *UDPClient {
	return &UDPClient{
		Server:  server,
		Timeout: 5 * time.Second,
	}
}

func (client *UDPClient) Query(req *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	conn, err := net.Dial("udp", client.Server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, err = conn.Write(req.Bytes())
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	// log.Println("dns response", n, fmt.Sprintf("%x", buf[:n]))
	return packet.FromBytes(buf[:n])
}
