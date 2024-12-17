package client

import (
	"fmt"
	"net"

	"github.com/lsongdev/dns-go/packet"
)

type UDPClient struct {
	Server string
}

func NewUDPClient(server string) *UDPClient {
	return &UDPClient{
		Server: server,
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
	res, err = packet.FromBytes(buf[:n])
	if res.Header.RCode != 0 {
		return nil, fmt.Errorf("query failed: %v", res.Header.RCode)
	}
	return res, err
}
