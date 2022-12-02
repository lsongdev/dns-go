package dns

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	Timeout time.Duration
}

func NewClient() *Client {
	return &Client{
		Timeout: 5 * time.Second,
	}
}

func (client *Client) Query(req *DNSPacket) (res *DNSPacket, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
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
	log.Println("dns response", n, fmt.Sprintf("%x", buf[:n]))
	return FromBytes(buf[:n])
}
