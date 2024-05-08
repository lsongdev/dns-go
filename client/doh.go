package client

import (
	"net/http"

	"github.com/song940/dns-go/packet"
)

// https://datatracker.ietf.org/doc/html/rfc8484
type DoHClient struct {
}

func NewDoHClient() *DoHClient {
	return &DoHClient{}
}

func (c *DoHClient) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	http.Get("https://cloudflare-dns.com/dns-query")
	return nil, nil
}
