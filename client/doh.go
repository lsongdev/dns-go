package client

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/song940/dns-go/packet"
)

type DoHClient struct {
	Server  string
	Timeout time.Duration
}

func NewDoHClient(server string) *DoHClient {
	return &DoHClient{
		Server:  server,
		Timeout: 5 * time.Second,
	}
}

func (client *DoHClient) Query(query *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	b64Req := base64.RawURLEncoding.EncodeToString(query.Bytes())
	url := fmt.Sprintf("%s?dns=%s", client.Server, b64Req)
	httpClient := &http.Client{Timeout: client.Timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "dns-go")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return packet.FromBytes(body)
}
