package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// HTTPClient is a DNS over HTTPS (DoH) client (RFC 8484).
// Supports both GET and POST methods.
// Uses HTTP/2 which is required by most DoH servers.
type HTTPClient struct {
	Server  string
	Timeout time.Duration
	UsePost bool // Use POST method instead of GET
}

// NewHTTPClient creates a new DoH client.
// server should be a full URL like "https://cloudflare-dns.com/dns-query"
func NewHTTPClient(server string) *HTTPClient {
	return &HTTPClient{
		Server:  server,
		Timeout: 5 * time.Second,
		UsePost: false,
	}
}

// NewHTTPClientPost creates a new DoH client using POST method.
// POST is recommended by RFC 8484 and has better compatibility.
func NewHTTPClientPost(server string) *HTTPClient {
	return &HTTPClient{
		Server:  server,
		Timeout: 5 * time.Second,
		UsePost: true,
	}
}

// createHTTPClient creates an HTTP client with HTTP/2 support.
func createHTTPClient(timeout time.Duration) *http.Client {
	// Create transport with HTTP/2 support
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		ForceAttemptHTTP2:   true, // Enable HTTP/2
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// Query sends a DNS query and returns the response.
func (c *HTTPClient) Query(query *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	queryData := query.Bytes()
	httpClient := createHTTPClient(c.Timeout)

	var req *http.Request
	if c.UsePost {
		// POST request (RFC 8484 recommended)
		req, err = http.NewRequest(http.MethodPost, c.Server, bytes.NewReader(queryData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
	} else {
		// GET request
		b64Req := base64.RawURLEncoding.EncodeToString(queryData)
		url := fmt.Sprintf("%s?dns=%s", c.Server, b64Req)
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "dns-go")

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return packet.FromBytes(body)
}

func (c *HTTPClient) Close() error {
	// HTTP client doesn't need closing
	return nil
}
