// Package proxy forwards queries to a pool of upstream resolvers.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lsongdev/dns-go/client"
	"github.com/lsongdev/dns-go/packet"
)

// Spec describes one upstream.
type Spec struct {
	Type    string // udp | tcp | dot | doh
	Addr    string // host:port, or a URL for doh
	Method  string // doh only: get | post (default post)
	Timeout time.Duration
}

// Dial builds a client for spec. No connection is made until the first query.
func Dial(spec Spec) (client.Client, error) {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	switch spec.Type {
	case "udp":
		c := client.NewUDPClient(spec.Addr)
		c.Timeout = timeout
		return c, nil
	case "tcp":
		c := client.NewTCPClient(spec.Addr)
		c.Timeout = timeout
		return c, nil
	case "dot":
		c := client.NewTLSClient(spec.Addr)
		c.Timeout = timeout
		return c, nil
	case "doh":
		var c *client.HTTPClient
		switch spec.Method {
		case "get":
			c = client.NewHTTPClient(spec.Addr)
		case "post", "":
			c = client.NewHTTPClientPost(spec.Addr)
		default:
			return nil, fmt.Errorf("doh method %q not supported", spec.Method)
		}
		c.Timeout = timeout
		return c, nil
	default:
		return nil, fmt.Errorf("unsupported upstream type %q", spec.Type)
	}
}

// Pool tries upstreams in order until one gives a usable answer. A pool is
// itself a client.Client.
type Pool struct {
	upstreams []client.Client
}

// New returns a pool over upstreams, which it owns and closes.
func New(upstreams ...client.Client) *Pool {
	return &Pool{upstreams: upstreams}
}

// NewFromSpecs dials every spec; on error nothing is left open.
func NewFromSpecs(specs []Spec) (*Pool, error) {
	if len(specs) == 0 {
		return nil, errors.New("proxy: no upstreams configured")
	}
	ups := make([]client.Client, 0, len(specs))
	for i, spec := range specs {
		c, err := Dial(spec)
		if err != nil {
			New(ups...).Close()
			return nil, fmt.Errorf("upstreams[%d]: %w", i, err)
		}
		ups = append(ups, c)
	}
	return New(ups...), nil
}

// Query returns the first response that is not SERVFAIL or REFUSED. If every
// upstream fails that way, the last such response is returned; if none
// responded at all, the last error.
func (p *Pool) Query(ctx context.Context, req *packet.DNSPacket) (*packet.DNSPacket, error) {
	var lastRes *packet.DNSPacket
	lastErr := errors.New("proxy: no upstreams")
	for _, u := range p.upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := u.Query(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}
		switch res.RCode() {
		case packet.RCodeServerFailure, packet.RCodeRefused:
			lastRes = res
			continue
		}
		return res, nil
	}
	if lastRes != nil {
		return lastRes, nil
	}
	return nil, lastErr
}

func (p *Pool) Close() error {
	var errs []error
	for _, u := range p.upstreams {
		errs = append(errs, u.Close())
	}
	return errors.Join(errs...)
}
