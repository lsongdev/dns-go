package proxy

import (
	"errors"
	"fmt"
	"time"

	"github.com/lsongdev/dns-go/client"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
)

type Upstream interface {
	Query(req *packet.DNSPacket) (*packet.DNSPacket, error)
	Close() error
}

type Pool struct {
	upstreams []Upstream
	strategy  string
}

func NewPool(spec config.ProxySpec) (*Pool, error) {
	if len(spec.Upstreams) == 0 {
		return nil, errors.New("proxy: no upstreams configured")
	}
	ups := make([]Upstream, 0, len(spec.Upstreams))
	for i, u := range spec.Upstreams {
		built, err := buildUpstream(u)
		if err != nil {
			closeAll(ups)
			return nil, fmt.Errorf("proxy.upstreams[%d]: %w", i, err)
		}
		ups = append(ups, built)
	}
	strategy := spec.Strategy
	if strategy == "" {
		strategy = "failover"
	}
	if strategy != "failover" {
		closeAll(ups)
		return nil, fmt.Errorf("proxy: strategy %q not implemented (only 'failover')", strategy)
	}
	return &Pool{upstreams: ups, strategy: strategy}, nil
}

func (p *Pool) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	var lastErr error
	for _, u := range p.upstreams {
		res, err := u.Query(req)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("proxy: no upstream attempted")
	}
	return nil, lastErr
}

func (p *Pool) Close() error {
	closeAll(p.upstreams)
	return nil
}

func closeAll(ups []Upstream) {
	for _, u := range ups {
		_ = u.Close()
	}
}

func buildUpstream(spec config.UpstreamSpec) (Upstream, error) {
	timeout := spec.Timeout.Duration()
	if timeout == 0 {
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
