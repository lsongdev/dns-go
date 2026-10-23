// Package client implements DNS exchanges over UDP, TCP, DoT, and DoH. All
// clients are safe for concurrent use and never serialize queries.
package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

const defaultTimeout = 5 * time.Second

// Client sends one query and returns the matching response. A response with
// a non-zero RCODE is a successful exchange, not an error.
type Client interface {
	Query(ctx context.Context, req *packet.DNSPacket) (*packet.DNSPacket, error)
	Close() error
}

// deadline returns the earlier of ctx's deadline and now+timeout.
func deadline(ctx context.Context, timeout time.Duration) time.Time {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	d := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(d) {
		return ctxDeadline
	}
	return d
}

func validateResponse(req, res *packet.DNSPacket) error {
	if req == nil || req.Header == nil {
		return fmt.Errorf("DNS request has no header")
	}
	if res == nil || res.Header == nil {
		return fmt.Errorf("DNS response has no header")
	}
	if res.Header.QR != packet.DNSResponse {
		return fmt.Errorf("received a DNS query instead of a response")
	}
	if res.Header.ID != req.Header.ID {
		return fmt.Errorf("DNS response ID mismatch: got %d, want %d", res.Header.ID, req.Header.ID)
	}
	if len(res.Questions) != len(req.Questions) {
		return fmt.Errorf("DNS response question count mismatch: got %d, want %d", len(res.Questions), len(req.Questions))
	}
	for i := range req.Questions {
		want := req.Questions[i]
		got := res.Questions[i]
		if !strings.EqualFold(strings.TrimSuffix(got.Name, "."), strings.TrimSuffix(want.Name, ".")) ||
			got.Type != want.Type || got.Class != want.Class {
			return fmt.Errorf("DNS response question %d does not match request", i)
		}
	}
	return nil
}
