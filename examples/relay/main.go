// Command relay is a minimal programmatic forwarder: one upstream, a cache,
// and UDP + DoH listeners, built from library packages without a config file.
package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/proxy"
	"github.com/lsongdev/dns-go/server"
)

var (
	udpAddr  = flag.String("udp", ":5353", "UDP listen address")
	httpAddr = flag.String("http", ":8080", "plain-HTTP DoH listen address")
	upstream = flag.String("upstream", "1.1.1.1:53", "upstream: host:port, tcp://host:port, dot://host:port, or a DoH URL")
	timeout  = flag.Duration("timeout", 5*time.Second, "upstream timeout")
	verbose  = flag.Bool("v", false, "log every query")
)

func main() {
	flag.Parse()

	pool, err := proxy.NewFromSpecs([]proxy.Spec{parseUpstream(*upstream, *timeout)})
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	opts := engine.Options{
		Upstream: pool,
		Cache:    cache.New(cache.Options{MaxTTL: time.Hour, NegativeTTL: 5 * time.Minute, MaxEntries: 10000}),
	}
	if *verbose {
		opts.OnQuery = func(ev engine.QueryEvent) {
			log.Printf("%s %s %s type=%d rcode=%d source=%s %v", ev.Transport, ev.Client, ev.Name, ev.Type, ev.RCode, ev.Source, ev.Duration)
		}
	}
	e := engine.New(opts)

	errCh := make(chan error, 2)
	go func() { errCh <- server.ListenUDP(*udpAddr, e) }()
	go func() { errCh <- server.ListenHTTP(*httpAddr, e) }()
	log.Printf("relaying udp %s and http %s%s to %s", *udpAddr, *httpAddr, server.DoHPath, *upstream)
	log.Fatal(<-errCh)
}

func parseUpstream(addr string, timeout time.Duration) proxy.Spec {
	switch {
	case strings.HasPrefix(addr, "https://"), strings.HasPrefix(addr, "http://"):
		return proxy.Spec{Type: "doh", Addr: addr, Timeout: timeout}
	case strings.HasPrefix(addr, "dot://"):
		return proxy.Spec{Type: "dot", Addr: strings.TrimPrefix(addr, "dot://"), Timeout: timeout}
	case strings.HasPrefix(addr, "tcp://"):
		return proxy.Spec{Type: "tcp", Addr: strings.TrimPrefix(addr, "tcp://"), Timeout: timeout}
	default:
		return proxy.Spec{Type: "udp", Addr: addr, Timeout: timeout}
	}
}
