package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lsongdev/dns-go/client"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

var (
	udpAddr  = flag.String("udp", ":5353", "UDP listen address")
	httpAddr = flag.String("http", ":8080", "HTTP/DoH listen address")
	upstream = flag.String("upstream", "1.1.1.1:53", "Upstream DNS server (UDP address or DoH URL)")
	timeout  = flag.Duration("timeout", 5*time.Second, "Query timeout")
	verbose  = flag.Bool("v", false, "Verbose logging")
)

type upstreamQuery interface {
	Query(req *packet.DNSPacket) (*packet.DNSPacket, error)
	Close() error
}

type RelayHandler struct {
	upstream upstreamQuery
}

func NewRelayHandler(upstreamAddr string, timeout time.Duration) (*RelayHandler, error) {
	var q upstreamQuery

	// Check if upstream is a URL (DoH), DoT, TCP, or UDP address
	if strings.HasPrefix(upstreamAddr, "http") {
		// Use POST for better compatibility with Cloudflare and other DoH providers
		c := client.NewHTTPClientPost(upstreamAddr)
		c.Timeout = timeout
		q = &httpCloser{c}
		log.Printf("Using DoH upstream (POST): %s", upstreamAddr)
	} else if strings.HasPrefix(upstreamAddr, "dot://") {
		server := upstreamAddr[6:] // Remove "dot://" prefix
		c := client.NewTLSClient(server)
		c.Timeout = timeout
		q = c
		log.Printf("Using DoT upstream: %s", upstreamAddr)
	} else if strings.HasPrefix(upstreamAddr, "tcp://") {
		server := upstreamAddr[6:] // Remove "tcp://" prefix
		c := client.NewTCPClient(server)
		c.Timeout = timeout
		q = c
		log.Printf("Using TCP upstream: %s", upstreamAddr)
	} else {
		c := client.NewUDPClient(upstreamAddr)
		c.Timeout = timeout
		q = c
		log.Printf("Using UDP upstream: %s", upstreamAddr)
	}

	return &RelayHandler{upstream: q}, nil
}

// httpCloser wraps HTTPClient to add Close method (no-op for HTTP)
type httpCloser struct {
	*client.HTTPClient
}

func (h *httpCloser) Close() error {
	return nil
}

func (h *RelayHandler) Close() {
	if h.upstream != nil {
		h.upstream.Close()
	}
}

func (h *RelayHandler) HandleQuery(conn *server.PackConn) {
	if len(conn.Request.Questions) == 0 {
		log.Printf("[%s] Invalid query: no questions", conn.RemoteAddr)
		return
	}

	question := conn.Request.Questions[0]
	start := time.Now()

	if *verbose {
		log.Printf("[%s] Query: %s %s", conn.RemoteAddr, question.Name, typeName(question.Type))
	}

	// Forward query to upstream
	res, err := h.upstream.Query(conn.Request)
	if err != nil {
		log.Printf("[%s] Upstream error: %v (%v)", conn.RemoteAddr, err, time.Since(start))
		// Return SERVFAIL to client
		h.writeError(conn, conn.Request, 2) // SERVFAIL
		return
	}

	// Check for EDNS in client request
	clientSupportsEDNS := false
	for _, add := range conn.Request.Additionals {
		if add.GetType() == packet.DNSTypeEDNS {
			clientSupportsEDNS = true
			break
		}
	}

	// If client doesn't support EDNS but response has EDNS, remove it
	if !clientSupportsEDNS && len(res.Additionals) > 0 {
		// Filter out EDNS records
		newAdditionals := make([]packet.DNSResource, 0, len(res.Additionals))
		for _, add := range res.Additionals {
			if add.GetType() != packet.DNSTypeEDNS {
				newAdditionals = append(newAdditionals, add)
			}
		}
		res.Additionals = newAdditionals
		res.Header.ARCount = uint16(len(res.Additionals))
	}

	// Log response
	if *verbose {
		log.Printf("[%s] Response: %d answers, %d authorities, %d additionals (%v)",
			conn.RemoteAddr, len(res.Answers), len(res.Authorities), len(res.Additionals), time.Since(start))

		if len(res.Answers) > 0 {
			log.Println("  Answers:")
			for _, record := range res.Answers {
				printRecord(record)
			}
		}
		if len(res.Authorities) > 0 {
			log.Println("  Authorities:")
			for _, record := range res.Authorities {
				printRecord(record)
			}
		}
		if len(res.Additionals) > 0 {
			log.Println("  Additionals:")
			for _, record := range res.Additionals {
				printRecord(record)
			}
		}
	}

	// Write response
	if err := conn.WriteResponse(res); err != nil {
		log.Printf("[%s] Write error: %v", conn.RemoteAddr, err)
	}
}

func (h *RelayHandler) writeError(conn *server.PackConn, req *packet.DNSPacket, rcode uint8) {
	res := packet.NewPacketFromRequest(req)
	res.Header.RCode = rcode
	conn.WriteResponse(res)
}

func typeName(t packet.DNSType) string {
	switch t {
	case packet.DNSTypeA:
		return "A"
	case packet.DNSTypeAAAA:
		return "AAAA"
	case packet.DNSTypeCNAME:
		return "CNAME"
	case packet.DNSTypeMX:
		return "MX"
	case packet.DNSTypeNS:
		return "NS"
	case packet.DNSTypeTXT:
		return "TXT"
	case packet.DNSTypePTR:
		return "PTR"
	case packet.DNSTypeSOA:
		return "SOA"
	case packet.DNSTypeSRV:
		return "SRV"
	default:
		return string(rune(t))
	}
}

func printRecord(record packet.DNSResource) {
	switch r := record.(type) {
	case *packet.DNSResourceRecordA:
		log.Printf("  A: %s -> %s", r.Name, r.Address)
	case *packet.DNSResourceRecordAAAA:
		log.Printf("  AAAA: %s -> %s", r.Name, r.Address)
	case *packet.DNSResourceRecordCNAME:
		log.Printf("  CNAME: %s -> %s", r.Name, r.Domain)
	case *packet.DNSResourceRecordMX:
		log.Printf("  MX: %s (pref=%d) -> %s", r.Name, r.Preference, r.Exchange)
	case *packet.DNSResourceRecordNS:
		log.Printf("  NS: %s -> %s", r.Name, r.NameServer)
	case *packet.DNSResourceRecordTXT:
		log.Printf("  TXT: %s -> %s", r.Name, r.Content)
	case *packet.DNSResourceRecordPTR:
		log.Printf("  PTR: %s -> %s", r.Name, r.PtrDomainName)
	case *packet.DNSResourceRecordSOA:
		log.Printf("  SOA: %s -> %s %s (serial=%d)", r.Name, r.MName, r.RName, r.Serial)
	case *packet.DNSResourceRecordEDNS:
		log.Printf("  EDNS: UDPSize=%d, DO=%v, Options=%d", r.UDPSize, r.GetDNSSECOK(), len(r.Options))
	case *packet.DNSResourceRecordSRV:
		log.Printf("  SRV: %s (priority=%d, weight=%d, port=%d) -> %s", r.Name, r.Priority, r.Weight, r.Port, r.Target)
	default:
		log.Printf("  Unknown: type=%d, record=%+v", record.GetType(), r)
	}
}

func main() {
	flag.Parse()

	log.Printf("Starting DNS relay...")
	log.Printf("  UDP listen:   %s", *udpAddr)
	log.Printf("  HTTP listen:  %s", *httpAddr)
	log.Printf("  Upstream:     %s", *upstream)
	log.Printf("  Timeout:      %v", *timeout)

	// Create upstream handler (auto-detect UDP or DoH)
	handler, err := NewRelayHandler(*upstream, *timeout)
	if err != nil {
		log.Fatalf("Failed to create relay handler: %v", err)
	}

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 2)

	// Start UDP server
	go func() {
		log.Printf("Listening on UDP %s", *udpAddr)
		if err := server.ListenUDP(*udpAddr, handler); err != nil {
			errChan <- err
		}
	}()

	// Start HTTP/DoH server
	go func() {
		log.Printf("Listening on HTTP %s", *httpAddr)
		if err := server.ListenHTTP(*httpAddr, handler); err != nil {
			errChan <- err
		}
	}()

	// Wait for error or signal
	select {
	case err := <-errChan:
		log.Printf("Server error: %v", err)
		handler.Close()
		os.Exit(1)
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		handler.Close()
	}
}
