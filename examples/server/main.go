package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

var (
	udpAddr  = flag.String("udp", ":5353", "UDP listen address")
	httpAddr = flag.String("http", ":8080", "HTTP/DoH listen address")
)

type MyHandler struct{}

func (h *MyHandler) HandleQuery(conn *server.PackConn) {
	if len(conn.Request.Questions) == 0 {
		log.Printf("[%s] Invalid query: no questions", conn.RemoteAddr)
		return
	}

	log.Printf("[%s] Query: %s", conn.RemoteAddr, conn.Request.Questions[0].Name)

	res := packet.NewPacketFromRequest(conn.Request)
	res.AddAnswer(&packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Type:  packet.DNSTypeA,
			Class: packet.DNSClassIN,
			Name:  conn.Request.Questions[0].Name,
			TTL:   100,
		},
		Address: "127.0.0.1",
	})

	if err := conn.WriteResponse(res); err != nil {
		log.Printf("[%s] Write error: %v", conn.RemoteAddr, err)
	}
}

func main() {
	flag.Parse()

	log.Printf("Starting DNS server...")
	log.Printf("  UDP listen:  %s", *udpAddr)
	log.Printf("  HTTP listen: %s", *httpAddr)

	handler := &MyHandler{}

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
		os.Exit(1)
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
	}
}
