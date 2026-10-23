// Command server shows the raw server.Handler API: every A query is
// answered with 127.0.0.1.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

var (
	udpAddr  = flag.String("udp", ":5353", "UDP listen address")
	httpAddr = flag.String("http", ":8080", "plain-HTTP DoH listen address")
)

func handle(ctx context.Context, w server.ResponseWriter, req *packet.DNSPacket) {
	res := packet.NewReply(req)
	if len(req.Questions) != 1 {
		res.SetRCode(packet.RCodeFormatError)
		_ = w.WriteMsg(res)
		return
	}
	q := req.Questions[0]
	log.Printf("[%s %s] %s type=%d", w.Transport(), w.RemoteAddr(), q.Name, q.Type)
	if q.Type == packet.DNSTypeA {
		res.AddAnswer(&packet.DNSResourceRecordA{
			DNSResourceRecord: packet.DNSResourceRecord{Name: q.Name, Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: 100},
			Address:           "127.0.0.1",
		})
	}
	if err := w.WriteMsg(res); err != nil {
		log.Printf("write: %v", err)
	}
}

func main() {
	flag.Parse()
	h := server.HandlerFunc(handle)
	errCh := make(chan error, 2)
	go func() { errCh <- server.ListenUDP(*udpAddr, h) }()
	go func() { errCh <- server.ListenHTTP(*httpAddr, h) }()
	log.Printf("listening udp %s, http %s%s", *udpAddr, *httpAddr, server.DoHPath)
	log.Fatal(<-errCh)
}
