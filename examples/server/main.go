package main

import (
	"log"

	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

type MyHandler struct{}

func (h *MyHandler) HandleQuery(conn *server.PackConn) {
	log.Println("query", conn.Request.Questions[0].Name)
	res := packet.NewPacketFromRequest(conn.Request)
	res.AddAnswer(&packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Type:  packet.DNSTypeA,
			Class: packet.DNSClassIN,
			Name:  conn.Request.Questions[0].Name,
			TTL:   100,
		},
		Address: "1.1.1.1",
	})
	conn.WriteResponse(res)
}

func main() {
	h := &MyHandler{}
	server.ListenUDP("0.0.0.0:53", h)
	server.ListenHTTP("0.0.0.0:8080", h)
}
