package examples

import (
	"log"

	"github.com/song940/dns-go/packet"
	"github.com/song940/dns-go/server"
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
		Address: "127.0.0.1",
	})
	conn.WriteResponse(res)
}

func RunServer() {
	h := &MyHandler{}
	server.ListenAndServe("0.0.0.0:53", h)
}
