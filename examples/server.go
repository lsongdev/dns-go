package examples

import (
	"github.com/song940/dns-go/packet"
	"github.com/song940/dns-go/server"
)

func RunServer() {
	handler := func(req *packet.DNSPacket) (res *packet.DNSPacket) {
		res = &packet.DNSPacket{
			Header: &packet.DNSHeader{
				ID: req.Header.ID,
				QR: packet.DNSResponse,
			},
			Questions: req.Questions,
			Answers: []packet.DNSResource{
				&packet.DNSResourceRecordA{
					DNSResourceRecord: packet.DNSResourceRecord{
						Name:  "example.com.",
						Type:  packet.DNSTypeA,
						Class: packet.DNSClassIN,
						TTL:   3600,
					},
					Address: "127.0.0.1",
				},
			},
		}
		return
	}
	server.ListenAndServe("0.0.0.0:53", handler)
}
