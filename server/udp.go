package server

import (
	"log"
	"net"

	"github.com/song940/dns-go/packet"
)

type PackConn struct {
	net.PacketConn
	RemoteAddr net.Addr
	Request    *packet.DNSPacket
}

func (p *PackConn) WriteResponse(res *packet.DNSPacket) error {
	res.Header.QR = packet.DNSResponse
	data := res.Bytes()
	_, err := p.WriteTo(data, p.RemoteAddr)
	return err
}

type Handler interface {
	HandleQuery(conn *PackConn)
}

func ListenAndServe(addr string, handler Handler) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return serveUDP(conn, handler)
}

func serveUDP(conn net.PacketConn, h Handler) error {
	buf := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}
		req, err := packet.FromBytes(buf[:n])
		pc := &PackConn{
			PacketConn: conn,
			RemoteAddr: remote,
			Request:    req,
		}
		if err != nil {
			log.Printf("Error decoding packet: %v", err)
			continue
		}
		h.HandleQuery(pc)
	}
}
