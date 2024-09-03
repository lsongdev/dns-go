package server

import (
	"log"
	"net"

	"github.com/song940/dns-go/packet"
)

type Handler func(*packet.DNSPacket) *packet.DNSPacket

func ListenAndServe(addr string, handler Handler) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return serveUDP(conn, handler)
}

func serveUDP(conn net.PacketConn, handler Handler) error {
	buf := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}
		go handleRequest(conn, buf[:n], remote, handler)
	}
}

func handleRequest(conn net.PacketConn, data []byte, remote net.Addr, handler Handler) {
	req, err := packet.FromBytes(data)
	if err != nil {
		log.Printf("Error decoding packet: %v", err)
		return
	}
	res := handler(req)
	if err := writeResponse(conn, res, remote); err != nil {
		log.Printf("Error writing packet: %v", err)
	}
}

func writeResponse(conn net.PacketConn, res *packet.DNSPacket, remote net.Addr) error {
	_, err := conn.WriteTo(res.Bytes(), remote)
	return err
}
