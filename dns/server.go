package dns

import (
	"log"
	"net"
)

type Handler func(*DNSPacket) *DNSPacket

func ListenAndServe(addr string, handler Handler) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}
		req, err := FromBytes(buf[:n])
		if err != nil {
			log.Printf("Error decoding packet: %v", err)
			continue
		}
		res := handler(req)
		_, err = conn.WriteTo(res.Bytes(), remote)
		if err != nil {
			log.Printf("Error writing packet: %v", err)
			continue
		}
	}
}
