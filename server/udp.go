package server

import (
	"io"
	"log"
	"net"

	"github.com/lsongdev/dns-go/packet"
)

type PackConn struct {
	io.Writer
	RemoteAddr string
	Request    *packet.DNSPacket
}

func (p *PackConn) WriteResponse(res *packet.DNSPacket) error {
	res.Header.QR = packet.DNSResponse
	_, err := p.Write(res.Bytes())
	return err
}

type DNSHandler interface {
	HandleQuery(conn *PackConn)
}

func ListenUDP(addr string, handler DNSHandler) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return serveUDP(conn, handler)
}

type UdpWritter struct {
	net.PacketConn
	addr net.Addr
}

func (w *UdpWritter) Write(data []byte) (int, error) {
	return w.WriteTo(data, w.addr)
}

func serveUDP(conn net.PacketConn, h DNSHandler) error {
	buf := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		req, err := packet.FromBytes(buf[:n])
		if err != nil {
			log.Printf("Error decoding packet: %v", err)
			continue
		}
		pc := &PackConn{
			Writer: &UdpWritter{
				conn,
				remote,
			},
			RemoteAddr: remote.String(),
			Request:    req,
		}
		h.HandleQuery(pc)
	}
}
