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
	buf := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		// Copy off the shared read buffer before handing to a goroutine —
		// FromBytes may keep slices into the input (name-compression pointers
		// chase back through the original byte stream via reader.Seek), and
		// the next ReadFrom will overwrite buf in place.
		data := make([]byte, n)
		copy(data, buf[:n])

		req, err := packet.FromBytes(data)
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
		go h.HandleQuery(pc)
	}
}
