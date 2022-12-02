package server

import (
	"encoding/base64"
	"log"
	"net/http"

	"github.com/lsongdev/dns-go/packet"
)

func ListenHTTP(addr string, handler DNSHandler) error {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr)
		d := r.URL.Query().Get("dns")
		data, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			return
		}
		req, err := packet.FromBytes(data)
		if err != nil {
			return
		}
		conn := &PackConn{
			Request:    req,
			RemoteAddr: r.RemoteAddr,
		}
		handler.HandleQuery(conn)
	})
	return http.ListenAndServe(addr, h)
}
