package main

import (
	"log"
	"os"

	"github.com/lsongdev/dns-go/examples"
)

func main() {
	if len(os.Args) < 2 {
		log.Println("Usage: go run main.go server|client")
		os.Exit(1)
	}
	cmd := os.Args[1]
	switch cmd {
	case "server":
		examples.RunServer()
	case "client":
		examples.RunClient()
	}
}
