package main

import (
	"log"

	"github.com/song940/dns-go/client"
	"github.com/song940/dns-go/packet"
)

func printRecord(record packet.DNSResource) {
	switch record.GetType() {
	case packet.DNSTypeA:
		a := record.(*packet.DNSResourceRecordA)
		println(a.Type, a.Name, a.Address)
	case packet.DNSTypeAAAA:
		aaaa := record.(*packet.DNSResourceRecordAAAA)
		println(aaaa.Name, aaaa.Address)
	case packet.DNSTypeSOA:
		soa := record.(*packet.DNSResourceRecordSOA)
		println(soa.Name, soa.MName, soa.RName, soa.Serial)
	case packet.DNSTypeTXT:
		txt := record.(*packet.DNSResourceRecordTXT)
		println(txt.Name, txt.Content)
	}
}

func main() {
	c := client.NewUDPClient()
	query := packet.NewPacket()
	// query.AddQuestionA("lsong.org")
	// query.AddQuestionAAAA("lsong.org")
	// query.AddQuestionCNAME("lsong.org")
	query.AddQuestionTXT("lsong.org")
	res, err := c.Query(query)
	if err != nil {
		panic(err)
	}
	log.Println("=========================== Answers ===========================")
	for _, record := range res.Answers {
		printRecord(record)
	}
	log.Println("=========================== Authorities ===========================")
	for _, record := range res.Authorities {
		printRecord(record)
	}
	log.Println("=========================== Additionals ===========================")
	for _, record := range res.Additionals {
		printRecord(record)
	}
}
