package examples

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

func RunClient() {
	// c := client.NewDoHClient("https://cloudflare-dns.com/dns-query")
	c := client.NewUDPClient("8.8.8.8:53")
	query := packet.NewPacket()
	query.AddQuestionA("google.com")
	// query.AddQuestionAAAA("lsong.org")
	// query.AddQuestionCNAME("lsong.org")
	// query.AddQuestionTXT("lsong.org")
	res, err := c.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	for _, question := range res.Questions {
		log.Println(question.Name, question.Type, question.Class)
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
