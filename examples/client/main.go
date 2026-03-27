package main

import (
	"log"

	"github.com/lsongdev/dns-go/client"
	"github.com/lsongdev/dns-go/packet"
)

func printRecord(record packet.DNSResource) {
	switch r := record.(type) {
	case *packet.DNSResourceRecordA:
		println(r.Type, r.Name, r.Address)
	case *packet.DNSResourceRecordAAAA:
		println(r.Name, r.Address)
	case *packet.DNSResourceRecordSOA:
		println(r.Name, r.MName, r.RName, r.Serial)
	case *packet.DNSResourceRecordTXT:
		println(r.Name, r.Content)
	case *packet.DNSResourceRecordNS:
		println(r.Name, r.NameServer)
	case *packet.DNSResourceRecordMX:
		println(r.Name, r.Preference, r.Exchange)
	case *packet.DNSResourceRecordPTR:
		println(r.Name, r.PtrDomainName)
	case *packet.DNSResourceRecordCNAME:
		println(r.Name, r.Domain)
	case *packet.DNSResourceRecordSRV:
		println(r.Name, r.Priority, r.Weight, r.Port, r.Target)
	case *packet.DNSResourceRecordEDNS:
		println(r.Name, r.UDPSize, r.GetDNSSECOK())
	default:
		println(record.GetType(), r)
	}
}

func main() {
	// c := client.NewDoHClient("https://cloudflare-dns.com/dns-query")
	c := client.NewUDPClient("8.8.8.8:53")
	query := packet.NewPacket()
	// query.AddQuestionTXT("lsong.org")
	query.AddQuestionTXT("google.com")
	// query.AddQuestionAAAA("lsong.org")
	// query.AddQuestionCNAME("lsong.org")
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
