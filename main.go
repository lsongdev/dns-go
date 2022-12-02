package main

import (
	"log"

	"github.com/song940/dns-go/dns"
)

func printRecord(record dns.DNSResource) {
	switch record.GetType() {
	case dns.DNSTypeA:
		a := record.(*dns.DNSResourceRecordA)
		println(a.Type, a.Name, a.Address)
	case dns.DNSTypeAAAA:
		aaaa := record.(*dns.DNSResourceRecordAAAA)
		println(aaaa.Name, aaaa.Address)
	case dns.DNSTypeSOA:
		soa := record.(*dns.DNSResourceRecordSOA)
		println(soa.Name, soa.MName, soa.RName, soa.Serial)
	case dns.DNSTypeTXT:
		txt := record.(*dns.DNSResourceRecordTXT)
		println(txt.Name, txt.Content)
	}
}

func main() {
	client := dns.NewClient()
	query := dns.NewPacket()
	// query.AddQuestionA("lsong.org")
	// query.AddQuestionAAAA("lsong.org")
	// query.AddQuestionCNAME("lsong.org")
	query.AddQuestionTXT("lsong.org")
	res, err := client.Query(query)
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
