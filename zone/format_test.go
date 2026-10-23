package zone

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lsongdev/dns-go/packet"
)

func TestFormatRoundTrip(t *testing.T) {
	z, err := ParseString("example.com", strings.Join([]string{
		`@ 300 IN SOA ns1 hostmaster 2026010101 7200 3600 1209600 300`,
		`@ 300 IN NS ns1.example.net.`,
		`@ 300 IN A 192.0.2.1`,
		`@ 300 IN AAAA 2001:db8::1`,
		`@ 300 IN MX 10 mail`,
		`@ 300 IN MX 0 .`,
		`@ 300 IN TXT "v=spf1 include:_spf.example.net ~all"`,
		`q 300 IN TXT "say \"hi\" \\ bye"`,
		`www 300 IN CNAME @`,
		`1.2 300 IN PTR host.example.com.`,
		`_sip._tcp 300 IN SRV 10 60 5060 sip`,
		`@ 300 IN CAA 0 issue "letsencrypt.org"`,
		`@ 300 IN DS 12345 13 2 ABCDEF0123`,
		`@ 300 IN DNSKEY 257 3 13 AQIDBA==`,
		`@ 300 IN RRSIG A 13 2 300 20300101000000 20200101000000 12345 example.com. AQID`,
		`@ 300 IN NSEC next.example.com. A NS SOA RRSIG`,
		`_443._tcp 300 IN TLSA 3 1 1 ABCDEF`,
		`@ 300 IN HTTPS 1 . alpn=h2,h3 port=8443 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1 mandatory=alpn,port`,
		`svc 300 IN SVCB 0 target.example.net.`,
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range z.Records {
		line := Format(r)
		again, err := ParseString("other.test", line)
		if err != nil {
			t.Errorf("%s: reparse: %v", line, err)
			continue
		}
		if !bytes.Equal(again.Records[0].Bytes(), r.Bytes()) {
			t.Errorf("round trip changed record:\n  %s\n  %s", line, Format(again.Records[0]))
		}
	}
	if got := Format(z.Records[8]); got != "www.example.com. 300 IN CNAME example.com." {
		t.Errorf("Format = %q", got)
	}
}

func TestTypeStrings(t *testing.T) {
	for _, s := range []string{"A", "aaaa", "HTTPS", "TYPE65280"} {
		typ, err := ParseType(s)
		if err != nil || !strings.EqualFold(TypeString(typ), s) {
			t.Errorf("%s -> %d -> %s (%v)", s, typ, TypeString(typ), err)
		}
	}
	if _, err := ParseType("BOGUS"); err == nil {
		t.Fatal("unknown mnemonic accepted")
	}
	unknown := &packet.DNSResourceRecordUnknown{DNSResourceRecord: packet.DNSResourceRecord{Name: "x", Type: 65280, Class: packet.DNSClassIN}, RData: []byte{1, 2}}
	if got := FormatRData(unknown); got != `\# 2 0102` {
		t.Fatalf("unknown RDATA = %q", got)
	}
}
