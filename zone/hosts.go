package zone

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/lsongdev/dns-go/packet"
)

// DefaultHostsTTL is the TTL given to records parsed from hosts files.
const DefaultHostsTTL = 300

// ParseHosts reads /etc/hosts-format data ("IP name [alias...]") into a
// Transparent zone at the root, so listed names are answered locally and
// every other name keeps resolving normally.
func ParseHosts(r io.Reader) (*Zone, error) {
	z := &Zone{Origin: ".", Kind: Transparent, TTL: DefaultHostsTTL}
	scanner := bufio.NewScanner(r)
	lineno := 0
	for scanner.Scan() {
		lineno++
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want \"address name...\"", lineno)
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			return nil, fmt.Errorf("line %d: invalid address %q", lineno, fields[0])
		}
		for _, name := range fields[1:] {
			z.Records = append(z.Records, hostRecord(CanonicalName(name), ip))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return z, nil
}

// ParseHostsFile is ParseHosts on a file.
func ParseHostsFile(path string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseHosts(f)
}

func hostRecord(name string, ip net.IP) packet.DNSResource {
	if v4 := ip.To4(); v4 != nil {
		return &packet.DNSResourceRecordA{
			DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: DefaultHostsTTL},
			Address:           v4.String(),
		}
	}
	return &packet.DNSResourceRecordAAAA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeAAAA, Class: packet.DNSClassIN, TTL: DefaultHostsTTL},
		Address:           ip.String(),
	}
}
