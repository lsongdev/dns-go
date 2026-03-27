package zone

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/lsongdev/dns-go/packet"
)

type Zone struct {
	Origin  string
	TTL     uint32
	Records []packet.DNSResource
}

func ParseFile(path string) (*Zone, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Zone, error) {
	z := &Zone{
		Origin: ".",
		TTL:    3600,
	}
	text := string(data)
	lines := tokenize(text)
	if err := parseLines(z, lines); err != nil {
		return nil, err
	}
	return z, nil
}

type lineToken struct {
	text   string
	lineno int
}

func tokenize(data string) []lineToken {
	var lines []lineToken
	current := ""
	inParen := false
	lineno := 0

	for i := 0; i < len(data); i++ {
		ch := data[i]

		if ch == '\n' {
			lineno++
			if inParen {
				current += " "
				continue
			}
			trimmed := strings.TrimSpace(current)
			if trimmed != "" && !isComment(trimmed) {
				lines = append(lines, lineToken{text: trimmed, lineno: lineno})
			}
			current = ""
			continue
		}

		if ch == ';' || ch == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			i--
			continue
		}

		if ch == '(' {
			inParen = true
			continue
		}
		if ch == ')' {
			inParen = false
			continue
		}

		current += string(ch)
	}

	if trimmed := strings.TrimSpace(current); trimmed != "" && !isComment(trimmed) {
		lines = append(lines, lineToken{text: trimmed, lineno: lineno})
	}

	return lines
}

func isComment(s string) bool {
	return strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#")
}

func parseLines(z *Zone, lines []lineToken) error {
	currentTTL := z.TTL
	for _, line := range lines {
		fields := splitFields(line.text)
		if len(fields) == 0 {
			continue
		}

		switch {
		case strings.HasPrefix(fields[0], "$ORIGIN"):
			if len(fields) >= 2 {
				z.Origin = absDomain(fields[1])
			}
			continue
		case strings.HasPrefix(fields[0], "$TTL"):
			if len(fields) >= 2 {
				ttl, err := parseTTL(fields[1])
				if err != nil {
					return fmt.Errorf("line %d: bad $TTL: %v", line.lineno, err)
				}
				z.TTL = ttl
				currentTTL = ttl
			}
			continue
		case strings.HasPrefix(fields[0], "$INCLUDE"):
			continue
		}

		rec, newTTL, err := parseRecordLine(fields, z, currentTTL, line.lineno)
		if err != nil {
			return err
		}
		if rec != nil {
			z.Records = append(z.Records, rec)
			if newTTL != 0 {
				currentTTL = newTTL
			}
		}
	}
	return nil
}


func splitFields(s string) []string {
	var fields []string
	current := ""
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' {
			inQuote = !inQuote
			current += string(ch)
			continue
		}
		if ch == '\\' && i+1 < len(s) {
			i++
			current += string(s[i])
			continue
		}
		if (ch == ' ' || ch == '\t') && !inQuote {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
			continue
		}
		current += string(ch)
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}

func parseRecordLine(fields []string, z *Zone, defaultTTL uint32, lineno int) (packet.DNSResource, uint32, error) {
	if len(fields) < 2 {
		return nil, 0, nil
	}

	idx := 0

	name := fields[idx]
	idx++

	ttl := defaultTTL
	class := packet.DNSClassIN

	if t, err := parseTTL(fields[idx]); err == nil {
		ttl = t
		idx++
	}

	if fields[idx] == "IN" || fields[idx] == "CH" || fields[idx] == "CS" || fields[idx] == "HS" {
		class = classFromString(fields[idx])
		idx++
	}

	if idx >= len(fields) {
		return nil, 0, fmt.Errorf("line %d: missing record type", lineno)
	}

	rtype := fields[idx]
	idx++

	rdata := fields[idx:]

	dname := resolveDomain(name, z.Origin)
	rec, err := buildRecord(dname, rtype, class, ttl, rdata, lineno)
	return rec, ttl, err
}

func resolveDomain(name, origin string) string {
	if name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if name == "" || name == "." {
		return origin
	}
	return name + "." + origin
}

func absDomain(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "."
	}
	return s
}

func buildRecord(name, rtype string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	switch strings.ToUpper(rtype) {
	case "A":
		return buildA(name, class, ttl, rdata, lineno)
	case "AAAA":
		return buildAAAA(name, class, ttl, rdata, lineno)
	case "CNAME":
		return buildCNAME(name, class, ttl, rdata, lineno)
	case "NS":
		return buildNS(name, class, ttl, rdata, lineno)
	case "MX":
		return buildMX(name, class, ttl, rdata, lineno)
	case "TXT":
		return buildTXT(name, class, ttl, rdata, lineno)
	case "PTR":
		return buildPTR(name, class, ttl, rdata, lineno)
	case "SOA":
		return buildSOA(name, class, ttl, rdata, lineno)
	case "SRV":
		return buildSRV(name, class, ttl, rdata, lineno)
	default:
		return nil, fmt.Errorf("line %d: unsupported record type %q", lineno, rtype)
	}
}

func classFromString(s string) packet.DNSClass {
	switch s {
	case "IN":
		return packet.DNSClassIN
	case "CH":
		return packet.DNSClassCH
	case "CS":
		return packet.DNSClassCS
	case "HS":
		return packet.DNSClassHS
	default:
		return packet.DNSClassIN
	}
}

func parseTTL(s string) (uint32, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	if s[len(s)-1] == 'S' {
		s = s[:len(s)-1]
	}
	multiplier := uint32(1)
	switch {
	case strings.HasSuffix(s, "W"):
		multiplier = 604800
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "D"):
		multiplier = 86400
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "H"):
		multiplier = 3600
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "M"):
		multiplier = 60
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad TTL value %q: %v", s, err)
	}
	return uint32(v) * multiplier, nil
}

func buildA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("line %d: A record requires an IP address", lineno)
	}
	ip := net.ParseIP(rdata[0])
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("line %d: invalid A record IP %q", lineno, rdata[0])
	}
	return &packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeA,
			Class: class,
			TTL:   ttl,
		},
		Address: rdata[0],
	}, nil
}

func buildAAAA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("line %d: AAAA record requires an IPv6 address", lineno)
	}
	ip := net.ParseIP(rdata[0])
	if ip == nil || ip.To16() == nil {
		return nil, fmt.Errorf("line %d: invalid AAAA record IP %q", lineno, rdata[0])
	}
	return &packet.DNSResourceRecordAAAA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeAAAA,
			Class: class,
			TTL:   ttl,
		},
		Address: rdata[0],
	}, nil
}

func buildCNAME(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("CNAME record requires a target domain")
	}
	return &packet.DNSResourceRecordCNAME{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeCNAME,
			Class: class,
			TTL:   ttl,
		},
		Domain: rdata[0],
	}, nil
}

func buildNS(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("NS record requires a nameserver domain")
	}
	return &packet.DNSResourceRecordNS{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeNS,
			Class: class,
			TTL:   ttl,
		},
		NameServer: rdata[0],
	}, nil
}

func buildMX(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 2 {
		return nil, fmt.Errorf("line %d: MX record requires preference and exchange", lineno)
	}
	pref, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid MX preference %q: %v", lineno, rdata[0], err)
	}
	return &packet.DNSResourceRecordMX{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeMX,
			Class: class,
			TTL:   ttl,
		},
		Preference: uint16(pref),
		Exchange:   rdata[1],
	}, nil
}

func buildTXT(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("TXT record requires text content")
	}
	content := strings.Join(rdata, " ")
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		content = content[1 : len(content)-1]
	}
	return &packet.DNSResourceRecordTXT{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeTXT,
			Class: class,
			TTL:   ttl,
		},
		Content: content,
	}, nil
}

func buildPTR(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("PTR record requires a target domain")
	}
	return &packet.DNSResourceRecordPTR{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypePTR,
			Class: class,
			TTL:   ttl,
		},
		PtrDomainName: rdata[0],
	}, nil
}

func buildSOA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 7 {
		return nil, fmt.Errorf("line %d: SOA requires MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM", lineno)
	}
	serial, err := strconv.ParseUint(rdata[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA serial: %v", lineno, err)
	}
	refresh, err := strconv.ParseUint(rdata[3], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA refresh: %v", lineno, err)
	}
	retry, err := strconv.ParseUint(rdata[4], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA retry: %v", lineno, err)
	}
	expire, err := strconv.ParseUint(rdata[5], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA expire: %v", lineno, err)
	}
	minimum, err := strconv.ParseUint(rdata[6], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA minimum: %v", lineno, err)
	}
	return &packet.DNSResourceRecordSOA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeSOA,
			Class: class,
			TTL:   ttl,
		},
		MName:   rdata[0],
		RName:   rdata[1],
		Serial:  uint32(serial),
		Refresh: uint32(refresh),
		Retry:   uint32(retry),
		Expire:  uint32(expire),
		Minimum: uint32(minimum),
	}, nil
}

func buildSRV(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("line %d: SRV requires priority weight port target", lineno)
	}
	priority, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SRV priority: %v", lineno, err)
	}
	weight, err := strconv.ParseUint(rdata[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SRV weight: %v", lineno, err)
	}
	port, err := strconv.ParseUint(rdata[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SRV port: %v", lineno, err)
	}
	return &packet.DNSResourceRecordSRV{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeSRV,
			Class: class,
			TTL:   ttl,
		},
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   rdata[3],
	}, nil
}
