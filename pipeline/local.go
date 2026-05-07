package pipeline

import (
	"fmt"
	"strings"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/zone"
)

// LocalSource resolves a query against records this server is authoritative
// for. The pipeline holds it as an interface so the config-driven LocalIndex
// can later be swapped for a database- or API-backed implementation without
// touching the request path.
type LocalSource interface {
	Lookup(qname string, qtype packet.DNSType) []packet.DNSResource
}

// LocalIndex is the default LocalSource: an in-memory map populated from
// `domains:` in config.yaml (inline records or BIND zone files). Lookups are
// O(zones * records); the assumption is "domains" is a small static list.
type LocalIndex struct {
	zones map[string][]packet.DNSResource // origin (lower-cased, no trailing dot)
}

func NewLocalIndex(domains []config.DomainSpec) (*LocalIndex, error) {
	li := &LocalIndex{zones: make(map[string][]packet.DNSResource)}
	for i, d := range domains {
		if d.Domain == "" {
			return nil, fmt.Errorf("domains[%d]: domain required", i)
		}
		origin := strings.ToLower(strings.TrimSuffix(d.Domain, "."))

		var z *zone.Zone
		var err error
		switch {
		case d.ZoneFile != "" && len(d.Records) > 0:
			return nil, fmt.Errorf("domains[%d] (%s): only one of records or zone_file allowed", i, d.Domain)
		case d.ZoneFile != "":
			z, err = zone.ParseFile(d.ZoneFile)
		default:
			z, err = parseInline(origin, d.Records)
		}
		if err != nil {
			return nil, fmt.Errorf("domains[%d] (%s): %w", i, d.Domain, err)
		}
		li.zones[origin] = append(li.zones[origin], z.Records...)
	}
	return li, nil
}

func parseInline(origin string, records []string) (*zone.Zone, error) {
	if len(records) == 0 {
		return &zone.Zone{Origin: origin}, nil
	}
	var b strings.Builder
	b.WriteString("$ORIGIN ")
	b.WriteString(origin)
	b.WriteString(".\n")
	for _, line := range records {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return zone.Parse([]byte(b.String()))
}

func (li *LocalIndex) Lookup(qname string, qtype packet.DNSType) []packet.DNSResource {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	origin := li.matchZone(qname)
	if origin == "" {
		return nil
	}
	var out []packet.DNSResource
	for _, r := range li.zones[origin] {
		name := strings.ToLower(recordName(r))
		if name != qname {
			continue
		}
		if r.GetType() != qtype {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (li *LocalIndex) matchZone(qname string) string {
	best := ""
	for origin := range li.zones {
		if origin == qname || strings.HasSuffix(qname, "."+origin) {
			if len(origin) > len(best) {
				best = origin
			}
		}
	}
	return best
}

func recordName(r packet.DNSResource) string {
	switch x := r.(type) {
	case *packet.DNSResourceRecordA:
		return x.Name
	case *packet.DNSResourceRecordAAAA:
		return x.Name
	case *packet.DNSResourceRecordCNAME:
		return x.Name
	case *packet.DNSResourceRecordMX:
		return x.Name
	case *packet.DNSResourceRecordNS:
		return x.Name
	case *packet.DNSResourceRecordTXT:
		return x.Name
	case *packet.DNSResourceRecordPTR:
		return x.Name
	case *packet.DNSResourceRecordSOA:
		return x.Name
	case *packet.DNSResourceRecordSRV:
		return x.Name
	case *packet.DNSResourceRecordEDNS:
		return x.Name
	case *packet.DNSResourceRecordUnknown:
		return x.Name
	}
	return ""
}
