package zone

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

var typeNames = map[packet.DNSType]string{
	packet.DNSTypeA: "A", packet.DNSTypeNS: "NS", packet.DNSTypeCNAME: "CNAME",
	packet.DNSTypeSOA: "SOA", packet.DNSTypePTR: "PTR", packet.DNSTypeMX: "MX",
	packet.DNSTypeTXT: "TXT", packet.DNSTypeAAAA: "AAAA", packet.DNSTypeSRV: "SRV",
	packet.DNSTypeDS: "DS", packet.DNSTypeRRSIG: "RRSIG", packet.DNSTypeNSEC: "NSEC",
	packet.DNSTypeDNSKEY: "DNSKEY", packet.DNSTypeNSEC3: "NSEC3", packet.DNSTypeTLSA: "TLSA",
	packet.DNSTypeSVCB: "SVCB", packet.DNSTypeHTTPS: "HTTPS", packet.DNSTypeCAA: "CAA",
	packet.DNSTypeEDNS: "OPT", packet.DNSTypeAXFR: "AXFR", packet.DNSTypeIXFR: "IXFR",
	packet.DNSTypeAny: "ANY", packet.DNSTypeSPF: "SPF",
}

// TypeString returns the mnemonic of t, or "TYPEn" (RFC 3597).
func TypeString(t packet.DNSType) string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType parses a mnemonic ("AAAA", case-insensitive) or "TYPEn".
func ParseType(s string) (packet.DNSType, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	for t, name := range typeNames {
		if name == upper {
			return t, nil
		}
	}
	if n, ok := strings.CutPrefix(upper, "TYPE"); ok {
		if v, err := strconv.ParseUint(n, 10, 16); err == nil {
			return packet.DNSType(v), nil
		}
	}
	return 0, fmt.Errorf("unknown DNS type %q", s)
}

// Format renders r as a zone-file line with an absolute owner name.
func Format(r packet.DNSResource) string {
	h := r.Header()
	return fmt.Sprintf("%s %d %s %s %s", fqdn(h.Name), h.TTL, h.Class, TypeString(h.Type), FormatRData(r))
}

// FormatRData renders the RDATA of r in presentation format. Names are
// absolute (trailing dot), so the output parses back under any origin.
func FormatRData(r packet.DNSResource) string {
	switch x := r.(type) {
	case *packet.DNSResourceRecordA:
		return x.Address
	case *packet.DNSResourceRecordAAAA:
		return x.Address
	case *packet.DNSResourceRecordCNAME:
		return fqdn(x.Domain)
	case *packet.DNSResourceRecordNS:
		return fqdn(x.NameServer)
	case *packet.DNSResourceRecordPTR:
		return fqdn(x.PtrDomainName)
	case *packet.DNSResourceRecordMX:
		return fmt.Sprintf("%d %s", x.Preference, fqdn(x.Exchange))
	case *packet.DNSResourceRecordTXT:
		return quote(x.Content)
	case *packet.DNSResourceRecordSOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", fqdn(x.MName), fqdn(x.RName), x.Serial, x.Refresh, x.Retry, x.Expire, x.Minimum)
	case *packet.DNSResourceRecordSRV:
		return fmt.Sprintf("%d %d %d %s", x.Priority, x.Weight, x.Port, fqdn(x.Target))
	case *packet.DNSResourceRecordCAA:
		return fmt.Sprintf("%d %s %s", x.Flags, x.Tag, quote(x.Value))
	case *packet.DNSResourceRecordDS:
		return fmt.Sprintf("%d %d %d %s", x.KeyTag, x.Algorithm, x.DigestType, strings.ToUpper(hex.EncodeToString(x.Digest)))
	case *packet.DNSResourceRecordDNSKEY:
		return fmt.Sprintf("%d %d %d %s", x.Flags, x.Protocol, x.Algorithm, base64.StdEncoding.EncodeToString(x.PublicKey))
	case *packet.DNSResourceRecordRRSIG:
		return fmt.Sprintf("%s %d %d %d %s %s %d %s %s", TypeString(x.TypeCovered), x.Algorithm, x.Labels, x.OriginalTTL,
			sigTime(x.Expiration), sigTime(x.Inception), x.KeyTag, fqdn(x.SignerName), base64.StdEncoding.EncodeToString(x.Signature))
	case *packet.DNSResourceRecordNSEC:
		parts := []string{fqdn(x.NextDomain)}
		for _, t := range x.Types {
			parts = append(parts, TypeString(t))
		}
		return strings.Join(parts, " ")
	case *packet.DNSResourceRecordTLSA:
		return fmt.Sprintf("%d %d %d %s", x.Usage, x.Selector, x.MatchingType, strings.ToUpper(hex.EncodeToString(x.CertificateAssociationData)))
	case *packet.DNSResourceRecordSVCB:
		parts := []string{strconv.Itoa(int(x.Priority)), fqdn(x.Target)}
		for _, p := range x.Params {
			parts = append(parts, formatSVCBParam(p))
		}
		return strings.Join(parts, " ")
	case *packet.DNSResourceRecordUnknown:
		return fmt.Sprintf(`\# %d %s`, len(x.RData), strings.ToUpper(hex.EncodeToString(x.RData)))
	default:
		data := r.Encode()
		return fmt.Sprintf(`\# %d %s`, len(data), strings.ToUpper(hex.EncodeToString(data)))
	}
}

func fqdn(name string) string {
	name = strings.TrimRight(name, ".")
	if name == "" {
		return "."
	}
	return name + "."
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func sigTime(t uint32) string {
	return time.Unix(int64(t), 0).UTC().Format("20060102150405")
}

var svcbKeyNames = map[uint16]string{
	packet.SVCBParamKeyMandatory: "mandatory", packet.SVCBParamKeyALPN: "alpn",
	packet.SVCBParamKeyNoDefaultALPN: "no-default-alpn", packet.SVCBParamKeyPort: "port",
	packet.SVCBParamKeyIPv4Hint: "ipv4hint", packet.SVCBParamKeyECH: "ech",
	packet.SVCBParamKeyIPv6Hint: "ipv6hint", packet.SVCBParamKeyDoHPath: "dohpath",
}

func svcbKeyName(key uint16) string {
	if name, ok := svcbKeyNames[key]; ok {
		return name
	}
	return "key" + strconv.Itoa(int(key))
}

func formatSVCBParam(p packet.SVCBParam) string {
	name := svcbKeyName(p.Key)
	v := p.Value
	switch p.Key {
	case packet.SVCBParamKeyNoDefaultALPN:
		return name
	case packet.SVCBParamKeyMandatory:
		var keys []string
		for i := 0; i+1 < len(v); i += 2 {
			keys = append(keys, svcbKeyName(binary.BigEndian.Uint16(v[i:])))
		}
		return name + "=" + strings.Join(keys, ",")
	case packet.SVCBParamKeyALPN:
		var ids []string
		for i := 0; i < len(v); {
			n := int(v[i])
			if i+1+n > len(v) {
				break
			}
			ids = append(ids, string(v[i+1:i+1+n]))
			i += 1 + n
		}
		return name + "=" + strings.Join(ids, ",")
	case packet.SVCBParamKeyPort:
		if len(v) == 2 {
			return name + "=" + strconv.Itoa(int(binary.BigEndian.Uint16(v)))
		}
	case packet.SVCBParamKeyIPv4Hint, packet.SVCBParamKeyIPv6Hint:
		size := net.IPv4len
		if p.Key == packet.SVCBParamKeyIPv6Hint {
			size = net.IPv6len
		}
		var ips []string
		for i := 0; i+size <= len(v); i += size {
			ips = append(ips, net.IP(v[i:i+size]).String())
		}
		return name + "=" + strings.Join(ips, ",")
	case packet.SVCBParamKeyECH:
		return name + "=" + base64.StdEncoding.EncodeToString(v)
	}
	return name + "=" + quote(string(v))
}
