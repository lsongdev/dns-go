package pipeline

import "github.com/lsongdev/dns-go/packet"

// StripEDNSIfNeeded normalises EDNS in res before sending downstream:
//   - if the request has no OPT, strip OPT entirely (older clients reject it);
//   - otherwise, drop the EDNS Padding option (RFC 7830). Upstream DoH/DoT
//     servers pad responses to defeat traffic analysis on the encrypted hop;
//     once we re-emit on a plain UDP socket the padding is just bloat
//     (a 50-byte answer balloons past 450 bytes).
func StripEDNSIfNeeded(req, res *packet.DNSPacket) {
	if res == nil || res.Header == nil {
		return
	}
	if !hasEDNS(res) {
		return
	}
	if !hasEDNS(req) {
		filtered := make([]packet.DNSResource, 0, len(res.Additionals))
		for _, add := range res.Additionals {
			if add.GetType() == packet.DNSTypeEDNS {
				continue
			}
			filtered = append(filtered, add)
		}
		res.Additionals = filtered
		res.Header.ARCount = uint16(len(filtered))
		return
	}
	for _, add := range res.Additionals {
		opt, ok := add.(*packet.DNSResourceRecordEDNS)
		if !ok {
			continue
		}
		if len(opt.Options) == 0 {
			continue
		}
		kept := opt.Options[:0]
		for _, o := range opt.Options {
			if o.Code == packet.EDNSOptionPadding {
				continue
			}
			kept = append(kept, o)
		}
		opt.Options = kept
	}
}

func hasEDNS(p *packet.DNSPacket) bool {
	if p == nil {
		return false
	}
	for _, add := range p.Additionals {
		if add.GetType() == packet.DNSTypeEDNS {
			return true
		}
	}
	return false
}
