// Package engine answers DNS queries from local zones, a filter, a cache,
// and upstream resolvers. Engine implements server.Handler; Service wires
// one from a config file and is the surface a management API builds on.
package engine

import (
	"context"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/client"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
	"github.com/lsongdev/dns-go/zone"
)

// Source says which stage produced an answer.
type Source string

const (
	SourceInvalid  Source = "invalid"  // rejected before resolution (FORMERR, NOTIMP, BADVERS, ...)
	SourcePolicy   Source = "policy"   // refused by policy (zone transfer, out-of-zone)
	SourceZone     Source = "zone"     // local zone data
	SourceFilter   Source = "filter"   // blocked by a filter rule
	SourceCache    Source = "cache"    // cached upstream answer
	SourceUpstream Source = "upstream" // fresh upstream answer
	SourceError    Source = "error"    // upstream failure (SERVFAIL)
)

// BlockMode is how blocked names are answered.
type BlockMode uint32

const (
	// BlockZeroIP answers A with 0.0.0.0, AAAA with ::, other types NODATA.
	BlockZeroIP BlockMode = iota
	BlockNXDomain
	BlockRefused
)

const (
	// DefaultTimeout bounds the whole resolution of one query.
	DefaultTimeout = 8 * time.Second
	blockedTTL     = 60
	maxCNAMEChase  = 8
)

// Options configures an Engine. A nil Upstream makes it an authoritative
// server: no recursion is advertised and names outside zones are REFUSED.
type Options struct {
	Zones     *zone.Store    // required; may be empty
	Filter    *filter.Filter // nil disables filtering
	Cache     *cache.Cache   // nil disables caching
	Upstream  client.Client  // nil: authoritative only
	BlockMode BlockMode
	// UDPSize is advertised in OPT records. Zero means server.DefaultUDPSize.
	UDPSize uint16
	// Timeout bounds each resolution. Zero means DefaultTimeout.
	Timeout time.Duration
	// OnQuery, if set, is called synchronously after each reply is written.
	// It must not block; hand events to a buffered channel for slow sinks.
	OnQuery func(QueryEvent)
}

// Engine is safe for concurrent use. Its components may be changed at
// runtime through their own APIs (zone.Store, filter.Filter, cache.Cache).
type Engine struct {
	zones    *zone.Store
	filter   *filter.Filter
	cache    *cache.Cache
	upstream client.Client
	udpSize  uint16
	timeout  time.Duration
	onQuery  func(QueryEvent)

	blockMode atomic.Uint32
}

func New(opts Options) *Engine {
	e := &Engine{
		zones:    opts.Zones,
		filter:   opts.Filter,
		cache:    opts.Cache,
		upstream: opts.Upstream,
		udpSize:  opts.UDPSize,
		timeout:  opts.Timeout,
		onQuery:  opts.OnQuery,
	}
	if e.zones == nil {
		e.zones = zone.NewStore(zone.StoreOptions{})
	}
	if e.udpSize == 0 {
		e.udpSize = server.DefaultUDPSize
	}
	if e.timeout <= 0 {
		e.timeout = DefaultTimeout
	}
	e.blockMode.Store(uint32(opts.BlockMode))
	return e
}

func (e *Engine) Zones() *zone.Store     { return e.zones }
func (e *Engine) Filter() *filter.Filter { return e.filter }
func (e *Engine) Cache() *cache.Cache    { return e.cache }
func (e *Engine) Recursive() bool        { return e.upstream != nil }

func (e *Engine) BlockMode() BlockMode     { return BlockMode(e.blockMode.Load()) }
func (e *Engine) SetBlockMode(m BlockMode) { e.blockMode.Store(uint32(m)) }

// QueryEvent describes one answered query, for logging and statistics.
type QueryEvent struct {
	Time      time.Time
	Duration  time.Duration
	Client    net.Addr
	Transport server.Transport
	Name      string
	Type      packet.DNSType
	Class     packet.DNSClass
	RCode     uint16
	Answers   int
	Source    Source
	Filter    filter.Match // set when a filter rule matched (block or allow)
	Err       error        // upstream error behind a SERVFAIL
}

// Result is a complete reply plus how it was produced.
type Result struct {
	Msg    *packet.DNSPacket
	Source Source
	Filter filter.Match
	Err    error
}

// ServeDNS implements server.Handler.
func (e *Engine) ServeDNS(ctx context.Context, w server.ResponseWriter, req *packet.DNSPacket) {
	if req.Header == nil || req.Header.QR != packet.DNSQuery {
		return // never answer responses: avoids reflection loops
	}
	start := time.Now()
	res := e.Resolve(ctx, req)
	_ = w.WriteMsg(res.Msg)
	if e.onQuery == nil {
		return
	}
	ev := QueryEvent{
		Time:      start,
		Duration:  time.Since(start),
		Client:    w.RemoteAddr(),
		Transport: w.Transport(),
		RCode:     res.Msg.RCode(),
		Answers:   len(res.Msg.Answers),
		Source:    res.Source,
		Filter:    res.Filter,
		Err:       res.Err,
	}
	if len(req.Questions) > 0 {
		q := req.Questions[0]
		ev.Name, ev.Type, ev.Class = q.Name, q.Type, q.Class
	}
	e.onQuery(ev)
}

// Resolve produces the complete reply to req, ready to be written. It is the
// programmatic entry point for tools such as a "test this query" API.
func (e *Engine) Resolve(ctx context.Context, req *packet.DNSPacket) Result {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	res := packet.NewReply(req)
	reqOPT := req.OPT()
	q := firstQuestion(req)
	var r answer
	switch {
	case req.Header.OpCode != uint8(packet.DNSOpCodeQuery):
		r = answer{rcode: packet.RCodeNotImplemented, source: SourceInvalid}
	case len(req.Questions) != 1 || countOPT(req) > 1:
		r = answer{rcode: packet.RCodeFormatError, source: SourceInvalid}
	case reqOPT != nil && reqOPT.Version != 0:
		r = answer{rcode: packet.RCodeBadVersion, source: SourceInvalid}
	case q.Type == packet.DNSTypeAXFR || q.Type == packet.DNSTypeIXFR:
		r = answer{rcode: packet.RCodeRefused, source: SourcePolicy}
	case q.Type == packet.DNSTypeMAILA || q.Type == packet.DNSTypeMAILB:
		r = answer{rcode: packet.RCodeNotImplemented, source: SourceInvalid}
	default:
		do := reqOPT != nil && reqOPT.GetDNSSECOK()
		r = e.resolve(ctx, q, do, req.Header.CD == 1, 0)
	}
	e.finalize(req, res, r)
	return Result{Msg: res, Source: r.source, Filter: r.match, Err: r.err}
}

// answer is the outcome of resolving one question.
type answer struct {
	rcode         uint16
	authoritative bool
	ad            bool
	answers       []packet.DNSResource
	authorities   []packet.DNSResource
	additionals   []packet.DNSResource
	source        Source
	match         filter.Match
	err           error
}

func (e *Engine) resolve(ctx context.Context, q *packet.DNSQuestion, do, cd bool, depth int) answer {
	if r := e.zones.Lookup(q.Name, q.Type, q.Class); r.Found {
		a := answer{
			rcode:         r.RCode,
			authoritative: r.Authoritative,
			answers:       r.Answers,
			authorities:   r.Authorities,
			additionals:   r.Additionals,
			source:        SourceZone,
		}
		if e.upstream != nil {
			e.chaseCNAME(ctx, q, do, cd, depth, &a)
		}
		return a
	}
	if e.upstream == nil {
		return answer{rcode: packet.RCodeRefused, source: SourcePolicy}
	}

	var match filter.Match
	if e.filter != nil {
		match = e.filter.Match(q.Name)
		if match.Action == filter.Block {
			a := e.blocked(q)
			a.match = match
			return a
		}
	}

	key := cache.KeyFor(q, do, cd)
	if e.cache != nil {
		if msg, ok := e.cache.Get(key); ok {
			a := fromMessage(msg, SourceCache)
			a.match = match
			return a
		}
	}

	msg, err := e.upstream.Query(ctx, upstreamQuery(q, do, cd, e.udpSize))
	if err != nil {
		return answer{rcode: packet.RCodeServerFailure, source: SourceError, match: match, err: err}
	}
	stripOPT(msg)
	if e.cache != nil {
		e.cache.Put(key, msg)
	}
	a := fromMessage(msg, SourceUpstream)
	a.match = match
	return a
}

// chaseCNAME completes a local answer whose CNAME chain leaves local data
// (e.g. an override "www.example.com CNAME cdn.example.net") by resolving
// the final target through the normal pipeline, as a recursive server must.
func (e *Engine) chaseCNAME(ctx context.Context, q *packet.DNSQuestion, do, cd bool, depth int, a *answer) {
	if depth >= maxCNAMEChase || a.rcode != packet.RCodeSuccess || len(a.answers) == 0 ||
		q.Type == packet.DNSTypeCNAME || q.Type == packet.DNSTypeAny {
		return
	}
	last, ok := a.answers[len(a.answers)-1].(*packet.DNSResourceRecordCNAME)
	if !ok {
		return
	}
	target := e.resolve(ctx, &packet.DNSQuestion{Name: last.Domain, Type: q.Type, Class: q.Class}, do, cd, depth+1)
	a.answers = append(append([]packet.DNSResource(nil), a.answers...), target.answers...)
	a.rcode = target.rcode
	a.authoritative = false
	if len(target.answers) == 0 {
		a.authorities = target.authorities
	}
	if target.err != nil {
		a.err = target.err
	}
}

func (e *Engine) blocked(q *packet.DNSQuestion) answer {
	a := answer{rcode: packet.RCodeSuccess, source: SourceFilter}
	switch e.BlockMode() {
	case BlockNXDomain:
		a.rcode = packet.RCodeNameError
	case BlockRefused:
		a.rcode = packet.RCodeRefused
	default:
		hdr := packet.DNSResourceRecord{Name: q.Name, Type: q.Type, Class: packet.DNSClassIN, TTL: blockedTTL}
		switch q.Type {
		case packet.DNSTypeA:
			a.answers = []packet.DNSResource{&packet.DNSResourceRecordA{DNSResourceRecord: hdr, Address: "0.0.0.0"}}
		case packet.DNSTypeAAAA:
			a.answers = []packet.DNSResource{&packet.DNSResourceRecordAAAA{DNSResourceRecord: hdr, Address: "::"}}
		}
	}
	return a
}

// finalize fills res from a, applying the protocol rules every reply obeys.
func (e *Engine) finalize(req, res *packet.DNSPacket, a answer) {
	reqOPT := req.OPT()
	do := reqOPT != nil && reqOPT.GetDNSSECOK()
	qtype := packet.DNSType(0)
	if q := firstQuestion(req); q != nil {
		qtype = q.Type
	}

	res.Answers = dnssecFilter(a.answers, do, qtype)
	res.Authorities = dnssecFilter(a.authorities, do, qtype)
	res.Additionals = dnssecFilter(a.additionals, do, qtype)
	if a.authoritative {
		res.Header.AA = 1
	}
	if e.upstream != nil {
		res.Header.RA = 1
	}
	// RFC 6840 §5.7-5.8: AD only for upstream-validated data, and only to
	// clients that signalled they understand it.
	if a.ad && (req.Header.AD == 1 || do) {
		res.Header.AD = 1
	}
	if reqOPT != nil {
		opt := packet.NewEDNSRecord(e.udpSize)
		opt.SetDNSSECOK(do)
		res.SetOPT(opt)
	}
	res.SetRCode(a.rcode)
}

func fromMessage(msg *packet.DNSPacket, source Source) answer {
	return answer{
		rcode:       msg.RCode(),
		ad:          msg.Header.AD == 1,
		answers:     msg.Answers,
		authorities: msg.Authorities,
		additionals: msg.Additionals,
		source:      source,
	}
}

// upstreamQuery builds a fresh query rather than relaying the client's, so
// client EDNS options (ECS, cookies, padding) never leak upstream and the
// ID is unpredictable.
func upstreamQuery(q *packet.DNSQuestion, do, cd bool, udpSize uint16) *packet.DNSPacket {
	msg := &packet.DNSPacket{Header: &packet.DNSHeader{ID: uint16(rand.Uint32()), RD: 1}}
	if cd {
		msg.Header.CD = 1
	}
	msg.AddQuestion(&packet.DNSQuestion{Name: q.Name, Type: q.Type, Class: q.Class})
	opt := packet.NewEDNSRecord(udpSize)
	opt.SetDNSSECOK(do)
	msg.SetOPT(opt)
	return msg
}

// stripOPT drops the upstream OPT after folding its extended RCODE into the
// header, leaving a transport-neutral message for the cache.
func stripOPT(msg *packet.DNSPacket) {
	if msg.OPT() == nil {
		return
	}
	rcode := msg.RCode()
	msg.SetOPT(nil)
	if rcode <= 0x0F {
		msg.Header.RCode = uint8(rcode)
	} else {
		msg.Header.RCode = uint8(packet.RCodeServerFailure)
	}
}

// dnssecFilter removes DNSSEC records the client did not ask for (RFC 4035
// §3.2.1): RRSIG/NSEC/NSEC3 only go to DO=1 clients or explicit queries.
func dnssecFilter(records []packet.DNSResource, do bool, qtype packet.DNSType) []packet.DNSResource {
	if do {
		return records
	}
	out := records[:0:0]
	for _, r := range records {
		switch t := r.GetType(); t {
		case packet.DNSTypeRRSIG, packet.DNSTypeNSEC, packet.DNSTypeNSEC3:
			if t != qtype {
				continue
			}
		case packet.DNSTypeEDNS:
			continue
		}
		out = append(out, r)
	}
	return out
}

func firstQuestion(req *packet.DNSPacket) *packet.DNSQuestion {
	if len(req.Questions) == 0 {
		return nil
	}
	return req.Questions[0]
}

func countOPT(p *packet.DNSPacket) int {
	n := 0
	for _, r := range p.Additionals {
		if r.GetType() == packet.DNSTypeEDNS {
			n++
		}
	}
	return n
}
