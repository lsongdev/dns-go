package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/zone"
)

const maxBodySize = 8 << 20

// Options configures the HTTP handler.
type Options struct {
	// Token, when set, must be sent as "Authorization: Bearer <token>" on
	// every /api request. Static panel files are served without it.
	Token string
	// Panel holds the web panel's static files, served at "/". Nil serves
	// only the API.
	Panel fs.FS
}

// Handler serves /api and the panel.
type Handler struct {
	mgr     *Manager
	stats   *Stats
	opts    Options
	started time.Time
	mux     *http.ServeMux
}

// NewHandler returns the API handler. stats may be nil.
func NewHandler(mgr *Manager, stats *Stats, opts Options) *Handler {
	if stats == nil {
		stats = NewStats()
	}
	h := &Handler{mgr: mgr, stats: stats, opts: opts, started: time.Now(), mux: http.NewServeMux()}
	routes := map[string]func(*http.Request) (any, error){
		"GET /api/status":                        h.status,
		"GET /api/stats":                         h.statsSummary,
		"GET /api/querylog":                      h.queryLog,
		"POST /api/resolve":                      h.resolve,
		"GET /api/zones":                         h.listZones,
		"POST /api/zones":                        h.createZone,
		"GET /api/zones/{zone}":                  h.getZone,
		"PUT /api/zones/{zone}":                  h.putZone,
		"DELETE /api/zones/{zone}":               h.deleteZone,
		"POST /api/zones/{zone}/records":         h.addRecord,
		"PUT /api/zones/{zone}/records/{id}":     h.putRecord,
		"DELETE /api/zones/{zone}/records/{id}":  h.deleteRecord,
		"GET /api/filters":                       h.getFilters,
		"PUT /api/filters/rules":                 h.putRules,
		"PUT /api/filters/block_mode":            h.putBlockMode,
		"GET /api/filters/check":                 h.checkFilter,
		"POST /api/filters/lists":                h.createList,
		"PUT /api/filters/lists/{name}":          h.putList,
		"DELETE /api/filters/lists/{name}":       h.deleteList,
		"POST /api/filters/lists/{name}/refresh": h.refreshList,
		"GET /api/access":                        h.getAccess,
		"PUT /api/access":                        h.putAccess,
		"DELETE /api/cache":                      h.flushCache,
	}
	for pattern, fn := range routes {
		h.mux.Handle(pattern, h.endpoint(fn))
	}
	h.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "no such endpoint"})
	})
	if opts.Panel != nil {
		h.mux.Handle("/", panelHandler(opts.Panel))
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") && !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="dns-go"`)
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) authorized(r *http.Request) bool {
	if h.opts.Token == "" {
		return true
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(h.opts.Token)) == 1
}

type errorBody struct {
	Error   string `json:"error"`
	Details any    `json:"details,omitempty"`
}

// endpoint adapts a handler returning (value, error) to JSON responses.
func (h *Handler) endpoint(fn func(*http.Request) (any, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		v, err := fn(r)
		if err != nil {
			body := errorBody{Error: err.Error()}
			var detailed interface{ Details() any }
			if errors.As(err, &detailed) {
				body.Details = detailed.Details()
			}
			writeJSON(w, statusOf(err), body)
			return
		}
		if v == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
}

func statusOf(err error) int {
	var invalid *InvalidError
	var notFound *NotFoundError
	var badRequest *badRequestError
	var conflict *conflictError
	var rules *rulesError
	switch {
	case errors.As(err, &badRequest), errors.As(err, &invalid), errors.As(err, &rules):
		return http.StatusBadRequest
	case errors.As(err, &notFound):
		return http.StatusNotFound
	case errors.As(err, &conflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

type badRequestError struct{ msg string }

func (e *badRequestError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &badRequestError{fmt.Sprintf(format, args...)}
}

type conflictError struct{ msg string }

func (e *conflictError) Error() string { return e.msg }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid JSON body: %v", err)
	}
	return nil
}

// ---- status, stats, query log, resolve ----

type statusBody struct {
	Version   string        `json:"version"`
	Mode      string        `json:"mode"`
	Storage   string        `json:"storage"`
	Uptime    int64         `json:"uptime_seconds"`
	Listens   []listenBody  `json:"listens"`
	Upstreams []string      `json:"upstreams"`
	Zones     int           `json:"zones"`
	Filter    *filterCounts `json:"filter,omitempty"`
	Cache     *cacheBody    `json:"cache,omitempty"`
	Clients   int           `json:"clients"`
}

type listenBody struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
	TLS  bool   `json:"tls"`
}

type filterCounts struct {
	Lists int `json:"lists"`
	Rules int `json:"rules"`
}

type cacheBody struct {
	Entries int `json:"entries"`
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "devel"
}

func (h *Handler) status(r *http.Request) (any, error) {
	cfg, d := h.mgr.Settings(), h.mgr.Data()
	svc := h.mgr.Service()
	out := statusBody{
		Version: version(),
		Mode:    cfg.Mode,
		Storage: cfg.Storage.Type,
		Uptime:  int64(time.Since(h.started).Seconds()),
		Zones:   len(svc.Zones.List()),
		Clients: len(d.Access.Clients),
	}
	for _, l := range cfg.Listens {
		out.Listens = append(out.Listens, listenBody{Type: l.Type, Addr: l.Addr, TLS: l.CertFile != ""})
	}
	for _, u := range cfg.Upstreams {
		out.Upstreams = append(out.Upstreams, u.Type+" "+u.Addr)
	}
	if svc.Filter != nil {
		counts := filterCounts{}
		for _, l := range svc.Filter.Lists() {
			counts.Lists++
			counts.Rules += l.Rules
		}
		out.Filter = &counts
	}
	if svc.Cache != nil {
		out.Cache = &cacheBody{Entries: svc.Cache.Len()}
	}
	return out, nil
}

func (h *Handler) statsSummary(r *http.Request) (any, error) {
	n := intParam(r, "top", 10)
	bucket := intParam(r, "bucket", 10)
	return h.stats.Summary(n, bucket), nil
}

func (h *Handler) queryLog(r *http.Request) (any, error) {
	q := r.URL.Query()
	return h.stats.Log(LogQuery{
		Limit:  intParam(r, "limit", 100),
		Search: q.Get("search"),
		Source: q.Get("source"),
		Client: q.Get("client"),
	}), nil
}

func intParam(r *http.Request, name string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil && v > 0 {
		return v
	}
	return def
}

type resolveRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	DO   bool   `json:"do"`
}

type resolveBody struct {
	RCode       string       `json:"rcode"`
	Source      string       `json:"source"`
	Filter      *filterMatch `json:"filter,omitempty"`
	Error       string       `json:"error,omitempty"`
	Flags       []string     `json:"flags"`
	Answers     []recordBody `json:"answers"`
	Authorities []recordBody `json:"authorities"`
	Additionals []recordBody `json:"additionals"`
	DurationUs  int64        `json:"duration_us"`
}

type filterMatch struct {
	Action string `json:"action"`
	List   string `json:"list,omitempty"`
	Rule   string `json:"rule,omitempty"`
}

func (h *Handler) resolve(r *http.Request) (any, error) {
	var req resolveRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, badRequest("name required")
	}
	qtype := packet.DNSTypeA
	if req.Type != "" {
		t, err := zone.ParseType(req.Type)
		if err != nil {
			return nil, badRequest("%v", err)
		}
		qtype = t
	}
	q := packet.NewPacket()
	q.Header.RD = 1
	q.AddQuestion(&packet.DNSQuestion{Name: zone.CanonicalName(name), Type: qtype, Class: packet.DNSClassIN})
	opt := packet.NewEDNSRecord(1232)
	opt.SetDNSSECOK(req.DO)
	q.SetOPT(opt)

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := h.mgr.Service().Engine.Resolve(ctx, q)
	out := resolveBody{
		RCode:       rcodeName(res.Msg.RCode()),
		Source:      string(res.Source),
		Flags:       flags(res.Msg.Header),
		Answers:     recordList(res.Msg.Answers, ""),
		Authorities: recordList(res.Msg.Authorities, ""),
		Additionals: recordList(res.Msg.Additionals, ""),
		DurationUs:  time.Since(start).Microseconds(),
	}
	if res.Filter.Action != filter.Pass {
		out.Filter = &filterMatch{Action: res.Filter.Action.String(), List: res.Filter.List, Rule: res.Filter.Rule}
	}
	if res.Err != nil {
		out.Error = res.Err.Error()
	}
	return out, nil
}

func flags(h *packet.DNSHeader) []string {
	out := []string{}
	for _, f := range []struct {
		set  uint8
		name string
	}{{h.AA, "aa"}, {h.TC, "tc"}, {h.RD, "rd"}, {h.RA, "ra"}, {h.AD, "ad"}, {h.CD, "cd"}} {
		if f.set == 1 {
			out = append(out, f.name)
		}
	}
	return out
}

func (h *Handler) flushCache(r *http.Request) (any, error) {
	if c := h.mgr.Service().Cache; c != nil {
		c.Flush()
	}
	return nil, nil
}

// ---- zones ----

// recordBody is one resource record. Name is relative to the zone ("@" for
// the apex) when listed under a zone, absolute elsewhere. Data is the RDATA
// in zone-file presentation format; relative names in it are completed with
// the zone origin.
type recordBody struct {
	ID   string `json:"id,omitempty"` // content-derived; changes when the record does
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	Type string `json:"type"`
	Data string `json:"data"`
}

type zoneSummary struct {
	ID       string `json:"id"`     // URL identifier: the origin, or "@" for the root
	Origin   string `json:"origin"` // "." for the root
	Kind     string `json:"kind"`
	Source   string `json:"source"` // records | zone_file | hosts_file
	Path     string `json:"path,omitempty"`
	Editable bool   `json:"editable"`
	Records  int    `json:"records"`
}

type zoneBody struct {
	zoneSummary
	RecordList []recordBody `json:"record_list"`
}

type zoneWrite struct {
	Origin  string       `json:"origin"`
	Kind    string       `json:"kind"`
	Records []recordBody `json:"records"`
}

func zoneID(origin string) string {
	if origin == "" {
		return "@"
	}
	return origin
}

func originFromID(id string) string {
	if id == "@" {
		return ""
	}
	return zone.CanonicalName(id)
}

func displayOrigin(origin string) string {
	if origin == "" {
		return "."
	}
	return origin
}

// findDomain returns the index of the domain with origin, or -1.
func findDomain(d *config.Data, origin string) int {
	for i, dom := range d.Domains {
		if zone.CanonicalName(dom.Domain) == origin {
			return i
		}
	}
	return -1
}

func summarize(dom config.DomainSpec, z *zone.Zone) zoneSummary {
	origin := zone.CanonicalName(dom.Domain)
	s := zoneSummary{ID: zoneID(origin), Origin: displayOrigin(origin), Kind: dom.Kind, Source: "records", Editable: true}
	switch {
	case dom.ZoneFile != "":
		s.Source, s.Path, s.Editable = "zone_file", dom.ZoneFile, false
	case dom.HostsFile != "":
		s.Source, s.Path, s.Editable = "hosts_file", dom.HostsFile, false
	}
	if z != nil {
		s.Records = len(z.Records)
	}
	return s
}

func (h *Handler) listZones(r *http.Request) (any, error) {
	d := h.mgr.Data()
	out := []zoneSummary{}
	for _, dom := range d.Domains {
		z, _ := h.mgr.Service().Zones.Get(dom.Domain)
		out = append(out, summarize(dom, z))
	}
	return out, nil
}

func (h *Handler) getZone(r *http.Request) (any, error) {
	origin := originFromID(r.PathValue("zone"))
	d := h.mgr.Data()
	i := findDomain(&d, origin)
	if i < 0 {
		return nil, &NotFoundError{"zone " + displayOrigin(origin)}
	}
	dom := d.Domains[i]
	z, _ := h.mgr.Service().Zones.Get(origin)
	out := zoneBody{zoneSummary: summarize(dom, z), RecordList: []recordBody{}}
	if out.Editable {
		// Editable zones list their stored lines, so IDs match what an
		// update will look up.
		for _, line := range dom.Records {
			if rt, err := zone.ParseRecordText(displayOrigin(origin), line); err == nil {
				out.RecordList = append(out.RecordList, recordOf(rt))
			}
		}
	} else if z != nil {
		out.RecordList = recordList(z.Records, origin)
	}
	return out, nil
}

func recordOf(rt zone.RecordText) recordBody {
	return recordBody{ID: rt.ID(), Name: rt.Name, TTL: rt.TTL, Type: rt.Type, Data: rt.Data}
}

func recordList(records []packet.DNSResource, origin string) []recordBody {
	out := make([]recordBody, 0, len(records))
	for _, r := range records {
		if r.GetType() == packet.DNSTypeEDNS {
			continue
		}
		out = append(out, recordOf(zone.TextOf(r, origin)))
	}
	return out
}

// recordTexts validates records and returns them in canonical form.
func recordTexts(origin string, records []recordBody) ([]zone.RecordText, error) {
	out := make([]zone.RecordText, 0, len(records))
	for _, rec := range records {
		name := strings.TrimSpace(rec.Name)
		if name == "" {
			name = "@"
		}
		if strings.ContainsAny(name, " \t\";") {
			return nil, badRequest("invalid name %q", rec.Name)
		}
		typ, err := zone.ParseType(rec.Type)
		if err != nil {
			return nil, badRequest("%v", err)
		}
		ttl := rec.TTL
		if ttl == 0 {
			ttl = 300
		}
		data := strings.TrimSpace(rec.Data)
		if data == "" || strings.ContainsAny(data, "\n\r;") {
			return nil, badRequest("invalid data %q", rec.Data)
		}
		line := zone.RecordText{Name: name, TTL: ttl, Type: zone.TypeString(typ), Data: data}
		rt, err := zone.ParseRecordText(displayOrigin(origin), line.String())
		if err != nil {
			return nil, badRequest("%s %s %s: %v", name, line.Type, data, err)
		}
		out = append(out, rt)
	}
	return out, nil
}

func lines(records []zone.RecordText) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.String()
	}
	return out
}

func normalizeKind(kind string) (string, error) {
	switch kind {
	case "":
		return "static", nil
	case "static", "transparent":
		return kind, nil
	default:
		return "", badRequest("kind %q invalid (want static or transparent)", kind)
	}
}

func (h *Handler) createZone(r *http.Request) (any, error) {
	var req zoneWrite
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	origin := zone.CanonicalName(req.Origin)
	if origin == "" {
		return nil, badRequest("origin required")
	}
	kind, err := normalizeKind(req.Kind)
	if err != nil {
		return nil, err
	}
	records, err := recordTexts(origin, req.Records)
	if err != nil {
		return nil, err
	}
	err = h.mgr.Update(r.Context(), func(d *config.Data) error {
		if findDomain(d, origin) >= 0 {
			return &conflictError{"zone " + origin + " already exists"}
		}
		d.Domains = append(d.Domains, config.DomainSpec{Domain: origin, Kind: kind, Records: lines(records)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	r.SetPathValue("zone", origin)
	return h.getZone(r)
}

// updateZone runs fn on the editable zone named in the request path.
func (h *Handler) updateZone(r *http.Request, fn func(*config.DomainSpec) error) (any, error) {
	origin := originFromID(r.PathValue("zone"))
	err := h.mgr.Update(r.Context(), func(d *config.Data) error {
		i := findDomain(d, origin)
		if i < 0 {
			return &NotFoundError{"zone " + displayOrigin(origin)}
		}
		dom := &d.Domains[i]
		if dom.ZoneFile != "" || dom.HostsFile != "" {
			return &conflictError{"zone " + displayOrigin(origin) + " is loaded from a file; edit the file instead"}
		}
		return fn(dom)
	})
	if err != nil {
		return nil, err
	}
	return h.getZone(r)
}

func (h *Handler) putZone(r *http.Request) (any, error) {
	var req zoneWrite
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	origin := originFromID(r.PathValue("zone"))
	records, err := recordTexts(origin, req.Records)
	if err != nil {
		return nil, err
	}
	return h.updateZone(r, func(dom *config.DomainSpec) error {
		if req.Kind != "" {
			kind, err := normalizeKind(req.Kind)
			if err != nil {
				return err
			}
			dom.Kind = kind
		}
		dom.Records = lines(records)
		return nil
	})
}

func (h *Handler) addRecord(r *http.Request) (any, error) {
	var rec recordBody
	if err := decode(r, &rec); err != nil {
		return nil, err
	}
	records, err := recordTexts(originFromID(r.PathValue("zone")), []recordBody{rec})
	if err != nil {
		return nil, err
	}
	return h.updateZone(r, func(dom *config.DomainSpec) error {
		dom.Records = append(dom.Records, records[0].String())
		return nil
	})
}

func (h *Handler) putRecord(r *http.Request) (any, error) {
	var rec recordBody
	if err := decode(r, &rec); err != nil {
		return nil, err
	}
	origin := originFromID(r.PathValue("zone"))
	records, err := recordTexts(origin, []recordBody{rec})
	if err != nil {
		return nil, err
	}
	return h.updateZone(r, func(dom *config.DomainSpec) error {
		i, err := findRecord(origin, dom, r.PathValue("id"))
		if err != nil {
			return err
		}
		dom.Records[i] = records[0].String()
		return nil
	})
}

func (h *Handler) deleteRecord(r *http.Request) (any, error) {
	origin := originFromID(r.PathValue("zone"))
	return h.updateZone(r, func(dom *config.DomainSpec) error {
		i, err := findRecord(origin, dom, r.PathValue("id"))
		if err != nil {
			return err
		}
		dom.Records = append(dom.Records[:i], dom.Records[i+1:]...)
		return nil
	})
}

// findRecord locates the stored line whose canonical form has id.
func findRecord(origin string, dom *config.DomainSpec, id string) (int, error) {
	for i, line := range dom.Records {
		if rt, err := zone.ParseRecordText(displayOrigin(origin), line); err == nil && rt.ID() == id {
			return i, nil
		}
	}
	return -1, &NotFoundError{"record " + id}
}

func (h *Handler) deleteZone(r *http.Request) (any, error) {
	origin := originFromID(r.PathValue("zone"))
	return nil, h.mgr.Update(r.Context(), func(d *config.Data) error {
		i := findDomain(d, origin)
		if i < 0 {
			return &NotFoundError{"zone " + displayOrigin(origin)}
		}
		d.Domains = append(d.Domains[:i], d.Domains[i+1:]...)
		return nil
	})
}

// ---- filters ----

type filtersBody struct {
	BlockMode string     `json:"block_mode"`
	Rules     []string   `json:"rules"`
	Lists     []listBody `json:"lists"`
}

type listBody struct {
	Name    string      `json:"name"`
	Kind    string      `json:"kind"`
	URL     string      `json:"url,omitempty"`
	File    string      `json:"file,omitempty"`
	Enabled bool        `json:"enabled"`
	Refresh string      `json:"refresh,omitempty"`
	Status  *listStatus `json:"status,omitempty"`
}

type listStatus struct {
	Rules     int        `json:"rules"`
	Skipped   int        `json:"skipped"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type listWrite struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	URL     string `json:"url"`
	File    string `json:"file"`
	Enabled *bool  `json:"enabled"`
	Refresh string `json:"refresh"`
}

var errNoFilters = &conflictError{"filtering is only available in forwarding mode"}

func (h *Handler) requireFilters() error {
	if h.mgr.Service().Filter == nil {
		return errNoFilters
	}
	return nil
}

func (h *Handler) getFilters(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	d := h.mgr.Data()
	status := map[string]filter.SourceStatus{}
	for _, s := range h.mgr.Service().Subscriptions.Status() {
		status[s.Name] = s
	}
	out := filtersBody{BlockMode: d.Filters.BlockMode, Rules: d.Filters.Rules, Lists: []listBody{}}
	if out.Rules == nil {
		out.Rules = []string{}
	}
	for _, l := range d.Filters.Lists {
		b := listBody{Name: l.Name, Kind: l.Kind, URL: l.URL, File: l.File, Enabled: l.IsEnabled()}
		if l.Refresh != 0 {
			b.Refresh = l.Refresh.Duration().String()
		}
		if s, ok := status[l.Name]; ok {
			st := &listStatus{Rules: s.Rules, Skipped: s.Skipped, Error: s.Error}
			if !s.UpdatedAt.IsZero() {
				t := s.UpdatedAt
				st.UpdatedAt = &t
			}
			b.Status = st
		}
		out.Lists = append(out.Lists, b)
	}
	return out, nil
}

type ruleError struct {
	Line  int    `json:"line"`
	Rule  string `json:"rule"`
	Error string `json:"error"`
}

type rulesBody struct {
	Rules []string `json:"rules"`
}

// rulesError reports every invalid rule at once, so a panel can mark lines.
type rulesError struct {
	Errors []ruleError `json:"errors"`
}

func (e *rulesError) Details() any { return e.Errors }

func (e *rulesError) Error() string {
	return fmt.Sprintf("%d invalid rule(s); first: line %d: %s", len(e.Errors), e.Errors[0].Line, e.Errors[0].Error)
}

func (h *Handler) putRules(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	var req rulesBody
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	var rules []string
	var errs []ruleError
	for i, line := range req.Rules {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := filter.ParseRule(line); err != nil {
			errs = append(errs, ruleError{Line: i + 1, Rule: line, Error: err.Error()})
			continue
		}
		rules = append(rules, line)
	}
	if len(errs) > 0 {
		return nil, &rulesError{errs}
	}
	err := h.mgr.Update(r.Context(), func(d *config.Data) error {
		d.Filters.Rules = rules
		return nil
	})
	if err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []string{}
	}
	return rulesBody{Rules: rules}, nil
}

func (h *Handler) putBlockMode(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	var req struct {
		BlockMode string `json:"block_mode"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if _, err := engine.ParseBlockMode(req.BlockMode); err != nil || req.BlockMode == "" {
		return nil, badRequest("block_mode %q invalid (want zero_ip, nxdomain, or refused)", req.BlockMode)
	}
	return req, h.mgr.Update(r.Context(), func(d *config.Data) error {
		d.Filters.BlockMode = req.BlockMode
		return nil
	})
}

func (h *Handler) checkFilter(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		return nil, badRequest("name required")
	}
	m := h.mgr.Service().Filter.Match(name)
	return filterMatch{Action: m.Action.String(), List: m.List, Rule: m.Rule}, nil
}

func (l listWrite) spec(name string) (config.ListSpec, error) {
	spec := config.ListSpec{Name: name, Kind: l.Kind, URL: strings.TrimSpace(l.URL), File: strings.TrimSpace(l.File), Enabled: l.Enabled}
	if spec.Kind == "" {
		spec.Kind = "block"
	}
	if l.Refresh != "" {
		d, err := time.ParseDuration(l.Refresh)
		if err != nil {
			return spec, badRequest("refresh %q: %v", l.Refresh, err)
		}
		spec.Refresh = config.Duration(d)
	}
	return spec, nil
}

func findList(d *config.Data, name string) int {
	for i, l := range d.Filters.Lists {
		if l.Name == name {
			return i
		}
	}
	return -1
}

func (h *Handler) createList(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	var req listWrite
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	spec, err := req.spec(strings.TrimSpace(req.Name))
	if err != nil {
		return nil, err
	}
	err = h.mgr.Update(r.Context(), func(d *config.Data) error {
		if findList(d, spec.Name) >= 0 {
			return &conflictError{"list " + spec.Name + " already exists"}
		}
		d.Filters.Lists = append(d.Filters.Lists, spec)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h.getFilters(r)
}

func (h *Handler) putList(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	name := r.PathValue("name")
	var req listWrite
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Name != "" && req.Name != name {
		return nil, badRequest("renaming lists is not supported")
	}
	spec, err := req.spec(name)
	if err != nil {
		return nil, err
	}
	err = h.mgr.Update(r.Context(), func(d *config.Data) error {
		i := findList(d, name)
		if i < 0 {
			return &NotFoundError{"list " + name}
		}
		d.Filters.Lists[i] = spec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h.getFilters(r)
}

func (h *Handler) deleteList(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	name := r.PathValue("name")
	return nil, h.mgr.Update(r.Context(), func(d *config.Data) error {
		i := findList(d, name)
		if i < 0 {
			return &NotFoundError{"list " + name}
		}
		d.Filters.Lists = append(d.Filters.Lists[:i], d.Filters.Lists[i+1:]...)
		return nil
	})
}

func (h *Handler) refreshList(r *http.Request) (any, error) {
	if err := h.requireFilters(); err != nil {
		return nil, err
	}
	name := r.PathValue("name")
	if d := h.mgr.Data(); findList(&d, name) < 0 {
		return nil, &NotFoundError{"list " + name}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.mgr.Service().Subscriptions.Refresh(ctx, name); err != nil {
		return nil, &conflictError{"refresh " + name + ": " + err.Error()}
	}
	return h.getFilters(r)
}

// ---- access ----

// accessBody mirrors config.AccessSpec. Allow null means the mode's default
// (private networks for forwarding); [] means only identified clients.
type accessBody struct {
	Allow      *[]string    `json:"allow"`
	Deny       []string     `json:"deny"`
	DenyAction string       `json:"deny_action"`
	Clients    []clientBody `json:"clients"`
}

type clientBody struct {
	Name     string   `json:"name"`
	IDs      []string `json:"ids"`
	Networks []string `json:"networks"`
}

func (h *Handler) getAccess(r *http.Request) (any, error) {
	spec := h.mgr.Data().Access
	out := accessBody{Allow: spec.Allow, Deny: nonNil(spec.Deny), DenyAction: spec.DenyAction, Clients: []clientBody{}}
	if out.DenyAction == "" {
		out.DenyAction = "refuse"
	}
	for _, c := range spec.Clients {
		out.Clients = append(out.Clients, clientBody{Name: c.Name, IDs: nonNil(c.IDs), Networks: nonNil(c.Networks)})
	}
	return out, nil
}

func (h *Handler) putAccess(r *http.Request) (any, error) {
	var req accessBody
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	spec := config.AccessSpec{Allow: req.Allow, Deny: req.Deny, DenyAction: req.DenyAction}
	for _, c := range req.Clients {
		spec.Clients = append(spec.Clients, config.ClientSpec{Name: strings.TrimSpace(c.Name), IDs: c.IDs, Networks: c.Networks})
	}
	err := h.mgr.Update(r.Context(), func(d *config.Data) error {
		d.Access = spec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h.getAccess(r)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
