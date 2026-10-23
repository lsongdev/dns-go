package engine

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/lsongdev/dns-go/access"
	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/proxy"
	"github.com/lsongdev/dns-go/zone"
)

// Service owns the components built from the process settings in a
// config.Config. Runtime data (zones, filters, access) arrives separately
// through Apply, so the service does not know or care where it is stored.
type Service struct {
	Engine        *Engine
	Zones         *zone.Store
	Filter        *filter.Filter        // nil in authoritative mode
	Subscriptions *filter.Subscriptions // nil in authoritative mode
	Cache         *cache.Cache          // nil when caching is disabled
	Access        *access.Controller

	mode     string
	upstream *proxy.Pool
}

// Hooks receives events from a Service. All fields are optional and must
// not block.
type Hooks struct {
	OnQuery      func(QueryEvent)
	OnListUpdate func(filter.SourceStatus)
}

// NewService builds and starts the components described by cfg's process
// settings, with no zones, rules, or clients yet; call Apply to load data.
func NewService(cfg *config.Config, hooks Hooks) (*Service, error) {
	s := &Service{
		mode:  cfg.Mode,
		Zones: zone.NewStore(zone.StoreOptions{Authoritative: cfg.Mode == config.ModeAuthoritative}),
	}
	rules, err := AccessRules(cfg.Mode, config.AccessSpec{})
	if err != nil {
		return nil, err
	}
	if s.Access, err = access.New(rules); err != nil {
		return nil, err
	}
	opts := Options{Zones: s.Zones, Access: s.Access, OnQuery: hooks.OnQuery}
	if cfg.Mode == config.ModeForwarding {
		pool, err := proxy.NewFromSpecs(upstreamSpecs(cfg.Upstreams))
		if err != nil {
			return nil, err
		}
		s.upstream = pool
		s.Filter = filter.New()
		s.Subscriptions = filter.NewSubscriptions(s.Filter, filter.SubscriptionOptions{
			CacheDir: filepath.Join(cfg.DataDir, "filters"),
			OnUpdate: hooks.OnListUpdate,
		})
		if cfg.Cache.Enabled {
			s.Cache = cache.New(cache.Options{
				MinTTL:      cfg.Cache.MinTTL.Duration(),
				MaxTTL:      cfg.Cache.MaxTTL.Duration(),
				NegativeTTL: cfg.Cache.NegativeTTL.Duration(),
				MaxEntries:  cfg.Cache.MaxEntries,
			})
		}
		opts.Upstream, opts.Filter, opts.Cache = pool, s.Filter, s.Cache
	}
	s.Engine = New(opts)
	return s, nil
}

// Mode reports the service's mode.
func (s *Service) Mode() string { return s.mode }

// Apply makes d the running data: zones, access rules, filter lists, and
// the block mode. Everything is validated before anything is replaced, so
// an error leaves the previous data in effect.
func (s *Service) Apply(d config.Data) error {
	d.ApplyDefaults()
	if err := d.Validate(s.mode); err != nil {
		return err
	}
	rules, err := AccessRules(s.mode, d.Access)
	if err != nil {
		return err
	}
	if _, err := access.New(rules); err != nil {
		return err
	}
	zones, err := ZonesFromConfig(d.Domains)
	if err != nil {
		return err
	}
	if err := s.Zones.Replace(zones); err != nil {
		return err
	}
	if err := s.Access.Set(rules); err != nil {
		return err
	}
	if s.Filter == nil {
		return nil
	}
	mode, err := ParseBlockMode(d.Filters.BlockMode)
	if err != nil {
		return err
	}
	s.Engine.SetBlockMode(mode)
	s.Filter.SetList(filter.List{Name: config.RulesListName, Kind: filter.BlockList, Rules: d.Filters.Rules})
	var sources []filter.Source
	for _, l := range d.Filters.Lists {
		if l.IsEnabled() {
			sources = append(sources, filter.Source{
				Name:    l.Name,
				Kind:    filter.Kind(l.Kind),
				URL:     l.URL,
				File:    l.File,
				Refresh: l.Refresh.Duration(),
			})
		}
	}
	return s.Subscriptions.Set(sources)
}

// Close stops background work and releases upstream connections.
func (s *Service) Close() error {
	if s.Subscriptions != nil {
		s.Subscriptions.Close()
	}
	if s.upstream != nil {
		return s.upstream.Close()
	}
	return nil
}

// ZonesFromConfig reads every configured domain into a zone.
func ZonesFromConfig(domains []config.DomainSpec) ([]*zone.Zone, error) {
	zones := make([]*zone.Zone, 0, len(domains))
	for i, d := range domains {
		var z *zone.Zone
		var err error
		switch {
		case d.HostsFile != "":
			z, err = zone.ParseHostsFile(d.HostsFile)
			if err == nil && d.Domain != "" {
				z.Origin = d.Domain
			}
		case d.ZoneFile != "":
			z, err = zone.ParseFile(d.ZoneFile)
			if err == nil {
				z.Origin = d.Domain
			}
		default:
			z, err = zone.ParseString(d.Domain, strings.Join(d.Records, "\n"))
		}
		if err != nil {
			return nil, fmt.Errorf("domains[%d] (%s): %w", i, d.Domain, err)
		}
		z.Kind = zone.Kind(d.Kind)
		zones = append(zones, z)
	}
	return zones, nil
}

// AccessRules converts an access spec, applying the mode's default Allow
// when it is omitted: private networks for a forwarding resolver (never an
// open resolver by accident), everyone for an authoritative server.
func AccessRules(mode string, spec config.AccessSpec) (access.Rules, error) {
	rules := access.Rules{DenyAction: access.Action(spec.DenyAction)}
	var err error
	switch {
	case spec.Allow != nil:
		if rules.Allow, err = access.ParseNetworks(*spec.Allow); err != nil {
			return rules, err
		}
		if rules.Allow == nil {
			rules.Allow = []netip.Prefix{}
		}
	case mode == config.ModeForwarding:
		rules.Allow = append([]netip.Prefix{}, access.Private...)
	}
	if rules.Deny, err = access.ParseNetworks(spec.Deny); err != nil {
		return rules, err
	}
	for _, c := range spec.Clients {
		networks, err := access.ParseNetworks(c.Networks)
		if err != nil {
			return rules, fmt.Errorf("client %q: %w", c.Name, err)
		}
		rules.Clients = append(rules.Clients, access.Client{Name: c.Name, IDs: c.IDs, Networks: networks})
	}
	return rules, nil
}

// ParseBlockMode maps the config spelling to a BlockMode.
func ParseBlockMode(s string) (BlockMode, error) {
	switch s {
	case "", "zero_ip":
		return BlockZeroIP, nil
	case "nxdomain":
		return BlockNXDomain, nil
	case "refused":
		return BlockRefused, nil
	default:
		return 0, fmt.Errorf("engine: unknown block mode %q", s)
	}
}

func upstreamSpecs(specs []config.UpstreamSpec) []proxy.Spec {
	out := make([]proxy.Spec, len(specs))
	for i, u := range specs {
		out[i] = proxy.Spec{Type: u.Type, Addr: u.Addr, Method: u.Method, Timeout: u.Timeout.Duration()}
	}
	return out
}
