package engine

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/lsongdev/dns-go/access"
	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/proxy"
	"github.com/lsongdev/dns-go/zone"
)

// Service owns the components built from a config file. A management API
// operates on these fields directly; Apply re-applies a (reloaded) config.
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

// NewService builds and starts every component described by cfg.
func NewService(cfg *config.Config, hooks Hooks) (*Service, error) {
	s := &Service{
		mode:  cfg.Mode,
		Zones: zone.NewStore(zone.StoreOptions{Authoritative: cfg.Mode == config.ModeAuthoritative}),
	}
	rules, err := AccessRulesFromConfig(cfg)
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
			CacheDir: cfg.Filters.CacheDir,
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
	if err := s.Apply(cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Apply loads zones, access rules, filter lists, and the block mode from
// cfg. Listeners, mode, upstreams, and cache sizing need a restart; a
// changed mode is rejected. Zones and access rules are validated before
// either is replaced.
func (s *Service) Apply(cfg *config.Config) error {
	if cfg.Mode != s.mode {
		return fmt.Errorf("engine: mode change (%s -> %s) requires a restart", s.mode, cfg.Mode)
	}
	rules, err := AccessRulesFromConfig(cfg)
	if err != nil {
		return err
	}
	if _, err := access.New(rules); err != nil {
		return err
	}
	zones, err := ZonesFromConfig(cfg.Domains)
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
	mode, err := ParseBlockMode(cfg.Filters.BlockMode)
	if err != nil {
		return err
	}
	s.Engine.SetBlockMode(mode)
	s.Filter.SetList(filter.List{Name: config.RulesListName, Kind: filter.BlockList, Rules: cfg.Filters.Rules})
	var sources []filter.Source
	for _, l := range cfg.Filters.Lists {
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

// AccessRulesFromConfig converts the access section, applying the mode's
// default Allow when it is omitted: private networks for a forwarding
// resolver (never an open resolver by accident), everyone for an
// authoritative server.
func AccessRulesFromConfig(cfg *config.Config) (access.Rules, error) {
	spec := cfg.Access
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
	case cfg.Mode == config.ModeForwarding:
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
