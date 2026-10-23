// Package config defines the YAML file format for cmd/dns-go. It only
// parses and validates structure; package engine turns it into components.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string (e.g. \"5s\", \"24h\"): %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

const (
	ModeAuthoritative = "authoritative"
	ModeForwarding    = "forwarding"
)

type Config struct {
	// Mode is "authoritative" (serve zones only, REFUSED elsewhere, no
	// recursion) or "forwarding" (resolve through upstreams, with local
	// zones, filtering, and caching). Default: forwarding.
	Mode      string         `yaml:"mode"`
	Listens   []ListenSpec   `yaml:"listens"`
	Domains   []DomainSpec   `yaml:"domains"`
	Upstreams []UpstreamSpec `yaml:"upstreams"`
	Cache     CacheSpec      `yaml:"cache"`
	Filters   FiltersSpec    `yaml:"filters"`
	Access    AccessSpec     `yaml:"access"`
}

type ListenSpec struct {
	Type     string `yaml:"type"` // udp | tcp | dot | doh
	Addr     string `yaml:"addr"`
	CertFile string `yaml:"cert_file"` // required for dot; doh without it serves plain HTTP
	KeyFile  string `yaml:"key_file"`
	// Hostname (dot, doh with TLS) enables client IDs from SNI: clients
	// connecting to "{id}.<hostname>" are identified as {id}.
	Hostname string `yaml:"hostname"`
	// TrustedProxies (doh) are reverse proxies whose X-Forwarded-For is
	// believed. Entries are CIDRs, addresses, or "private".
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// AccessSpec controls who may query. Network entries are CIDRs, bare
// addresses, or the keyword "private" (loopback, RFC 1918, CGNAT,
// link-local, ULA).
type AccessSpec struct {
	// Allow lists networks that may query without a client ID. Omitted:
	// "private" in forwarding mode, everyone in authoritative mode.
	Allow      []string     `yaml:"allow"`
	Deny       []string     `yaml:"deny"`
	DenyAction string       `yaml:"deny_action"` // refuse (default) | drop
	Clients    []ClientSpec `yaml:"clients"`
}

// ClientSpec is a known client, identified by ID or by network.
type ClientSpec struct {
	Name     string   `yaml:"name"`
	IDs      []string `yaml:"ids"`
	Networks []string `yaml:"networks"`
}

// DomainSpec is one zone. Exactly one of Records, ZoneFile, or HostsFile
// supplies its data.
type DomainSpec struct {
	Domain string `yaml:"domain"` // zone origin; hosts files default to the root
	// Kind is "static" (the zone owns its namespace; default) or
	// "transparent" (answer only names with data, let others resolve
	// normally). Hosts files are always transparent.
	Kind      string   `yaml:"kind"`
	Records   []string `yaml:"records"`
	ZoneFile  string   `yaml:"zone_file"`
	HostsFile string   `yaml:"hosts_file"`
}

type UpstreamSpec struct {
	Type    string   `yaml:"type"` // udp | tcp | dot | doh
	Addr    string   `yaml:"addr"`
	Method  string   `yaml:"method"` // doh: get | post
	Timeout Duration `yaml:"timeout"`
}

type CacheSpec struct {
	Enabled     bool     `yaml:"enabled"`
	MinTTL      Duration `yaml:"min_ttl"`
	MaxTTL      Duration `yaml:"max_ttl"`
	NegativeTTL Duration `yaml:"negative_ttl"`
	MaxEntries  int      `yaml:"max_entries"`
}

type FiltersSpec struct {
	// BlockMode is how blocked names are answered: "zero_ip" (A 0.0.0.0,
	// AAAA ::, other types NODATA; default), "nxdomain", or "refused".
	BlockMode string     `yaml:"block_mode"`
	CacheDir  string     `yaml:"cache_dir"` // keeps downloaded lists across restarts
	Lists     []ListSpec `yaml:"lists"`
	Rules     []string   `yaml:"rules"` // inline rules, installed as list "rules"
}

type ListSpec struct {
	Name    string   `yaml:"name"`
	Kind    string   `yaml:"kind"` // block (default) | allow
	URL     string   `yaml:"url"`
	File    string   `yaml:"file"`
	Enabled *bool    `yaml:"enabled"` // default true
	Refresh Duration `yaml:"refresh"`
}

func (l ListSpec) IsEnabled() bool { return l.Enabled == nil || *l.Enabled }

// RulesListName is the filter list that holds FiltersSpec.Rules.
const RulesListName = "rules"

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeForwarding
	}
	if c.Cache.MaxTTL == 0 {
		c.Cache.MaxTTL = Duration(24 * time.Hour)
	}
	if c.Cache.NegativeTTL == 0 {
		c.Cache.NegativeTTL = Duration(5 * time.Minute)
	}
	if c.Cache.MaxEntries == 0 {
		c.Cache.MaxEntries = 10000
	}
	for i := range c.Domains {
		d := &c.Domains[i]
		if d.Kind == "" {
			d.Kind = "static"
			if d.HostsFile != "" {
				d.Kind = "transparent"
			}
		}
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Type == "doh" && u.Method == "" {
			u.Method = "post"
		}
		if u.Timeout == 0 {
			u.Timeout = Duration(5 * time.Second)
		}
	}
	if c.Filters.BlockMode == "" {
		c.Filters.BlockMode = "zero_ip"
	}
	for i := range c.Filters.Lists {
		if c.Filters.Lists[i].Kind == "" {
			c.Filters.Lists[i].Kind = "block"
		}
	}
}

func (c *Config) Validate() error {
	if c.Mode != ModeAuthoritative && c.Mode != ModeForwarding {
		return fmt.Errorf("mode %q invalid (want %s or %s)", c.Mode, ModeAuthoritative, ModeForwarding)
	}
	if len(c.Listens) == 0 {
		return fmt.Errorf("at least one listen required")
	}
	for i, l := range c.Listens {
		if l.Addr == "" {
			return fmt.Errorf("listens[%d]: addr required", i)
		}
		switch l.Type {
		case "udp", "tcp", "dot", "doh":
		default:
			return fmt.Errorf("listens[%d]: unknown type %q (want udp/tcp/dot/doh)", i, l.Type)
		}
		if (l.CertFile == "") != (l.KeyFile == "") {
			return fmt.Errorf("listens[%d]: cert_file and key_file must be set together", i)
		}
		if l.Type == "dot" && l.CertFile == "" {
			return fmt.Errorf("listens[%d]: dot requires cert_file and key_file", i)
		}
	}
	for i, d := range c.Domains {
		sources := 0
		for _, set := range []bool{len(d.Records) > 0, d.ZoneFile != "", d.HostsFile != ""} {
			if set {
				sources++
			}
		}
		if sources != 1 {
			return fmt.Errorf("domains[%d]: exactly one of records, zone_file, hosts_file required", i)
		}
		if d.HostsFile == "" && d.Domain == "" {
			return fmt.Errorf("domains[%d]: domain required", i)
		}
		switch d.Kind {
		case "static", "transparent":
		default:
			return fmt.Errorf("domains[%d]: kind %q invalid (want static or transparent)", i, d.Kind)
		}
		if d.HostsFile != "" && d.Kind != "transparent" {
			return fmt.Errorf("domains[%d]: hosts_file domains are always transparent", i)
		}
	}
	for i, u := range c.Upstreams {
		switch u.Type {
		case "udp", "tcp", "dot", "doh":
		default:
			return fmt.Errorf("upstreams[%d]: unknown type %q (want udp/tcp/dot/doh)", i, u.Type)
		}
		if u.Addr == "" {
			return fmt.Errorf("upstreams[%d]: addr required", i)
		}
		if u.Type == "doh" && u.Method != "get" && u.Method != "post" {
			return fmt.Errorf("upstreams[%d]: method %q invalid (want get or post)", i, u.Method)
		}
	}
	switch c.Access.DenyAction {
	case "", "refuse", "drop":
	default:
		return fmt.Errorf("access.deny_action %q invalid (want refuse or drop)", c.Access.DenyAction)
	}
	for i, l := range c.Listens {
		if len(l.TrustedProxies) > 0 && l.Type != "doh" {
			return fmt.Errorf("listens[%d]: trusted_proxies only applies to doh", i)
		}
		if l.Hostname != "" && l.CertFile == "" {
			return fmt.Errorf("listens[%d]: hostname needs TLS (cert_file/key_file)", i)
		}
	}
	switch c.Filters.BlockMode {
	case "zero_ip", "nxdomain", "refused":
	default:
		return fmt.Errorf("filters.block_mode %q invalid (want zero_ip, nxdomain, or refused)", c.Filters.BlockMode)
	}
	names := map[string]bool{RulesListName: true}
	for i, l := range c.Filters.Lists {
		if l.Name == "" {
			return fmt.Errorf("filters.lists[%d]: name required", i)
		}
		if names[l.Name] {
			return fmt.Errorf("filters.lists[%d]: name %q is duplicate or reserved", i, l.Name)
		}
		names[l.Name] = true
		if (l.URL == "") == (l.File == "") {
			return fmt.Errorf("filters.lists[%d]: exactly one of url or file required", i)
		}
		if l.Kind != "block" && l.Kind != "allow" {
			return fmt.Errorf("filters.lists[%d]: kind %q invalid (want block or allow)", i, l.Kind)
		}
	}

	switch c.Mode {
	case ModeAuthoritative:
		if len(c.Domains) == 0 {
			return fmt.Errorf("authoritative mode requires at least one domain")
		}
		for i, d := range c.Domains {
			if d.Kind != "static" {
				return fmt.Errorf("domains[%d]: authoritative mode serves only static zones", i)
			}
		}
		if c.Cache.Enabled || len(c.Upstreams) > 0 || len(c.Filters.Rules) > 0 || len(c.Filters.Lists) > 0 {
			return fmt.Errorf("authoritative mode cannot configure cache, upstreams, or filters")
		}
	case ModeForwarding:
		if len(c.Upstreams) == 0 {
			return fmt.Errorf("forwarding mode requires at least one upstream")
		}
	}
	return nil
}
