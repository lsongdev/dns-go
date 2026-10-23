// Package config defines the YAML file format for cmd/dns-go. It only
// parses and validates structure; package engine turns it into components.
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

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
	Domains   []DomainSpec   `yaml:"domains,omitempty"`
	Upstreams []UpstreamSpec `yaml:"upstreams,omitempty"`
	Cache     CacheSpec      `yaml:"cache,omitempty"`
	Filters   FiltersSpec    `yaml:"filters,omitempty"`
	Access    AccessSpec     `yaml:"access,omitempty"`
	API       APISpec        `yaml:"api,omitempty"`
}

// APISpec enables the HTTP management API and web panel.
type APISpec struct {
	// Addr enables the API ("127.0.0.1:8080"). Empty disables it.
	Addr string `yaml:"addr"`
	// Token is the bearer token clients must send. Required unless Addr is
	// a loopback address.
	Token    string `yaml:"token,omitempty"`
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

type ListenSpec struct {
	Type     string `yaml:"type"` // udp | tcp | dot | doh
	Addr     string `yaml:"addr"`
	CertFile string `yaml:"cert_file,omitempty"` // required for dot; doh without it serves plain HTTP
	KeyFile  string `yaml:"key_file,omitempty"`
	// Hostname (dot, doh with TLS) enables client IDs from SNI: clients
	// connecting to "{id}.<hostname>" are identified as {id}.
	Hostname string `yaml:"hostname,omitempty"`
	// TrustedProxies (doh) are reverse proxies whose X-Forwarded-For is
	// believed. Entries are CIDRs, addresses, or "private".
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
}

// AccessSpec controls who may query. Network entries are CIDRs, bare
// addresses, or the keyword "private" (loopback, RFC 1918, CGNAT,
// link-local, ULA).
type AccessSpec struct {
	// Allow lists networks that may query without a client ID. Omitted:
	// "private" in forwarding mode, everyone in authoritative mode.
	Allow      *[]string    `yaml:"allow,omitempty"`
	Deny       []string     `yaml:"deny,omitempty"`
	DenyAction string       `yaml:"deny_action,omitempty"` // refuse (default) | drop
	Clients    []ClientSpec `yaml:"clients,omitempty"`
}

// ClientSpec is a known client, identified by ID or by network.
type ClientSpec struct {
	Name     string   `yaml:"name"`
	IDs      []string `yaml:"ids,omitempty"`
	Networks []string `yaml:"networks,omitempty"`
}

// DomainSpec is one zone. Exactly one of Records, ZoneFile, or HostsFile
// supplies its data.
type DomainSpec struct {
	Domain string `yaml:"domain,omitempty"` // zone origin; hosts files default to the root
	// Kind is "static" (the zone owns its namespace; default) or
	// "transparent" (answer only names with data, let others resolve
	// normally). Hosts files are always transparent.
	Kind      string   `yaml:"kind,omitempty"`
	Records   []string `yaml:"records,omitempty"`
	ZoneFile  string   `yaml:"zone_file,omitempty"`
	HostsFile string   `yaml:"hosts_file,omitempty"`
}

type UpstreamSpec struct {
	Type    string   `yaml:"type"` // udp | tcp | dot | doh
	Addr    string   `yaml:"addr"`
	Method  string   `yaml:"method,omitempty"` // doh: get | post
	Timeout Duration `yaml:"timeout,omitempty"`
}

type CacheSpec struct {
	Enabled     bool     `yaml:"enabled,omitempty"`
	MinTTL      Duration `yaml:"min_ttl,omitempty"`
	MaxTTL      Duration `yaml:"max_ttl,omitempty"`
	NegativeTTL Duration `yaml:"negative_ttl,omitempty"`
	MaxEntries  int      `yaml:"max_entries,omitempty"`
}

type FiltersSpec struct {
	// BlockMode is how blocked names are answered: "zero_ip" (A 0.0.0.0,
	// AAAA ::, other types NODATA; default), "nxdomain", or "refused".
	BlockMode string     `yaml:"block_mode,omitempty"`
	CacheDir  string     `yaml:"cache_dir,omitempty"` // keeps downloaded lists across restarts
	Lists     []ListSpec `yaml:"lists,omitempty"`
	Rules     []string   `yaml:"rules,omitempty"` // inline rules, installed as list "rules"
}

type ListSpec struct {
	Name    string   `yaml:"name"`
	Kind    string   `yaml:"kind,omitempty"` // block (default) | allow
	URL     string   `yaml:"url,omitempty"`
	File    string   `yaml:"file,omitempty"`
	Enabled *bool    `yaml:"enabled,omitempty"` // default true
	Refresh Duration `yaml:"refresh,omitempty"`
}

func (l ListSpec) IsEnabled() bool { return l.Enabled == nil || *l.Enabled }

func (a APISpec) validate() error {
	if a.Addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(a.Addr)
	if err != nil {
		return fmt.Errorf("api.addr: %w", err)
	}
	ip := net.ParseIP(host)
	if a.Token == "" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("api.token is required when api.addr is not a loopback address")
	}
	if (a.CertFile == "") != (a.KeyFile == "") {
		return fmt.Errorf("api: cert_file and key_file must be set together")
	}
	return nil
}

// RulesListName is the filter list that holds FiltersSpec.Rules.
const RulesListName = "rules"

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

// Save writes c to path atomically (temp file + rename). Comments in an
// existing file are not preserved.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clone returns a deep copy of c.
func (c *Config) Clone() *Config {
	data, err := yaml.Marshal(c)
	if err != nil {
		panic(err) // Config contains only marshalable fields
	}
	out := &Config{}
	if err := yaml.Unmarshal(data, out); err != nil {
		panic(err)
	}
	return out
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
		if sources > 1 {
			return fmt.Errorf("domains[%d]: only one of records, zone_file, hosts_file allowed", i)
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
	if err := c.API.validate(); err != nil {
		return err
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
