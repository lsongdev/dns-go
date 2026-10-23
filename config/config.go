// Package config defines the YAML file format for cmd/dns-go. It only
// parses and validates structure; package engine turns it into components.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Config is the whole file: process settings (fixed for the life of the
// process) plus the inline Data, which is what the management API edits.
// Where Data is kept at runtime is chosen by Storage; the rest of the
// program only ever sees a Data value.
type Config struct {
	// Mode is "authoritative" (serve zones only, REFUSED elsewhere, no
	// recursion) or "forwarding" (resolve through upstreams, with local
	// zones, filtering, and caching). Default: forwarding.
	Mode      string         `yaml:"mode"`
	Listens   []ListenSpec   `yaml:"listens"`
	Upstreams []UpstreamSpec `yaml:"upstreams,omitempty"`
	Cache     CacheSpec      `yaml:"cache,omitempty"`
	API       APISpec        `yaml:"api,omitempty"`
	// DataDir holds downloaded filter lists and, by default, the database.
	// Default: "data".
	DataDir string      `yaml:"data_dir,omitempty"`
	Storage StorageSpec `yaml:"storage,omitempty"`

	Data `yaml:",inline"`
}

// Data is the runtime-managed configuration: zones, filters, and access.
type Data struct {
	Domains []DomainSpec `yaml:"domains,omitempty"`
	Filters FiltersSpec  `yaml:"filters,omitempty"`
	Access  AccessSpec   `yaml:"access,omitempty"`
}

const (
	// StorageConfig keeps Data in the config file itself (default).
	StorageConfig = "config"
	// StorageSQLite keeps Data in a SQLite database. A new database is
	// seeded once from the config file's data sections.
	StorageSQLite = "sqlite"
)

// StorageSpec selects where Data lives.
type StorageSpec struct {
	Type string `yaml:"type,omitempty"` // config (default) | sqlite
	Path string `yaml:"path,omitempty"` // sqlite: database file; default <data_dir>/dns-go.db
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

// Clone returns a deep copy of d.
func (d Data) Clone() Data {
	raw, err := yaml.Marshal(d)
	if err != nil {
		panic(err) // Data contains only marshalable fields
	}
	var out Data
	if err := yaml.Unmarshal(raw, &out); err != nil {
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
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.Storage.Type == "" {
		c.Storage.Type = StorageConfig
	}
	if c.Storage.Type == StorageSQLite && c.Storage.Path == "" {
		c.Storage.Path = filepath.Join(c.DataDir, "dns-go.db")
	}
	c.Data.ApplyDefaults()
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Type == "doh" && u.Method == "" {
			u.Method = "post"
		}
		if u.Timeout == 0 {
			u.Timeout = Duration(5 * time.Second)
		}
	}
}

// ApplyDefaults fills omitted fields of d.
func (d *Data) ApplyDefaults() {
	for i := range d.Domains {
		dom := &d.Domains[i]
		if dom.Kind == "" {
			dom.Kind = "static"
			if dom.HostsFile != "" {
				dom.Kind = "transparent"
			}
		}
	}
	if d.Filters.BlockMode == "" {
		d.Filters.BlockMode = "zero_ip"
	}
	for i := range d.Filters.Lists {
		if d.Filters.Lists[i].Kind == "" {
			d.Filters.Lists[i].Kind = "block"
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
	for i, l := range c.Listens {
		if len(l.TrustedProxies) > 0 && l.Type != "doh" {
			return fmt.Errorf("listens[%d]: trusted_proxies only applies to doh", i)
		}
		if l.Hostname != "" && l.CertFile == "" {
			return fmt.Errorf("listens[%d]: hostname needs TLS (cert_file/key_file)", i)
		}
	}
	switch c.Storage.Type {
	case StorageConfig, StorageSQLite:
	default:
		return fmt.Errorf("storage.type %q invalid (want config or sqlite)", c.Storage.Type)
	}
	switch c.Mode {
	case ModeAuthoritative:
		if c.Cache.Enabled || len(c.Upstreams) > 0 {
			return fmt.Errorf("authoritative mode cannot configure cache or upstreams")
		}
	case ModeForwarding:
		if len(c.Upstreams) == 0 {
			return fmt.Errorf("forwarding mode requires at least one upstream")
		}
	}
	return c.Data.Validate(c.Mode)
}

// Validate checks d for the given mode.
func (d *Data) Validate(mode string) error {
	for i, dom := range d.Domains {
		sources := 0
		for _, set := range []bool{len(dom.Records) > 0, dom.ZoneFile != "", dom.HostsFile != ""} {
			if set {
				sources++
			}
		}
		if sources > 1 {
			return fmt.Errorf("domains[%d]: only one of records, zone_file, hosts_file allowed", i)
		}
		if dom.HostsFile == "" && dom.Domain == "" {
			return fmt.Errorf("domains[%d]: domain required", i)
		}
		switch dom.Kind {
		case "static", "transparent":
		default:
			return fmt.Errorf("domains[%d]: kind %q invalid (want static or transparent)", i, dom.Kind)
		}
		if dom.HostsFile != "" && dom.Kind != "transparent" {
			return fmt.Errorf("domains[%d]: hosts_file domains are always transparent", i)
		}
	}
	switch d.Access.DenyAction {
	case "", "refuse", "drop":
	default:
		return fmt.Errorf("access.deny_action %q invalid (want refuse or drop)", d.Access.DenyAction)
	}
	switch d.Filters.BlockMode {
	case "zero_ip", "nxdomain", "refused":
	default:
		return fmt.Errorf("filters.block_mode %q invalid (want zero_ip, nxdomain, or refused)", d.Filters.BlockMode)
	}
	names := map[string]bool{RulesListName: true}
	for i, l := range d.Filters.Lists {
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

	if mode == ModeAuthoritative {
		for i, dom := range d.Domains {
			if dom.Kind != "static" {
				return fmt.Errorf("domains[%d]: authoritative mode serves only static zones", i)
			}
		}
		if len(d.Filters.Rules) > 0 || len(d.Filters.Lists) > 0 {
			return fmt.Errorf("authoritative mode cannot configure filters")
		}
	}
	return nil
}
