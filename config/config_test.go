package config

import (
	"strings"
	"testing"
	"time"
)

const listens = `
listens:
  - type: udp
    addr: ":5353"
`

func TestParseMinimalAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(listens + `
upstreams:
  - type: udp
    addr: "1.1.1.1:53"
  - type: doh
    addr: "https://dns.example/dns-query"
domains:
  - domain: home.lan
    records: ["nas IN A 192.168.1.10"]
  - hosts_file: /etc/hosts
filters:
  lists:
    - name: ads
      url: https://lists.example/ads.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeForwarding {
		t.Errorf("default mode = %q", cfg.Mode)
	}
	if cfg.Cache.MinTTL != 0 || cfg.Cache.MaxTTL.Duration() != 24*time.Hour || cfg.Cache.NegativeTTL.Duration() != 5*time.Minute {
		t.Errorf("cache defaults = %+v", cfg.Cache)
	}
	if cfg.Upstreams[0].Timeout.Duration() != 5*time.Second || cfg.Upstreams[1].Method != "post" {
		t.Errorf("upstream defaults = %+v", cfg.Upstreams)
	}
	if cfg.Domains[0].Kind != "static" || cfg.Domains[1].Kind != "transparent" {
		t.Errorf("domain kind defaults = %+v", cfg.Domains)
	}
	if cfg.Filters.BlockMode != "zero_ip" || cfg.Filters.Lists[0].Kind != "block" || !cfg.Filters.Lists[0].IsEnabled() {
		t.Errorf("filter defaults = %+v", cfg.Filters)
	}
}

func TestValidateErrors(t *testing.T) {
	upstream := "\nupstreams:\n  - {type: udp, addr: \"1.1.1.1:53\"}\n"
	cases := map[string]string{
		"no listens":          "upstreams: [{type: udp, addr: x}]",
		"bad mode":            listens + upstream + "mode: hybrid",
		"bad listen type":     "listens: [{type: quic, addr: x}]" + upstream,
		"dot without cert":    "listens: [{type: dot, addr: x}]" + upstream,
		"half a cert":         "listens: [{type: doh, addr: x, cert_file: a}]" + upstream,
		"forwarding no upstr": listens,
		"bad upstream type":   listens + "upstreams: [{type: quic, addr: x}]",
		"bad doh method":      listens + "upstreams: [{type: doh, addr: x, method: put}]",
		"domain two sources":  listens + upstream + "domains: [{domain: a.com, zone_file: x, records: [y]}]",
		"domain no name":      listens + upstream + "domains: [{records: [y]}]",
		"bad kind":            listens + upstream + "domains: [{domain: a.com, kind: weird, records: [y]}]",
		"static hosts":        listens + upstream + "domains: [{hosts_file: x, kind: static}]",
		"bad block mode":      listens + upstream + "filters: {block_mode: drop}",
		"list no source":      listens + upstream + "filters: {lists: [{name: a}]}",
		"list two sources":    listens + upstream + "filters: {lists: [{name: a, url: x, file: y}]}",
		"list reserved name":  listens + upstream + "filters: {lists: [{name: rules, url: x}]}",
		"list duplicate":      listens + upstream + "filters: {lists: [{name: a, url: x}, {name: a, url: y}]}",
		"list bad kind":       listens + upstream + "filters: {lists: [{name: a, url: x, kind: deny}]}",
		"auth no domains":     listens + "mode: authoritative",
		"auth with upstreams": listens + upstream + "mode: authoritative\ndomains: [{domain: a.com, records: [x]}]",
		"auth with cache":     listens + "mode: authoritative\ncache: {enabled: true}\ndomains: [{domain: a.com, records: [x]}]",
		"auth with filters":   listens + "mode: authoritative\nfilters: {rules: [x]}\ndomains: [{domain: a.com, records: [x]}]",
		"auth transparent":    listens + "mode: authoritative\ndomains: [{domain: a.com, kind: transparent, records: [x]}]",
		"bad duration":        listens + upstream + "cache: {max_ttl: forever}",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAuthoritativeMode(t *testing.T) {
	_, err := Parse([]byte(listens + "mode: authoritative\ndomains: [{domain: a.com, records: [x]}]"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDisabledList(t *testing.T) {
	cfg, err := Parse([]byte(listens + `
upstreams: [{type: udp, addr: "1.1.1.1:53"}]
filters:
  lists: [{name: a, url: x, enabled: false}]
`))
	if err != nil || cfg.Filters.Lists[0].IsEnabled() {
		t.Fatalf("enabled: false not honored: %v", err)
	}
}

func TestLoadRepoConfig(t *testing.T) {
	cfg, err := Load("../config.yaml")
	if err != nil {
		t.Fatalf("repo config.yaml: %v", err)
	}
	if len(cfg.Listens) == 0 || !strings.Contains(cfg.Mode, "forwarding") {
		t.Errorf("unexpected repo config: %+v", cfg)
	}
}

func TestAccessAndListenerValidation(t *testing.T) {
	upstream := "\nupstreams: [{type: udp, addr: \"1.1.1.1:53\"}]\n"
	ok := `
listens:
  - {type: doh, addr: ":443", cert_file: c, key_file: k, hostname: dns.example.com, trusted_proxies: [127.0.0.1]}
access:
  allow: [private, 203.0.113.0/24]
  deny_action: drop
  clients:
    - {name: laptop, ids: [k3y], networks: [192.168.1.20]}
` + upstream
	cfg, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Access.Clients) != 1 || cfg.Access.Clients[0].IDs[0] != "k3y" || cfg.Listens[0].Hostname != "dns.example.com" {
		t.Fatalf("parsed %+v", cfg)
	}
	for name, src := range map[string]string{
		"bad deny action":      listens + upstream + "access: {deny_action: ignore}",
		"proxies on udp":       "listens: [{type: udp, addr: x, trusted_proxies: [127.0.0.1]}]" + upstream,
		"hostname without TLS": "listens: [{type: tcp, addr: x, hostname: dns.example.com}]" + upstream,
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAPIValidation(t *testing.T) {
	up := "\nupstreams: [{type: udp, addr: \"1.1.1.1:53\"}]\n"
	if _, err := Parse([]byte(listens + up + "api: {addr: \"127.0.0.1:8080\"}")); err != nil {
		t.Fatalf("loopback API without token should be allowed: %v", err)
	}
	if _, err := Parse([]byte(listens + up + "api: {addr: \":8080\"}")); err == nil {
		t.Fatal("public API without token must be rejected")
	}
	if _, err := Parse([]byte(listens + up + "api: {addr: \":8080\", token: s3cret}")); err != nil {
		t.Fatal(err)
	}
}

func TestSaveAndClone(t *testing.T) {
	cfg, err := Parse([]byte(listens + `
upstreams: [{type: udp, addr: "1.1.1.1:53", timeout: 3s}]
domains: [{domain: home.lan}]
cache: {enabled: true, max_ttl: 1h}
`))
	if err != nil {
		t.Fatal(err)
	}
	clone := cfg.Clone()
	clone.Domains[0].Records = append(clone.Domains[0].Records, "x IN A 192.0.2.1")
	if len(cfg.Domains[0].Records) != 0 {
		t.Fatal("Clone shares slices")
	}
	path := t.TempDir() + "/c.yaml"
	if err := clone.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Access.Allow != nil {
		t.Fatal("omitted allow must stay omitted after Save")
	}
	if loaded.Domains[0].Records[0] != "x IN A 192.0.2.1" || loaded.Upstreams[0].Timeout.Duration() != 3*time.Second || loaded.Cache.MaxTTL.Duration() != time.Hour {
		t.Fatalf("round trip lost data: %+v", loaded)
	}
}
