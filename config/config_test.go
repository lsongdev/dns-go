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
		"domain no data":      listens + upstream + "domains: [{domain: a.com}]",
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
