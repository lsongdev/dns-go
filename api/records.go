package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/zone"
)

// Record is one record with an absolute owner name, for programs that
// manage individual records through the Manager: an ACME client publishing
// DNS-01 challenges, a panel publishing the addresses of the apps it runs.
type Record struct {
	Name string // absolute owner, e.g. "_acme-challenge.example.com"
	TTL  uint32
	Type string // e.g. "A", "TXT"
	Data string // RDATA in presentation format, e.g. `"token"` for TXT
}

// ErrNoZone reports that no editable zone contains a name.
var ErrNoZone = errors.New("no editable zone contains the name")

// ZoneFor returns the origin of the most specific editable zone (records
// kept by dns-go, not loaded from a zone or hosts file) that contains name.
func (m *Manager) ZoneFor(name string) (origin string, ok bool) {
	d := m.Data()
	if i := editableZone(d, name); i >= 0 {
		return zone.CanonicalName(d.Domains[i].Domain), true
	}
	return "", false
}

// Lookup returns the records owned by name in its editable zone.
func (m *Manager) Lookup(name string) ([]Record, error) {
	d := m.Data()
	i := editableZone(d, name)
	if i < 0 {
		return nil, fmt.Errorf("%s: %w", name, ErrNoZone)
	}
	origin := originOf(d.Domains[i])
	var out []Record
	for _, line := range d.Domains[i].Records {
		r, err := zone.ParseRecordText(origin, line)
		if err != nil {
			return nil, err
		}
		if owner := absolute(r.Name, origin); owner == zone.CanonicalName(name) {
			out = append(out, Record{Name: owner, TTL: r.TTL, Type: r.Type, Data: r.Data})
		}
	}
	return out, nil
}

// AddRecord adds r to the most specific editable zone that contains its
// name. Adding a record that is already present (same name, type and data)
// succeeds without a change.
func (m *Manager) AddRecord(ctx context.Context, r Record) error {
	return m.Update(ctx, func(d *config.Data) error {
		i := editableZone(*d, r.Name)
		if i < 0 {
			return fmt.Errorf("%s: %w", r.Name, ErrNoZone)
		}
		origin := originOf(d.Domains[i])
		text, err := parseRecord(origin, r)
		if err != nil {
			return &InvalidError{err}
		}
		if indexOf(d.Domains[i].Records, origin, text) >= 0 {
			return nil
		}
		d.Domains[i].Records = append(d.Domains[i].Records, text.String())
		return nil
	})
}

// RemoveRecord removes the record with r's name, type and data (its TTL is
// ignored). Removing a record that does not exist succeeds.
func (m *Manager) RemoveRecord(ctx context.Context, r Record) error {
	if _, ok := m.ZoneFor(r.Name); !ok {
		return nil
	}
	return m.Update(ctx, func(d *config.Data) error {
		i := editableZone(*d, r.Name)
		if i < 0 {
			return nil
		}
		origin := originOf(d.Domains[i])
		text, err := parseRecord(origin, r)
		if err != nil {
			return &InvalidError{err}
		}
		if j := indexOf(d.Domains[i].Records, origin, text); j >= 0 {
			d.Domains[i].Records = slices.Delete(d.Domains[i].Records, j, j+1)
		}
		return nil
	})
}

// editableZone returns the index of the most specific editable zone in d
// containing name, or -1.
func editableZone(d config.Data, name string) int {
	name = zone.CanonicalName(name)
	best, bestLen := -1, -1
	for i, dom := range d.Domains {
		if dom.ZoneFile != "" || dom.HostsFile != "" {
			continue
		}
		origin := zone.CanonicalName(dom.Domain)
		if (origin == "" || name == origin || strings.HasSuffix(name, "."+origin)) && len(origin) > bestLen {
			best, bestLen = i, len(origin)
		}
	}
	return best
}

func originOf(dom config.DomainSpec) string {
	if origin := zone.CanonicalName(dom.Domain); origin != "" {
		return origin
	}
	return "."
}

// absolute turns an owner relative to origin back into a canonical name.
func absolute(name, origin string) string {
	switch {
	case name == "@":
		return zone.CanonicalName(origin)
	case strings.HasSuffix(name, "."):
		return zone.CanonicalName(name)
	case origin == ".":
		return zone.CanonicalName(name)
	default:
		return zone.CanonicalName(name + "." + origin)
	}
}

func parseRecord(origin string, r Record) (zone.RecordText, error) {
	return zone.ParseRecordText(origin, fmt.Sprintf("%s. %d IN %s %s", zone.CanonicalName(r.Name), r.TTL, r.Type, r.Data))
}

// indexOf finds the line holding the same record as want, ignoring TTL.
func indexOf(lines []string, origin string, want zone.RecordText) int {
	for i, line := range lines {
		r, err := zone.ParseRecordText(origin, line)
		if err == nil && r.Name == want.Name && r.Type == want.Type && r.Data == want.Data {
			return i
		}
	}
	return -1
}
