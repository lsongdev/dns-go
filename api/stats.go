package api

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/zone"
)

const (
	logCapacity  = 5000
	topKeyLimit  = 20000 // distinct names tracked per top list
	seriesLength = 24 * 60
)

// LogEntry is one query in the query log.
type LogEntry struct {
	Time       time.Time `json:"time"`
	DurationUs int64     `json:"duration_us"`
	Client     string    `json:"client"`
	ClientName string    `json:"client_name,omitempty"`
	Transport  string    `json:"transport"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	RCode      string    `json:"rcode"`
	Answers    int       `json:"answers"`
	Source     string    `json:"source"`
	FilterList string    `json:"filter_list,omitempty"`
	FilterRule string    `json:"filter_rule,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Stats aggregates query events in memory. Record is cheap and safe to call
// from engine.Hooks.OnQuery.
type Stats struct {
	mu       sync.Mutex
	started  time.Time
	total    uint64
	bySource map[string]uint64
	series   [seriesLength]minuteBucket
	names    map[string]uint64
	blocked  map[string]uint64
	clients  map[string]uint64
	log      []LogEntry
	logNext  int
	now      func() time.Time
}

type minuteBucket struct {
	minute  int64
	total   uint32
	blocked uint32
}

func NewStats() *Stats {
	return &Stats{
		started:  time.Now(),
		bySource: make(map[string]uint64),
		names:    make(map[string]uint64),
		blocked:  make(map[string]uint64),
		clients:  make(map[string]uint64),
		log:      make([]LogEntry, 0, logCapacity),
		now:      time.Now,
	}
}

// Record adds one query event.
func (s *Stats) Record(ev engine.QueryEvent) {
	entry := LogEntry{
		Time:       ev.Time,
		DurationUs: ev.Duration.Microseconds(),
		Client:     ev.Client.Addr().String(),
		ClientName: ev.ClientName,
		Transport:  string(ev.Transport),
		Name:       strings.ToLower(strings.TrimSuffix(ev.Name, ".")),
		Type:       zone.TypeString(ev.Type),
		RCode:      rcodeName(ev.RCode),
		Answers:    ev.Answers,
		Source:     string(ev.Source),
		FilterList: ev.Filter.List,
		FilterRule: ev.Filter.Rule,
	}
	if ev.Err != nil {
		entry.Error = ev.Err.Error()
	}
	isBlocked := ev.Source == engine.SourceFilter
	client := entry.Client
	if entry.ClientName != "" {
		client = entry.ClientName
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.bySource[entry.Source]++
	minute := ev.Time.Unix() / 60
	b := &s.series[minute%seriesLength]
	if b.minute != minute {
		*b = minuteBucket{minute: minute}
	}
	b.total++
	if isBlocked {
		b.blocked++
		bump(s.blocked, entry.Name)
	}
	bump(s.names, entry.Name)
	bump(s.clients, client)
	if len(s.log) < logCapacity {
		s.log = append(s.log, entry)
	} else {
		s.log[s.logNext] = entry
	}
	s.logNext = (s.logNext + 1) % logCapacity
}

func bump(m map[string]uint64, key string) {
	if _, ok := m[key]; ok || len(m) < topKeyLimit {
		m[key]++
	}
}

// Summary is the dashboard view.
type Summary struct {
	Since      time.Time         `json:"since"`
	Total      uint64            `json:"total"`
	Blocked    uint64            `json:"blocked"`
	BySource   map[string]uint64 `json:"by_source"`
	Series     []SeriesPoint     `json:"series"` // per minute, oldest first, last 24h
	TopNames   []Count           `json:"top_names"`
	TopBlocked []Count           `json:"top_blocked"`
	TopClients []Count           `json:"top_clients"`
}

type SeriesPoint struct {
	Time    time.Time `json:"time"`
	Total   uint32    `json:"total"`
	Blocked uint32    `json:"blocked"`
}

type Count struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

// Summary returns totals, the last 24h per-minute series (bucketed into
// `bucket` minutes), and the top n entries of each list.
func (s *Stats) Summary(n int, bucket int) Summary {
	if bucket < 1 {
		bucket = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Summary{
		Since:      s.started,
		Total:      s.total,
		Blocked:    s.bySource[string(engine.SourceFilter)],
		BySource:   make(map[string]uint64, len(s.bySource)),
		TopNames:   top(s.names, n),
		TopBlocked: top(s.blocked, n),
		TopClients: top(s.clients, n),
	}
	for k, v := range s.bySource {
		out.BySource[k] = v
	}
	now := s.now().Unix() / 60
	// Align buckets to wall-clock boundaries inside the 24h window; the last
	// bucket holds the current minute.
	first := now - seriesLength + 1
	first += (int64(bucket) - first%int64(bucket)) % int64(bucket)
	for start := first; start <= now; start += int64(bucket) {
		p := SeriesPoint{Time: time.Unix(start*60, 0).UTC()}
		for m := start; m < start+int64(bucket) && m <= now; m++ {
			if b := s.series[((m%seriesLength)+seriesLength)%seriesLength]; b.minute == m {
				p.Total += b.total
				p.Blocked += b.blocked
			}
		}
		out.Series = append(out.Series, p)
	}
	return out
}

func top(m map[string]uint64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// LogQuery filters the query log.
type LogQuery struct {
	Limit  int
	Search string // substring of name, client, or client name
	Source string
	Client string
}

// Log returns matching entries, newest first.
func (s *Stats) Log(q LogQuery) []LogEntry {
	if q.Limit <= 0 || q.Limit > logCapacity {
		q.Limit = 100
	}
	search := strings.ToLower(q.Search)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LogEntry, 0, q.Limit)
	// logNext is the slot after the newest entry, whether or not the ring
	// has wrapped, so walking backwards from it yields newest first.
	n := len(s.log)
	for i := 0; i < n && len(out) < q.Limit; i++ {
		e := s.log[(s.logNext-1-i+2*n)%n]
		if q.Source != "" && e.Source != q.Source {
			continue
		}
		if q.Client != "" && e.Client != q.Client && e.ClientName != q.Client {
			continue
		}
		if search != "" && !strings.Contains(e.Name, search) && !strings.Contains(e.Client, search) &&
			!strings.Contains(strings.ToLower(e.ClientName), search) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func rcodeName(rcode uint16) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 16:
		return "BADVERS"
	default:
		return "RCODE" + strconv.Itoa(int(rcode))
	}
}
