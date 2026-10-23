package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultRefresh is how often URL sources are re-downloaded.
	DefaultRefresh    = 24 * time.Hour
	retryAfterFailure = 5 * time.Minute
	maxListSize       = 64 << 20
)

// Source is a rule list loaded from a URL or a local file.
type Source struct {
	Name string
	Kind Kind
	URL  string
	File string
	// Refresh is the reload interval. URL sources default to DefaultRefresh;
	// file sources are loaded once unless Refresh is set.
	Refresh time.Duration
}

// SourceStatus reports the state of one source.
type SourceStatus struct {
	Source
	Rules     int
	Skipped   int
	UpdatedAt time.Time // last successful load; zero if never loaded
	Error     string    // last load error, cleared on success
}

// Subscriptions keeps a set of sources loaded into a Filter: files are read
// synchronously by Set, URLs are fetched in the background and refreshed on
// their interval. A failed refresh keeps the previously loaded rules. With a
// cache directory, downloaded lists survive restarts without network access.
type Subscriptions struct {
	filter   *Filter
	client   *http.Client
	cacheDir string
	onUpdate func(SourceStatus)

	mu      sync.Mutex
	entries map[string]*subscription
	closed  bool
}

// SubscriptionOptions configures Subscriptions.
type SubscriptionOptions struct {
	Client   *http.Client // nil uses a client with a 60s timeout
	CacheDir string       // empty disables the on-disk cache
	// OnUpdate, if set, is called after every load attempt with the
	// source's new status (Error set on failure).
	OnUpdate func(SourceStatus)
}

type subscription struct {
	source Source
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	status SourceStatus
}

func NewSubscriptions(f *Filter, opts SubscriptionOptions) *Subscriptions {
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Subscriptions{filter: f, client: client, cacheDir: opts.CacheDir, onUpdate: opts.OnUpdate, entries: make(map[string]*subscription)}
}

// Set makes sources the active set. Unchanged sources keep running, changed
// ones restart, and removed ones are stopped and their lists removed from
// the filter. An invalid source rejects the whole call.
func (s *Subscriptions) Set(sources []Source) error {
	seen := make(map[string]bool, len(sources))
	for i, src := range sources {
		if err := validateSource(src); err != nil {
			return fmt.Errorf("sources[%d]: %w", i, err)
		}
		if seen[src.Name] {
			return fmt.Errorf("sources[%d]: duplicate name %q", i, src.Name)
		}
		seen[src.Name] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("filter: subscriptions closed")
	}
	for name, sub := range s.entries {
		if !seen[name] {
			sub.stop()
			delete(s.entries, name)
			s.filter.RemoveList(name)
		}
	}
	for _, src := range sources {
		if old, ok := s.entries[src.Name]; ok {
			if old.source == src {
				continue
			}
			old.stop()
		}
		s.entries[src.Name] = s.start(src)
	}
	return nil
}

func validateSource(src Source) error {
	switch {
	case src.Name == "":
		return fmt.Errorf("name required")
	case (src.URL == "") == (src.File == ""):
		return fmt.Errorf("source %q: exactly one of url or file required", src.Name)
	case src.Kind != "" && src.Kind != BlockList && src.Kind != AllowList:
		return fmt.Errorf("source %q: unknown kind %q", src.Name, src.Kind)
	}
	return nil
}

// start loads what is available locally right away, then hands URL
// fetching and periodic refresh to a goroutine.
func (s *Subscriptions) start(src Source) *subscription {
	ctx, cancel := context.WithCancel(context.Background())
	sub := &subscription{source: src, cancel: cancel, done: make(chan struct{}), status: SourceStatus{Source: src}}
	refresh := src.Refresh
	if src.File != "" {
		s.load(ctx, sub)
	} else {
		if refresh <= 0 {
			refresh = DefaultRefresh
		}
		s.loadCached(sub)
	}
	// Failed downloads retry sooner than the regular interval.
	next := func(ok bool) time.Duration {
		if !ok && src.URL != "" {
			return min(retryAfterFailure, refresh)
		}
		return refresh
	}
	go func() {
		defer close(sub.done)
		wait := refresh
		if src.URL != "" {
			wait = next(s.load(ctx, sub))
		}
		for wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = next(s.load(ctx, sub))
		}
	}()
	return sub
}

func (sub *subscription) stop() {
	sub.cancel()
	<-sub.done
}

// Refresh reloads one source now.
func (s *Subscriptions) Refresh(ctx context.Context, name string) error {
	s.mu.Lock()
	sub, ok := s.entries[name]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("filter: no source named %q", name)
	}
	if !s.load(ctx, sub) {
		return fmt.Errorf("%s", sub.snapshot().Error)
	}
	return nil
}

// Status reports every source ordered by name.
func (s *Subscriptions) Status() []SourceStatus {
	s.mu.Lock()
	out := make([]SourceStatus, 0, len(s.entries))
	for _, sub := range s.entries {
		out = append(out, sub.snapshot())
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Close stops all refresh loops. Installed lists stay in the filter.
func (s *Subscriptions) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, sub := range s.entries {
		sub.stop()
	}
}

func (sub *subscription) snapshot() SourceStatus {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.status
}

func (sub *subscription) record(info ListInfo, err error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if err != nil {
		sub.status.Error = err.Error()
		return
	}
	sub.status.Error = ""
	sub.status.Rules = info.Rules
	sub.status.Skipped = info.Skipped
	sub.status.UpdatedAt = time.Now()
}

// load fetches and installs a source, reporting success.
func (s *Subscriptions) load(ctx context.Context, sub *subscription) bool {
	data, err := s.fetch(ctx, sub.source)
	if err != nil {
		if ctx.Err() == nil {
			sub.record(ListInfo{}, err)
			if s.onUpdate != nil {
				s.onUpdate(sub.snapshot())
			}
		}
		return false
	}
	info, err := s.filter.SetListFrom(sub.source.Name, sub.source.Kind, bytes.NewReader(data))
	sub.record(info, err)
	if err == nil && sub.source.URL != "" {
		s.writeCache(sub.source, data)
	}
	if s.onUpdate != nil {
		s.onUpdate(sub.snapshot())
	}
	return err == nil
}

func (s *Subscriptions) loadCached(sub *subscription) {
	path := s.cachePath(sub.source)
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	info, err := s.filter.SetListFrom(sub.source.Name, sub.source.Kind, bytes.NewReader(data))
	if err != nil {
		return
	}
	sub.record(info, nil)
	if stat, err := os.Stat(path); err == nil {
		sub.mu.Lock()
		sub.status.UpdatedAt = stat.ModTime()
		sub.mu.Unlock()
	}
}

func (s *Subscriptions) fetch(ctx context.Context, src Source) ([]byte, error) {
	if src.File != "" {
		return os.ReadFile(src.File)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dns-go")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", src.URL, res.Status)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxListSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxListSize {
		return nil, fmt.Errorf("GET %s: list exceeds %d bytes", src.URL, maxListSize)
	}
	return data, nil
}

func (s *Subscriptions) cachePath(src Source) string {
	if s.cacheDir == "" || src.URL == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(src.URL))
	return filepath.Join(s.cacheDir, hex.EncodeToString(sum[:12])+".txt")
}

func (s *Subscriptions) writeCache(src Source, data []byte) {
	path := s.cachePath(src)
	if path == "" {
		return
	}
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
