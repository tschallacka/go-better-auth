package betterauth

import (
	"strings"
	"sync"
	"time"
)

// RateLimitEntry is one counter: requests in the current window and when the
// last one came.
type RateLimitEntry struct {
	Count       int
	LastRequest time.Time
}

// RateLimitStore keeps rate-limit counters (D11). The library keeps them in
// process memory only; a deployment of several instances supplies a shared
// store so a client cannot spread its attempts across them.
type RateLimitStore interface {
	Get(key string) (RateLimitEntry, bool)
	Set(key string, e RateLimitEntry)
}

// MemoryRateLimitStore is the default store: per process, in memory.
type MemoryRateLimitStore struct {
	mu      sync.Mutex
	entries map[string]RateLimitEntry
	writes  int
}

// NewMemoryRateLimitStore returns an empty in-memory store.
func NewMemoryRateLimitStore() *MemoryRateLimitStore {
	return &MemoryRateLimitStore{entries: map[string]RateLimitEntry{}}
}

// Get implements RateLimitStore.
func (s *MemoryRateLimitStore) Get(key string) (RateLimitEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	return e, ok
}

// Set implements RateLimitStore. Every few thousand writes it drops entries
// idle for an hour, so the map does not grow without bound.
func (s *MemoryRateLimitStore) Set(key string, e RateLimitEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = e
	s.writes++
	if s.writes%4096 == 0 {
		cutoff := e.LastRequest.Add(-time.Hour)
		for k, v := range s.entries {
			if v.LastRequest.Before(cutoff) {
				delete(s.entries, k)
			}
		}
	}
}

type rateLimiter struct {
	store  RateLimitStore
	window time.Duration
	max    int
	now    func() time.Time
	mu     sync.Mutex // check-and-record is not atomic in the store interface
}

func newRateLimiter(o RateLimitOptions, now func() time.Time) *rateLimiter {
	if o.Disabled {
		return nil
	}
	return &rateLimiter{store: o.Store, window: o.Window, max: o.Max, now: now}
}

// rule is the library's getDefaultSpecialRules: stricter limits on the paths
// that take credentials.
func (l *rateLimiter) rule(path string) (time.Duration, int) {
	for _, p := range []string{"/sign-in", "/sign-up", "/change-password", "/change-email"} {
		if strings.HasPrefix(path, p) {
			return 10 * time.Second, 3
		}
	}
	return l.window, l.max
}

func rateKey(ip, path string) string {
	return ip + "|" + strings.TrimRight(path, "/")
}

// check reports whether the request must be refused, and the seconds to wait.
func (l *rateLimiter) check(ip, path string) (bool, int) {
	window, max := l.rule(path)
	e, ok := l.store.Get(rateKey(ip, path))
	if !ok {
		return false, 0
	}
	since := l.now().Sub(e.LastRequest)
	if since < window && e.Count >= max {
		wait := e.LastRequest.Add(window).Sub(l.now())
		secs := int((wait + time.Second - 1) / time.Second)
		return true, secs
	}
	return false, 0
}

// record counts a response, as the library's onResponse does.
func (l *rateLimiter) record(ip, path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	window, _ := l.rule(path)
	key := rateKey(ip, path)
	now := l.now()
	e, ok := l.store.Get(key)
	if !ok || now.Sub(e.LastRequest) > window {
		l.store.Set(key, RateLimitEntry{Count: 1, LastRequest: now})
		return
	}
	l.store.Set(key, RateLimitEntry{Count: e.Count + 1, LastRequest: now})
}
