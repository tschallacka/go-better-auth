package compat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/difftest"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/migrations"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
)

func decodeBody(t *testing.T, r *difftest.Response) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	return v
}

// During the overlap both implementations serve one database. A session
// either side creates must be read identically by the other, and sign-out on
// one side must end it for both.
func TestSharedDatabase(t *testing.T) {
	pool, dbURL := testdb.FreshURL(t)
	lib := difftest.StartLibrary(t, dbURL, coreConfig()) // creates the tables
	auth, err := betterauth.New(goConfig(), pgstore.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(auth.Handler())
	t.Cleanup(srv.Close)

	// The library signs Ann up; Go reads her session from the same cookie.
	onLib := difftest.NewClient(lib.URL, baseURL)
	if r := onLib.Post(t, api+"/sign-up/email", map[string]any{"email": "ann@example.com", "password": "12345678", "name": "Ann"}); r.Status != 200 {
		t.Fatalf("library sign-up: %d %s", r.Status, r.Body)
	}
	onGo := difftest.NewClient(srv.URL, baseURL)
	for name, ck := range onLib.Cookies() {
		onGo.SetCookie(name, ck.Value)
	}
	fromLib := decodeBody(t, onLib.Get(t, api+"/get-session"))
	fromGo := decodeBody(t, onGo.Get(t, api+"/get-session"))
	if fromLib == nil || !reflect.DeepEqual(fromLib, fromGo) {
		t.Fatalf("one session, two readings:\n go  %v\n lib %v", fromGo, fromLib)
	}

	// Go signs Ann in with the password the library hashed; the library
	// reads that session back the same way.
	goBrowser := difftest.NewClient(srv.URL, baseURL)
	if r := goBrowser.Post(t, api+"/sign-in/email", map[string]any{"email": "ann@example.com", "password": "12345678"}); r.Status != 200 {
		t.Fatalf("Go sign-in with a library password: %d %s", r.Status, r.Body)
	}
	libBrowser := difftest.NewClient(lib.URL, baseURL)
	for name, ck := range goBrowser.Cookies() {
		libBrowser.SetCookie(name, ck.Value)
	}
	fromGo = decodeBody(t, goBrowser.Get(t, api+"/get-session"))
	fromLib = decodeBody(t, libBrowser.Get(t, api+"/get-session"))
	if fromGo == nil || !reflect.DeepEqual(fromLib, fromGo) {
		t.Fatalf("a Go session read by the library:\n go  %v\n lib %v", fromGo, fromLib)
	}

	// Sign-out on Go ends the session the library created.
	if r := onGo.Post(t, api+"/sign-out", map[string]any{}); r.Status != 200 {
		t.Fatalf("Go sign-out: %d %s", r.Status, r.Body)
	}
	if r := onLib.Get(t, api+"/get-session"); string(r.Body) != "null" {
		t.Errorf("library still sees the session Go signed out: %s", r.Body)
	}
}

// With a client address in X-Forwarded-For both limit the fourth sign-in
// inside ten seconds the same way.
func TestRateLimitMatchesLibrary(t *testing.T) {
	lc := coreConfig()
	lc.RateLimit = true
	gc := goConfig()
	gc.RateLimit = betterauth.RateLimitOptions{}
	s := newSidesWith(t, lc, gc)
	lib, gol := s.browsers()
	for _, c := range []*difftest.Client{lib, gol} {
		c.Header = http.Header{"X-Forwarded-For": {"203.0.113.7"}}
	}
	for i := 1; i <= 4; i++ {
		rl := lib.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "wrong-password"})
		rg := gol.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "wrong-password"})
		if rl.Status != rg.Status || string(rl.Body) != string(rg.Body) {
			t.Fatalf("attempt %d: go %d %s, library %d %s", i, rg.Status, rg.Body, rl.Status, rl.Body)
		}
		if i == 4 {
			if rl.Status != 429 {
				t.Fatalf("the library did not limit the fourth attempt: %d", rl.Status)
			}
			if rl.Header.Get("X-Retry-After") == "" || rg.Header.Get("X-Retry-After") == "" {
				t.Errorf("X-Retry-After go %q, library %q", rg.Header.Get("X-Retry-After"), rl.Header.Get("X-Retry-After"))
			}
		}
	}
	// A different address is counted separately.
	for _, c := range []*difftest.Client{lib, gol} {
		c.Header = http.Header{"X-Forwarded-For": {"203.0.113.8"}}
	}
	if rl, rg := lib.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "x"}),
		gol.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "x"}); rl.Status != rg.Status {
		t.Errorf("another address: go %d, library %d", rg.Status, rl.Status)
	}
}

// A client rotating addresses inside one IPv6 /64 is limited as one client,
// on both sides.
func TestRateLimitIPv6Subnet(t *testing.T) {
	lc := coreConfig()
	lc.RateLimit = true
	gc := goConfig()
	gc.RateLimit = betterauth.RateLimitOptions{}
	s := newSidesWith(t, lc, gc)
	lib, gol := s.browsers()
	for i := 1; i <= 4; i++ {
		xff := http.Header{"X-Forwarded-For": {fmt.Sprintf("2001:db8:1:2::%x", i)}}
		lib.Header, gol.Header = xff, xff
		rl := lib.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "wrong-password"})
		rg := gol.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "wrong-password"})
		if rl.Status != rg.Status {
			t.Fatalf("attempt %d from another address in the /64: go %d, library %d", i, rg.Status, rl.Status)
		}
		if i == 4 && rg.Status != 429 {
			t.Errorf("fourth attempt from one /64: %d; want 429", rg.Status)
		}
	}
}

// Check and count are one step: of many simultaneous sign-ins from one
// client only the allowed number get through. (The library counts after the
// response, so it lets them all through; there is nothing to compare.)
func TestRateLimitUnderConcurrency(t *testing.T) {
	gc := goConfig()
	gc.RateLimit = betterauth.RateLimitOptions{}
	pool := testdb.Fresh(t)
	migrate(t, pool)
	auth, err := betterauth.New(gc, pgstore.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(auth.Handler())
	t.Cleanup(srv.Close)

	const n = 30
	statuses := make(chan int, n)
	start := make(chan struct{})
	for range n {
		go func() {
			c := difftest.NewClient(srv.URL, baseURL)
			c.Header = http.Header{"X-Forwarded-For": {"198.51.100.4"}}
			<-start
			statuses <- c.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "wrong-password"}).Status
		}()
	}
	close(start)
	passed := 0
	for range n {
		if <-statuses != http.StatusTooManyRequests {
			passed++
		}
	}
	if passed != 3 {
		t.Errorf("%d of %d simultaneous sign-ins got through; want 3", passed, n)
	}
}

// migrate applies the core migration to a fresh database.
func migrate(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) {
	t.Helper()
	ddl, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), ddl); err != nil {
		t.Fatal(err)
	}
}

// D15: without X-Forwarded-For the library does not limit at all; Go limits
// on the connection's address instead.
func TestRateLimitWithoutForwardedFor(t *testing.T) {
	gc := goConfig()
	gc.RateLimit = betterauth.RateLimitOptions{}
	pool := testdb.Fresh(t)
	migrate(t, pool)
	auth, err := betterauth.New(gc, pgstore.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(auth.Handler())
	t.Cleanup(srv.Close)
	c := difftest.NewClient(srv.URL, baseURL)
	var last int
	for range 4 {
		last = c.Post(t, api+"/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "wrong-password"}).Status
	}
	if last != 429 {
		t.Errorf("fourth sign-in without X-Forwarded-For: %d; want 429 (D15)", last)
	}
}
