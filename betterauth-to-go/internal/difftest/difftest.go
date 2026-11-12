// Package difftest runs the real better-auth 1.6.14 next to the Go code so
// tests can send both the same requests and compare what comes back, and so
// one implementation can read what the other wrote. Test code only.
//
// It needs Node and testdata/gen/node_modules (npm ci --ignore-scripts).
// Without them a test is skipped, unless GBA_REQUIRE_LIBRARY=1 (set in CI).
package difftest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
)

// Plugin enables one library plugin with plain-data options.
type Plugin struct {
	Name    string         `json:"name"`
	Options map[string]any `json:"options,omitempty"`
}

// Config is the library's configuration as plain data. Callbacks that send
// mail are installed by server.mjs and land in the outbox.
//
// The library runs with NODE_ENV=production, as deployed. Rate limiting and
// the origin check are stated here rather than left to environment defaults:
// the origin check is on unless a test turns it off.
type Config struct {
	Secret             string
	BaseURL            string
	RateLimit          bool // the library's rate limiter
	DisableOriginCheck bool // advanced.disableOriginCheck
	Options            map[string]any
	Plugins            []Plugin
}

func (c Config) payload() ([]byte, error) {
	return json.Marshal(map[string]any{
		"secret":      c.Secret,
		"baseURL":     c.BaseURL,
		"rateLimit":   c.RateLimit,
		"originCheck": !c.DisableOriginCheck,
		"options":     c.Options,
		"plugins":     c.Plugins,
	})
}

// Library is one running instance of the real library.
type Library struct {
	URL string // e.g. http://127.0.0.1:41234
}

// RequireLibrary skips the test when the library cannot run, or fails it
// under GBA_REQUIRE_LIBRARY=1. It returns the node binary.
func RequireLibrary(t testing.TB) string {
	t.Helper()
	node, err := exec.LookPath("node")
	_, statErr := os.Stat(filepath.Join(testvectors.GenDir(), "node_modules", "better-auth"))
	if err != nil || statErr != nil {
		if os.Getenv("GBA_REQUIRE_LIBRARY") == "1" {
			t.Fatalf("real better-auth unavailable (node: %v, node_modules: %v); run npm ci in testdata/gen", err, statErr)
		}
		t.Skip("real better-auth unavailable; run npm ci --ignore-scripts in testdata/gen")
	}
	return node
}

// syncBuffer collects the server's stderr for failure messages.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// StartLibrary runs the library over the database at dbURL, creating its
// tables with the library's own migrator, and stops it when the test ends.
func StartLibrary(t testing.TB, dbURL string, cfg Config) *Library {
	t.Helper()
	node := RequireLibrary(t)
	conf, err := cfg.payload()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "server.mjs")
	cmd.Dir = testvectors.GenDir()
	// Nothing is inherited: NODE_ENV=test or TEST=1 in the caller's shell would
	// switch off the library's origin check, and BETTER_AUTH_* variables
	// would change its configuration behind the test's back.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"NODE_ENV=production",
		"PG_URL=" + dbURL,
		"CONFIG=" + string(conf),
		"PARENT_PID=" + strconv.Itoa(os.Getpid()),
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the library: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close() // server.mjs exits when its stdin closes
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if port, ok := strings.CutPrefix(sc.Text(), "ready "); ok {
				ready <- port
			}
		}
		close(ready)
	}()
	select {
	case port, ok := <-ready:
		if !ok {
			t.Fatalf("the library exited before it was ready:\n%s", stderr.String())
		}
		return &Library{URL: "http://127.0.0.1:" + port}
	case <-time.After(60 * time.Second):
		t.Fatalf("the library did not start within a minute:\n%s", stderr.String())
	}
	return nil
}

// Message is one thing the library asked to send.
type Message map[string]any

// Outbox returns and clears what the library asked to send since the last
// call.
func (l *Library) Outbox(t testing.TB) []Message {
	t.Helper()
	res, err := http.Get(l.URL + "/__outbox")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out []Message
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Response is one HTTP response, read in full.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	Cookies []*http.Cookie // from Set-Cookie
}

// JSON decodes the body, failing the test when it is not JSON.
func (r *Response) JSON(t testing.TB) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatalf("response %d is not JSON: %v\n%s", r.Status, err, r.Body)
	}
	return v
}

// Client is one browser: it keeps cookies across requests and sends the
// Origin and Fetch Metadata headers a browser's fetch() would. The jar keys
// cookies by name only and ignores Path and Domain: every request goes to the
// one origin under test.
type Client struct {
	Base   string // e.g. a Library URL or an httptest server URL
	Origin string // sent on every request; the library checks it
	// Fetch Metadata, sent when non-empty. NewClient sets what a same-origin
	// fetch() sends; a test of cross-site navigation changes them.
	FetchSite, FetchMode, FetchDest string
	jar                             map[string]*http.Cookie
}

// NewClient returns a browser for base that claims origin and behaves like a
// same-origin fetch().
func NewClient(base, origin string) *Client {
	return &Client{Base: base, Origin: origin, FetchSite: "same-origin", FetchMode: "cors", FetchDest: "empty",
		jar: map[string]*http.Cookie{}}
}

// Cookies returns the cookies the browser holds, by name.
func (c *Client) Cookies() map[string]*http.Cookie {
	out := make(map[string]*http.Cookie, len(c.jar))
	for k, v := range c.jar {
		out[k] = v
	}
	return out
}

// SetCookie puts a cookie into the browser as if a server had set it.
func (c *Client) SetCookie(name, value string) {
	c.jar[name] = &http.Cookie{Name: name, Value: value}
}

// Do sends method path (relative to Base) with body encoded as JSON when it
// is not nil, and stores the cookies the response sets.
func (c *Client) Do(t testing.TB, method, path string, body any) *Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Origin != "" {
		req.Header.Set("Origin", c.Origin)
	}
	for h, v := range map[string]string{"Sec-Fetch-Site": c.FetchSite, "Sec-Fetch-Mode": c.FetchMode, "Sec-Fetch-Dest": c.FetchDest} {
		if v != "" {
			req.Header.Set(h, v)
		}
	}
	names := make([]string, 0, len(c.jar))
	for n := range c.jar {
		names = append(names, n)
	}
	sort.Strings(names)
	pairs := make([]string, len(names))
	for i, n := range names {
		// As a browser sends it: one header, the stored value as it was set.
		pairs[i] = n + "=" + c.jar[n].Value
	}
	if len(pairs) > 0 {
		req.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := &Response{Status: res.StatusCode, Header: res.Header, Body: b, Cookies: res.Cookies()}
	for _, ck := range out.Cookies {
		// net/http reports "Max-Age=0" as MaxAge < 0; either that or a past
		// Expires means the server deleted it.
		if ck.MaxAge < 0 || (!ck.Expires.IsZero() && ck.Expires.Before(time.Now())) {
			delete(c.jar, ck.Name)
			continue
		}
		c.jar[ck.Name] = ck
	}
	return out
}

// Get is Do with GET and no body.
func (c *Client) Get(t testing.TB, path string) *Response { return c.Do(t, http.MethodGet, path, nil) }

// Post is Do with POST.
func (c *Client) Post(t testing.TB, path string, body any) *Response {
	return c.Do(t, http.MethodPost, path, body)
}

// isoMillis is how JavaScript's Date.prototype.toJSON writes a time.
var isoMillis = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

// Shape names what a masked value looked like, so masking hides the value
// but not its form: a Go timestamp written with nanoseconds, an empty token
// or a number where the library has a string still shows up as a difference.
func Shape(v any) string {
	switch x := v.(type) {
	case string:
		switch {
		case x == "":
			return "<empty-string>"
		case isoMillis.MatchString(x):
			return "<iso8601-ms>"
		}
		return fmt.Sprintf("<string:%d>", len(x))
	case float64, json.Number:
		return "<number>"
	case bool:
		return "<bool>"
	case map[string]any:
		return "<object>"
	case []any:
		return "<array>"
	}
	return fmt.Sprintf("<%T>", v)
}

// Normalize returns v with every value under one of the keys replaced by its
// Shape, at any depth; a null stays null so presence is still compared.
func Normalize(v any, keys ...string) any {
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(x))
			for k, val := range x {
				if set[k] && val != nil {
					out[k] = Shape(val)
				} else {
					out[k] = walk(val)
				}
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, val := range x {
				out[i] = walk(val)
			}
			return out
		}
		return v
	}
	return walk(v)
}

// Diff returns "" when a and b encode to the same JSON, or both encodings. A
// value that cannot be encoded is a difference, never a match.
func Diff(a, b any) string {
	ja, errA := json.MarshalIndent(a, "", "  ")
	jb, errB := json.MarshalIndent(b, "", "  ")
	if errA != nil || errB != nil {
		return fmt.Sprintf("cannot compare: go %v, library %v", errA, errB)
	}
	if bytes.Equal(ja, jb) {
		return ""
	}
	return fmt.Sprintf("--- go\n%s\n--- library\n%s", ja, jb)
}

// Query adds q to path.
func Query(path string, q map[string]string) string {
	v := url.Values{}
	for k, val := range q {
		v.Set(k, val)
	}
	return path + "?" + v.Encode()
}
