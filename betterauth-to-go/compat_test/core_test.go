package compat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/difftest"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/migrations"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
)

// sides runs the real library and the Go handler next to each other, each on
// its own database, with the same configuration.
type sides struct {
	libURL, goURL   string
	libPool, goPool *pgxpool.Pool
}

// goConfig is the Go handler's equivalent of coreConfig.
func goConfig() betterauth.Config {
	return betterauth.Config{
		Secret:           secret,
		BaseURL:          baseURL,
		EmailAndPassword: betterauth.EmailAndPassword{Enabled: true},
		RateLimit:        betterauth.RateLimitOptions{Disabled: true}, // the library's is off in coreConfig
	}
}

func newSides(t *testing.T, compat betterauth.Compat) *sides {
	t.Helper()
	gc := goConfig()
	gc.Compat = compat
	return newSidesWith(t, coreConfig(), gc)
}

func newSidesWith(t *testing.T, libCfg difftest.Config, goCfg betterauth.Config) *sides {
	t.Helper()
	libPool, libDB := testdb.FreshURL(t)
	lib := difftest.StartLibrary(t, libDB, libCfg)
	goPool := testdb.Fresh(t)
	ddl, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, goPool, ddl)
	auth, err := betterauth.New(goCfg, pgstore.New(goPool))
	if err != nil {
		t.Fatal(err)
	}
	// Served directly: an http.ServeMux would redirect unclean paths (//, ..)
	// before the handler sees them, where the library answers 404.
	srv := httptest.NewServer(auth.Handler())
	t.Cleanup(srv.Close)
	return &sides{libURL: lib.URL, goURL: srv.URL, libPool: libPool, goPool: goPool}
}

// browsers returns one fresh browser per side.
func (s *sides) browsers() (lib, gol *difftest.Client) {
	return difftest.NewClient(s.libURL, baseURL), difftest.NewClient(s.goURL, baseURL)
}

// sql runs the same statement on both databases.
func (s *sides) sql(t *testing.T, stmt string) {
	t.Helper()
	testdb.Exec(t, s.libPool, stmt)
	testdb.Exec(t, s.goPool, stmt)
}

var maskedFields = []string{"id", "token", "userId", "createdAt", "updatedAt", "expiresAt"}

var maxAgeRefresh = regexp.MustCompile(`Max-Age=60479[89]|Max-Age=604800`)

// cookieShape keeps a Set-Cookie's name and attributes and masks its value.
func cookieShape(h string, approxMaxAge bool) string {
	pair, attrs, _ := strings.Cut(h, ";")
	name, value, _ := strings.Cut(pair, "=")
	if value != "" {
		value = "<set>"
	}
	if approxMaxAge {
		// The library computes Max-Age from a second clock read after the
		// write; whether it lands on 604800 or 604799 depends on timing.
		attrs = maxAgeRefresh.ReplaceAllString(attrs, "Max-Age=~604800")
	}
	return name + "=" + value + ";" + attrs
}

type step struct {
	label        string
	method, path string
	ctype        string
	body         string
	approxMaxAge bool
}

// same sends one step to both sides through the given browsers and fails the
// test where the answers differ.
func same(t *testing.T, lib, gol *difftest.Client, st step) (*difftest.Response, *difftest.Response) {
	t.Helper()
	var body []byte
	if st.body != "" || st.ctype != "" {
		body = []byte(st.body)
	}
	rl := lib.DoRaw(t, st.method, st.path, st.ctype, body)
	rg := gol.DoRaw(t, st.method, st.path, st.ctype, body)
	if rl.Status != rg.Status {
		t.Errorf("%s: status go %d, library %d\n go  %s\n lib %s", st.label, rg.Status, rl.Status, rg.Body, rl.Body)
		return rl, rg
	}
	// Every header both could send, except the ones a server or transport
	// sets on its own.
	volatile := map[string]bool{"Date": true, "Content-Length": true, "Connection": true, "Keep-Alive": true,
		"Transfer-Encoding": true, "Set-Cookie": true}
	names := map[string]bool{}
	for h := range rl.Header {
		names[h] = true
	}
	for h := range rg.Header {
		names[h] = true
	}
	for h := range names {
		if volatile[h] {
			continue
		}
		if strings.Join(rl.Header.Values(h), "|") != strings.Join(rg.Header.Values(h), "|") {
			t.Errorf("%s: %s go %q, library %q", st.label, h, rg.Header.Values(h), rl.Header.Values(h))
		}
	}
	var cl, cg []string
	for _, h := range rl.Header.Values("Set-Cookie") {
		cl = append(cl, cookieShape(h, st.approxMaxAge))
	}
	for _, h := range rg.Header.Values("Set-Cookie") {
		cg = append(cg, cookieShape(h, st.approxMaxAge))
	}
	if strings.Join(cl, "\n") != strings.Join(cg, "\n") {
		t.Errorf("%s: Set-Cookie\n go  %q\n lib %q", st.label, cg, cl)
	}
	if len(rl.Body) == 0 || len(rg.Body) == 0 {
		if len(rl.Body) != len(rg.Body) {
			t.Errorf("%s: body go %q, library %q", st.label, rg.Body, rl.Body)
		}
		return rl, rg
	}
	var vl, vg any
	if json.Unmarshal(rl.Body, &vl) != nil || json.Unmarshal(rg.Body, &vg) != nil {
		if string(rl.Body) != string(rg.Body) {
			t.Errorf("%s: body go %q, library %q", st.label, rg.Body, rl.Body)
		}
		return rl, rg
	}
	if d := difftest.Diff(difftest.Normalize(vg, maskedFields...), difftest.Normalize(vl, maskedFields...)); d != "" {
		t.Errorf("%s: body differs\n%s", st.label, d)
	}
	// Key order, as JavaScript objects keep it.
	if keysOf(rl.Body) != keysOf(rg.Body) {
		t.Errorf("%s: key order\n go  %s\n lib %s", st.label, keysOf(rg.Body), keysOf(rl.Body))
	}
	return rl, rg
}

var jsonKey = regexp.MustCompile(`"([A-Za-z]+)":`)

func keysOf(b []byte) string {
	var out []string
	for _, m := range jsonKey.FindAllSubmatch(b, -1) {
		out = append(out, string(m[1]))
	}
	return strings.Join(out, ",")
}

const api = "/api/auth"

func post(label, path, body string) step {
	return step{label: label, method: "POST", path: api + path, ctype: "application/json", body: body}
}

func get(label, path string) step { return step{label: label, method: "GET", path: api + path} }

func TestCoreMatchesLibrary(t *testing.T) {
	s := newSides(t, betterauth.Compat{RevealExistingEmail: true})
	lib, gol := s.browsers()

	for _, st := range []step{
		post("sign-up empty body", "/sign-up/email", `{}`),
		post("sign-up bad email", "/sign-up/email", `{"email":"nope","password":"12345678","name":"x"}`),
		post("sign-up no name", "/sign-up/email", `{"email":"a@b.co","password":"12345678"}`),
		post("sign-up short password", "/sign-up/email", `{"email":"a@b.co","password":"1234567","name":"x"}`),
		post("sign-up long password", "/sign-up/email", `{"email":"a@b.co","password":"`+strings.Repeat("x", 129)+`","name":"x"}`),
		post("sign-up name not a string", "/sign-up/email", `{"email":"a@b.co","password":"12345678","name":5}`),
		post("sign-up rememberMe not a boolean", "/sign-up/email", `{"email":"a@b.co","password":"12345678","name":"x","rememberMe":"false"}`),
		post("sign-up array body", "/sign-up/email", `[1,2]`),
		{label: "sign-up text/plain", method: "POST", path: api + "/sign-up/email", ctype: "text/plain", body: `{}`},
		{label: "sign-up without content type", method: "POST", path: api + "/sign-up/email", body: `{"a":1}`},
	} {
		same(t, lib, gol, st)
	}

	// A real sign-up without remember-me, then the session it made.
	same(t, lib, gol, post("sign-up", "/sign-up/email", `{"email":"Ann@Example.com","password":"12345678","name":"Ann","rememberMe":false}`))
	same(t, lib, gol, get("get-session after sign-up", "/get-session"))
	same(t, lib, gol, post("get-session by POST", "/get-session", `{}`))
	same(t, lib, gol, post("sign-out", "/sign-out", `{}`))
	same(t, lib, gol, get("get-session after sign-out", "/get-session"))

	other1, other2 := s.browsers()
	same(t, other1, other2, post("sign-up existing email (compat)", "/sign-up/email", `{"email":"ann@example.com","password":"12345678","name":"Ann"}`))

	in1, in2 := s.browsers()
	for _, st := range []step{
		post("sign-in bad email", "/sign-in/email", `{"email":"nope","password":"x"}`),
		post("sign-in missing password", "/sign-in/email", `{"email":"ann@example.com"}`),
		post("sign-in unknown user", "/sign-in/email", `{"email":"bob@example.com","password":"12345678"}`),
		post("sign-in wrong password", "/sign-in/email", `{"email":"ann@example.com","password":"wrong-password"}`),
		post("sign-in foreign callback", "/sign-in/email", `{"email":"ann@example.com","password":"12345678","callbackURL":"https://evil.example/x"}`),
		post("sign-in protocol-relative callback", "/sign-in/email", `{"email":"ann@example.com","password":"12345678","callbackURL":"//evil.example"}`),
		{label: "sign-in form body", method: "POST", path: api + "/sign-in/email", ctype: "application/x-www-form-urlencoded", body: "email=ann%40example.com&password=12345678"},
		post("sign-in with callback", "/sign-in/email", `{"email":"ANN@example.com","password":"12345678","callbackURL":"/dash"}`),
		get("get-session", "/get-session"),
		get("unknown path", "/nope"),
		get("wrong method", "/sign-in/email"),
		get("trailing slash", "/get-session/"),
		{label: "outside the base path", method: "GET", path: "/other/get-session"},
		{label: "double slash", method: "GET", path: api + "//get-session"},
		get("ok", "/ok"),
		{label: "malformed JSON", method: "POST", path: api + "/sign-in/email", ctype: "application/json", body: `{"email":`},
		{label: "JSON with trailing garbage", method: "POST", path: api + "/sign-in/email", ctype: "application/json", body: `{"email":"ann@example.com","password":"12345678"}x`},
		{label: "percent-encoded slash in the path", method: "POST", path: api + "/sign-in%2Femail", ctype: "application/json", body: `{"email":"ann@example.com","password":"12345678"}`},
		{label: "percent-encoded letter in the path", method: "GET", path: api + "/%67et-session"},
		{label: "body on GET get-session", method: "GET", path: api + "/get-session", ctype: "text/plain", body: "hello"},
		{label: "form with a bad escape", method: "POST", path: api + "/sign-in/email", ctype: "application/x-www-form-urlencoded", body: "email=a%ZZ@b.co&password=12345678"},
		{label: "form with a semicolon", method: "POST", path: api + "/sign-in/email", ctype: "application/x-www-form-urlencoded", body: "email=a@b.co;x=1&password=12345678"},
	} {
		same(t, in1, in2, st)
	}

	// A session at least a day old is refreshed on get-session.
	s.sql(t, `UPDATE "session" SET "expiresAt" = now() + interval '6 days'`)
	st := get("get-session refreshes a day-old session", "/get-session")
	st.approxMaxAge = true
	same(t, in1, in2, st)
	same(t, in1, in2, get("get-session right after a refresh", "/get-session"))

	// An expired session clears the cookies and comes back null.
	s.sql(t, `UPDATE "session" SET "expiresAt" = now() - interval '1 minute'`)
	same(t, in1, in2, get("get-session with an expired session", "/get-session"))
	var nl, ng int
	_ = s.libPool.QueryRow(context.Background(), `SELECT count(*) FROM "session" WHERE "expiresAt" < now()`).Scan(&nl)
	_ = s.goPool.QueryRow(context.Background(), `SELECT count(*) FROM "session" WHERE "expiresAt" < now()`).Scan(&ng)
	if nl != ng {
		t.Errorf("expired sessions left: go %d, library %d", ng, nl)
	}

	// CSRF: a cross-site login navigation, and a foreign origin with a cookie.
	x1, x2 := s.browsers()
	for _, c := range []*difftest.Client{x1, x2} {
		c.Origin = "http://evil.example"
		c.FetchSite, c.FetchMode, c.FetchDest = "cross-site", "navigate", "document"
	}
	same(t, x1, x2, post("cross-site login navigation", "/sign-in/email", `{"email":"ann@example.com","password":"12345678"}`))
	y1, y2 := s.browsers()
	for _, c := range []*difftest.Client{y1, y2} {
		c.Origin = "http://evil.example"
		c.SetCookie(sessionCookie, "x")
	}
	same(t, y1, y2, post("foreign origin with a cookie", "/sign-out", `{}`))
	z1, z2 := s.browsers()
	for _, c := range []*difftest.Client{z1, z2} {
		c.Origin = "null"
		c.SetCookie(sessionCookie, "x")
	}
	same(t, z1, z2, post("null origin with a cookie", "/sign-out", `{}`))
	e1, e2 := s.browsers()
	for _, c := range []*difftest.Client{e1, e2} {
		c.Origin = "http://evil.example"
		c.Header = http.Header{"Cookie": {""}}
	}
	same(t, e1, e2, post("foreign origin with an empty Cookie header", "/sign-out", `{}`))

	// The session's ipAddress comes from X-Forwarded-For, normalised: IPv6 to
	// its /64, IPv4-mapped IPv6 to IPv4. ipAddress is compared unmasked.
	for i, xff := range []string{"2001:DB8::1", "::ffff:1.2.3.4", "203.0.113.9", "not-an-ip"} {
		f1, f2 := s.browsers()
		for _, c := range []*difftest.Client{f1, f2} {
			c.Header = http.Header{"X-Forwarded-For": {xff + ", 10.0.0.1"}}
		}
		email := fmt.Sprintf("ip%d@example.com", i)
		same(t, f1, f2, post("sign-up from "+xff, "/sign-up/email", `{"email":"`+email+`","password":"12345678","name":"Ip"}`))
		same(t, f1, f2, get("session ipAddress from "+xff, "/get-session"))
	}
}
