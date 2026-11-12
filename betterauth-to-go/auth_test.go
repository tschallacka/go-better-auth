package betterauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/cookie"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/difftest"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/migrations"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/schema"
)

const (
	secret  = "unit-test-secret-0123456789abcdef0123456789"
	baseURL = "http://localhost:3000"
	api     = "/api/auth"
	token   = "better-auth.session_token"
)

type fakeStore struct{ betterauth.Store }

func config() betterauth.Config {
	return betterauth.Config{
		Secret:           secret,
		BaseURL:          baseURL,
		EmailAndPassword: betterauth.EmailAndPassword{Enabled: true},
		RateLimit:        betterauth.RateLimitOptions{Disabled: true},
	}
}

func TestNewRejectsWhatItCannotHonour(t *testing.T) {
	org, err := schema.Organization(schema.OrganizationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*betterauth.Config){
		"no secret":           func(c *betterauth.Config) { c.Secret = "" },
		"relative base URL":   func(c *betterauth.Config) { c.BaseURL = "/app" },
		"ftp base URL":        func(c *betterauth.Config) { c.BaseURL = "ftp://x.example" },
		"base path without /": func(c *betterauth.Config) { c.BasePath = "api" },
		"bad trusted origin":  func(c *betterauth.Config) { c.TrustedOrigins = []string{"not an origin"} },
		"inverted lengths": func(c *betterauth.Config) {
			c.EmailAndPassword.MinPasswordLength, c.EmailAndPassword.MaxPasswordLength = 20, 10
		},
		"email verification": func(c *betterauth.Config) { c.EmailAndPassword.RequireEmailVerification = true },
		"deferred refresh":   func(c *betterauth.Config) { c.Session.DeferSessionRefresh = true },
		"plugin":             func(c *betterauth.Config) { c.Schema.Plugins = []schema.Plugin{org} },
		"additional user fields": func(c *betterauth.Config) {
			c.Schema.User.Additional = []schema.Field{{Name: "x", Type: schema.String}}
		},
	} {
		c := config()
		mut(&c)
		if _, err := betterauth.New(c, fakeStore{}); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	if _, err := betterauth.New(config(), nil); err == nil {
		t.Error("New accepted a nil store")
	}
	if _, err := betterauth.New(config(), fakeStore{}); err != nil {
		t.Errorf("a valid config was refused: %v", err)
	}
}

func start(t *testing.T, cfg betterauth.Config) (*betterauth.Auth, string, func(string)) {
	t.Helper()
	pool := testdb.Fresh(t)
	ddl, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, pool, ddl)
	a, err := betterauth.New(cfg, pgstore.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return a, srv.URL, func(sql string) { testdb.Exec(t, pool, sql) }
}

func signUp(t *testing.T, c *difftest.Client, email string) *difftest.Response {
	t.Helper()
	return c.Post(t, api+"/sign-up/email", map[string]any{"email": email, "password": "12345678", "name": "N"})
}

// D9: by default a sign-up for a registered email gets the library's generic
// answer, with no session and no cookie, instead of a 422.
func TestSignUpExistingEmailDoesNotReveal(t *testing.T) {
	_, url, sql := start(t, config())
	if r := signUp(t, difftest.NewClient(url, baseURL), "ann@example.com"); r.Status != 200 {
		t.Fatalf("first sign-up: %d %s", r.Status, r.Body)
	}
	c := difftest.NewClient(url, baseURL)
	r := signUp(t, c, "Ann@Example.com")
	if r.Status != 200 || !strings.HasPrefix(string(r.Body), `{"token":null,"user":{"name":"N","email":"ann@example.com","emailVerified":false,"image":null,`) {
		t.Errorf("duplicate sign-up: %d %s", r.Status, r.Body)
	}
	if len(r.Cookies) != 0 {
		t.Errorf("duplicate sign-up set cookies: %v", r.Cookies)
	}
	sql(`DO $$ BEGIN IF (SELECT count(*) FROM "user") <> 1 THEN RAISE EXCEPTION 'a second user was written'; END IF; END $$`)
}

func request(cookieHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, baseURL+api+"/get-session", nil)
	if cookieHeader != "" {
		r.Header.Set("Cookie", cookieHeader)
	}
	return r
}

func TestResolveSession(t *testing.T) {
	a, url, sql := start(t, config())
	c := difftest.NewClient(url, baseURL)
	if r := signUp(t, c, "ann@example.com"); r.Status != 200 {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
	value := c.Cookies()[token].Value

	info, err := a.ResolveSession(request(token + "=" + value))
	if err != nil {
		t.Fatalf("ResolveSession: %v", err)
	}
	if info.User.Email != "ann@example.com" || info.Session.UserID != info.User.ID || info.Session.Token == "" {
		t.Errorf("resolved %+v", info)
	}
	if !info.Session.ExpiresAt.After(time.Now().Add(6 * 24 * time.Hour)) {
		t.Errorf("expiresAt %v; want about 7 days ahead", info.Session.ExpiresAt)
	}

	signed, _ := cookie.SignValue("not-a-real-session-token-000000", []byte(secret))
	foreign, _ := cookie.SignValue(info.Session.Token, []byte("another secret"))
	for name, header := range map[string]string{
		"no cookie":         "",
		"tampered":          token + "=" + strings.Replace(value, value[:4], "AAAA", 1),
		"unsigned token":    token + "=" + info.Session.Token,
		"foreign secret":    token + "=" + foreign,
		"unknown token":     token + "=" + signed,
		"other cookie name": "better-auth.session_tokens=" + value,
	} {
		if _, err := a.ResolveSession(request(header)); !errors.Is(err, betterauth.ErrNoSession) {
			t.Errorf("%s: %v; want ErrNoSession", name, err)
		}
	}

	sql(`UPDATE "session" SET "expiresAt" = now() - interval '1 second'`)
	if _, err := a.ResolveSession(request(token + "=" + value)); !errors.Is(err, betterauth.ErrNoSession) {
		t.Errorf("expired session: %v; want ErrNoSession", err)
	}
}

// Session fixation: a session cookie planted before sign-in is never adopted;
// sign-in always issues a new token.
func TestSignInIssuesAFreshSession(t *testing.T) {
	a, url, _ := start(t, config())
	victim := difftest.NewClient(url, baseURL)
	if r := signUp(t, victim, "ann@example.com"); r.Status != 200 {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
	planted := victim.Cookies()[token].Value
	r := victim.Post(t, api+"/sign-in/email", map[string]any{"email": "ann@example.com", "password": "12345678"})
	if r.Status != 200 {
		t.Fatalf("sign-in: %d %s", r.Status, r.Body)
	}
	fresh := victim.Cookies()[token].Value
	if fresh == planted {
		t.Fatal("sign-in kept the session token the browser already had")
	}
	before, _ := a.ResolveSession(request(token + "=" + planted))
	after, err := a.ResolveSession(request(token + "=" + fresh))
	if err != nil || before == nil || after.Session.Token == before.Session.Token {
		t.Errorf("sign-in did not create a distinct session: %v", err)
	}
}
