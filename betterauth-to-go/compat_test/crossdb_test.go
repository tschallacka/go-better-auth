package compat

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/cookie"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/crypto"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/difftest"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
)

const (
	secret  = "difftest-secret-0123456789abcdef0123456789"
	baseURL = "http://localhost:3000"
	// The library's default session cookie name.
	sessionCookie = "better-auth.session_token"
)

// These tests cross data at the database and cookie level using the Go
// primitives (crypto, cookie, pgstore) directly; once the Go handler exists,
// the endpoint tests drive both sides through HTTP as well.

func coreConfig() difftest.Config {
	return difftest.Config{
		Secret:  secret,
		BaseURL: baseURL,
		Options: map[string]any{"emailAndPassword": map[string]any{"enabled": true}},
	}
}

// The library under test must keep its CSRF and origin checks on; if the
// harness ever let an environment variable switch them off, every Go CSRF
// comparison would pass against a library that has none.
func TestHarnessKeepsLibrarySecurityOn(t *testing.T) {
	_, dbURL := testdb.FreshURL(t)
	lib := difftest.StartLibrary(t, dbURL, coreConfig())

	attacker := difftest.NewClient(lib.URL, "http://evil.example")
	attacker.FetchSite, attacker.FetchMode, attacker.FetchDest = "cross-site", "navigate", "document"
	res := attacker.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "a@example.com", "password": "whatever-123"})
	if res.Status != 403 || !strings.Contains(string(res.Body), "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED") {
		t.Errorf("cross-site login navigation: %d %s; want 403 CROSS_SITE_NAVIGATION_LOGIN_BLOCKED", res.Status, res.Body)
	}

	withCookie := difftest.NewClient(lib.URL, "http://evil.example")
	withCookie.SetCookie(sessionCookie, "x")
	res = withCookie.Post(t, "/api/auth/sign-out", map[string]any{})
	if res.Status != 403 || !strings.Contains(string(res.Body), "INVALID_ORIGIN") {
		t.Errorf("sign-out from a foreign origin with a cookie: %d %s; want 403 INVALID_ORIGIN", res.Status, res.Body)
	}
}

func field(t *testing.T, v any, path ...string) any {
	t.Helper()
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("no %q in %v", p, v)
		}
		v = m[p]
	}
	return v
}

// The library writes a user, a password and a session; Go must read all of
// them: the signed cookie, the session row and the password hash.
func TestGoReadsWhatLibraryWrites(t *testing.T) {
	pool, dbURL := testdb.FreshURL(t)
	lib := difftest.StartLibrary(t, dbURL, coreConfig())
	browser := difftest.NewClient(lib.URL, baseURL)

	res := browser.Post(t, "/api/auth/sign-up/email", map[string]any{
		"email": "ann@example.com", "password": "correct horse battery", "name": "Ann",
	})
	if res.Status != 200 {
		t.Fatalf("library sign-up: %d %s", res.Status, res.Body)
	}
	userID := field(t, res.JSON(t), "user", "id").(string)

	ck := browser.Cookies()[sessionCookie]
	if ck == nil {
		t.Fatalf("library set no %s cookie; got %v", sessionCookie, res.Cookies)
	}
	token, state := cookie.GetSigned(cookie.Parse(sessionCookie+"="+ck.Value), sessionCookie, cookie.NoPrefix, []byte(secret))
	if state != cookie.Valid {
		t.Fatalf("Go does not accept the library's session cookie %q (state %d)", ck.Value, state)
	}

	ctx := context.Background()
	store := pgstore.New(pool)
	session, err := store.FindOne(ctx, "session", []betterauth.Where{{Column: "token", Value: token}})
	if err != nil {
		t.Fatalf("session row for the cookie's token: %v", err)
	}
	if session["userId"] != userID {
		t.Errorf("session belongs to %v; signed-up user is %s", session["userId"], userID)
	}
	account, err := store.FindOne(ctx, "account", []betterauth.Where{
		{Column: "userId", Value: userID}, {Column: "providerId", Value: "credential"},
	})
	if err != nil {
		t.Fatalf("credential account: %v", err)
	}
	ok, err := crypto.VerifyPassword(account["password"].(string), "correct horse battery")
	if err != nil || !ok {
		t.Errorf("Go cannot verify the library's password hash: %v, %v", ok, err)
	}
	if ok, _ := crypto.VerifyPassword(account["password"].(string), "wrong"); ok {
		t.Error("the library's hash verified a wrong password in Go")
	}
}

// Go writes a user, a credential account and a session, and signs the cookie;
// the library must accept the cookie and the password.
func TestLibraryReadsWhatGoWrites(t *testing.T) {
	pool, dbURL := testdb.FreshURL(t)
	lib := difftest.StartLibrary(t, dbURL, coreConfig()) // creates the tables
	ctx := context.Background()
	store := pgstore.New(pool)
	now := time.Now().UTC().Truncate(time.Millisecond)

	id := func() string {
		s, err := crypto.RandomString(rand.Reader, 32, crypto.LowerAlpha+crypto.UpperAlpha+crypto.Digits)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	userID := id()
	if _, err := store.Create(ctx, "user", betterauth.Row{"id": userID, "name": "Bo", "email": "bo@example.com",
		"emailVerified": false, "createdAt": now, "updatedAt": now}); err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.HashPassword(rand.Reader, "go wrote this password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "account", betterauth.Row{"id": id(), "accountId": userID, "providerId": "credential",
		"userId": userID, "password": hash, "createdAt": now, "updatedAt": now}); err != nil {
		t.Fatal(err)
	}
	token, err := crypto.RandomString(rand.Reader, 32, crypto.DefaultAlphabet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "session", betterauth.Row{"id": id(), "token": token, "userId": userID,
		"expiresAt": now.Add(7 * 24 * time.Hour), "createdAt": now, "updatedAt": now}); err != nil {
		t.Fatal(err)
	}
	// The cookie goes through Go's own Set-Cookie serialisation and is read
	// back the way a browser stores it.
	maxAge := 604800
	header, err := cookie.SerializeSigned(sessionCookie, token, []byte(secret),
		cookie.Options{Path: "/", HTTPOnly: true, SameSite: "lax", MaxAge: &maxAge}, now)
	if err != nil {
		t.Fatal(err)
	}
	set, err := http.ParseSetCookie(header)
	if err != nil {
		t.Fatalf("Go's Set-Cookie %q does not parse: %v", header, err)
	}

	browser := difftest.NewClient(lib.URL, baseURL)
	browser.SetCookie(set.Name, set.Value)
	res := browser.Get(t, "/api/auth/get-session")
	if res.Status != 200 {
		t.Fatalf("library get-session with a Go cookie: %d %s", res.Status, res.Body)
	}
	got := res.JSON(t)
	if got == nil || field(t, got, "user", "id") != userID {
		t.Fatalf("library did not resolve the Go session: %s", res.Body)
	}
	// Times Go wrote must come back as written: a timezone or precision slip
	// in the Go side would move the expiry.
	if want := now.Add(7 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z"); field(t, got, "session", "expiresAt") != want {
		t.Errorf("library reads expiresAt %v; Go wrote %s", field(t, got, "session", "expiresAt"), want)
	}
	if field(t, got, "session", "token") != token || field(t, got, "user", "email") != "bo@example.com" {
		t.Errorf("library read the session as %s", res.Body)
	}
	fresh := difftest.NewClient(lib.URL, baseURL)
	res = fresh.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "bo@example.com", "password": "go wrote this password"})
	if res.Status != 200 {
		t.Fatalf("library sign-in with a Go password hash: %d %s", res.Status, res.Body)
	}
	res = fresh.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "bo@example.com", "password": "something else"})
	if res.Status != 401 {
		t.Errorf("library accepted a wrong password against a Go hash: %d %s", res.Status, res.Body)
	}
}
