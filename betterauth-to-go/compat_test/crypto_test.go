// Package compat holds the cross-compatibility tests of PLAN.md section 7:
// values the Go code writes must be read correctly by the real better-auth.
package compat

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/cookie"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/crypto"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
)

// library runs testdata/gen/<script> with req as JSON on stdin and decodes
// its stdout into res. It skips when Node or the generator's node_modules is
// missing, unless GBA_REQUIRE_LIBRARY=1, which CI sets so it can never skip.
func library(t *testing.T, script string, req, res any) {
	t.Helper()
	gen := testvectors.GenDir()
	node, err := exec.LookPath("node")
	_, statErr := os.Stat(filepath.Join(gen, "node_modules", "better-auth"))
	if err != nil || statErr != nil {
		if os.Getenv("GBA_REQUIRE_LIBRARY") == "1" {
			t.Fatalf("real better-auth unavailable (node: %v, node_modules: %v); run npm ci in testdata/gen", err, statErr)
		}
		t.Skip("real better-auth unavailable; run npm ci --ignore-scripts in testdata/gen")
	}
	in, _ := json.Marshal(req)
	cmd := exec.Command(node, script)
	cmd.Dir = gen
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, stderr.String())
	}
	if err := json.Unmarshal(out, res); err != nil {
		t.Fatalf("%s output: %v\n%s", script, err, out)
	}
}

type outcome struct {
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
}

func (o outcome) str(t *testing.T) string {
	t.Helper()
	var s string
	if o.Error != "" || json.Unmarshal(o.Value, &s) != nil {
		t.Fatalf("library returned %s / %q, want a string", o.Value, o.Error)
	}
	return s
}

func TestLibraryReadsGoOutput(t *testing.T) {
	type pw struct {
		Password string `json:"password"`
		Hash     string `json:"hash"`
	}
	type ct struct {
		Secret     string `json:"secret"`
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	}
	type vct struct {
		Keys           map[string]string `json:"keys"`
		CurrentVersion int64             `json:"currentVersion"`
		LegacySecret   string            `json:"legacySecret"`
		Plaintext      string            `json:"-"`
		Ciphertext     string            `json:"ciphertext"`
	}
	type ck struct {
		Cookie string `json:"cookie"`
		Name   string `json:"name"`
		Secret string `json:"secret"`
		Prefix string `json:"prefix"`
		Want   string `json:"-"`
	}
	var req struct {
		Passwords   []pw  `json:"passwords"`
		Ciphertexts []ct  `json:"ciphertexts"`
		Versioned   []vct `json:"versioned"`
		Cookies     []ck  `json:"cookies"`
	}

	for _, p := range []string{"correct horse", "ünïcödé", "ｐａｓｓ", "é"} {
		h, err := crypto.HashPassword(rand.Reader, p)
		if err != nil {
			t.Fatal(err)
		}
		req.Passwords = append(req.Passwords, pw{p, h})
	}
	wrong := req.Passwords[0]
	wrong.Password = "correct horsE"
	req.Passwords = append(req.Passwords, wrong)

	for _, p := range []string{"", "JBSWY3DPEHPK3PXP", `["a","b"]`, "ünïcödé"} {
		c, err := crypto.Encrypt(rand.Reader, "go-secret-0123456789", p)
		if err != nil {
			t.Fatal(err)
		}
		req.Ciphertexts = append(req.Ciphertexts, ct{"go-secret-0123456789", p, c})
	}

	kr := crypto.Keyring{Keys: map[int64]string{1: "go-v1-secret", 3: "go-v3-secret"}, Current: 3}
	vc, err := kr.Encrypt(rand.Reader, "versioned from go")
	if err != nil {
		t.Fatal(err)
	}
	req.Versioned = append(req.Versioned, vct{Keys: map[string]string{"1": "go-v1-secret", "3": "go-v3-secret"}, CurrentVersion: 3, Plaintext: "versioned from go", Ciphertext: vc})

	secret := "go-cookie-secret-0123456789"
	for _, c := range []struct {
		name, value string
		prefix      cookie.Prefix
	}{
		{"better-auth.session_token", "Gm3aT1kq9xYz2bLw7nPs4dRf", cookie.NoPrefix},
		{"better-auth.session_token", "tok/with+chars=", cookie.PrefixSecure},
		{"better-auth.dont_remember", "true", cookie.NoPrefix},
		{"x", "ünïcödé.with.dots", cookie.NoPrefix},
	} {
		header, err := cookie.SerializeSigned(c.name, c.value, []byte(secret), cookie.Options{Prefix: c.prefix, Path: "/"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		pair := header[:bytes.IndexByte([]byte(header), ';')]
		req.Cookies = append(req.Cookies, ck{Cookie: pair, Name: c.name, Secret: secret, Prefix: string(c.prefix), Want: c.value})
	}

	var res struct {
		Passwords   []outcome `json:"passwords"`
		Ciphertexts []outcome `json:"ciphertexts"`
		Versioned   []outcome `json:"versioned"`
		Cookies     []outcome `json:"cookies"`
	}
	library(t, "verify-go.mjs", req, &res)

	for i, p := range req.Passwords {
		want := "true"
		if i == len(req.Passwords)-1 {
			want = "false"
		}
		if string(res.Passwords[i].Value) != want {
			t.Errorf("library verifyPassword(Go hash of %q) = %s %q; want %s", p.Password, res.Passwords[i].Value, res.Passwords[i].Error, want)
		}
	}
	for i, c := range req.Ciphertexts {
		if got := res.Ciphertexts[i].str(t); got != c.Plaintext {
			t.Errorf("library decrypted Go ciphertext to %q; want %q", got, c.Plaintext)
		}
	}
	for i, v := range req.Versioned {
		if got := res.Versioned[i].str(t); got != v.Plaintext {
			t.Errorf("library decrypted Go envelope to %q; want %q", got, v.Plaintext)
		}
	}
	for i, c := range req.Cookies {
		if got := res.Cookies[i].str(t); got != c.Want {
			t.Errorf("library read Go cookie %q as %q; want %q", c.Cookie, got, c.Want)
		}
	}
}
