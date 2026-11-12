package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
)

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func TestSerializeSignedMatchesLibrary(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, c := range v.SignedCookieHeaders {
		o := c.Options
		opt := Options{
			Prefix:      Prefix(o.Prefix),
			MaxAge:      o.MaxAge,
			Domain:      o.Domain,
			Path:        o.Path,
			HTTPOnly:    o.HTTPOnly,
			Secure:      o.Secure,
			SameSite:    o.SameSite,
			Partitioned: o.Partitioned,
		}
		got, err := SerializeSigned(c.Name, c.Value, []byte(c.Secret), opt, now)
		if err != nil || got != c.Header {
			t.Errorf("SerializeSigned(%q)\n got  %q, %v\n want %q", c.Name, got, err, c.Header)
		}
	}
}

func TestGetSignedMatchesLibrary(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, c := range v.SignedCookieReads {
		value, state := GetSigned(Parse(c.Cookie), c.Name, NoPrefix, []byte(c.Secret))
		var want string
		switch string(c.Result) {
		case "null":
			if state != Absent {
				t.Errorf("%s: state %d; library returned null (Absent)", c.Label, state)
			}
			continue
		case "false":
			if state != Invalid {
				t.Errorf("%s: state %d; library returned false (Invalid)", c.Label, state)
			}
			continue
		}
		if err := json.Unmarshal(c.Result, &want); err != nil {
			t.Fatalf("%s: result %s: %v", c.Label, c.Result, err)
		}
		if state != Valid || value != want {
			t.Errorf("%s: GetSigned = %q, %d; library returned %q", c.Label, value, state, want)
		}
	}
}

func TestParse(t *testing.T) {
	for _, c := range []struct {
		header string
		want   map[string]string
	}{
		{"", map[string]string{}},
		{"a=1", map[string]string{"a": "1"}},
		{" a = 1 ; b=2", map[string]string{"a": "1", "b": "2"}},
		{"a=1; a=2", map[string]string{"a": "1"}},
		{`a="quoted"`, map[string]string{"a": "quoted"}},
		{`a="`, map[string]string{"a": ""}},
		{`a="half`, map[string]string{"a": "hal"}}, // slice(1, -1) drops the last character regardless
		{"a=%20x%2B", map[string]string{"a": " x+"}},
		{"a=%E0%A4%A", map[string]string{"a": "%E0%A4%A"}}, // undecodable: kept as written
		{"a=b=c", map[string]string{"a": "b=c"}},
		{"junk; a=1", map[string]string{"a": "1"}},
		{"noequals", map[string]string{}},
		{"a=1;", map[string]string{"a": "1"}},
		{"=v", map[string]string{"": "v"}},
	} {
		got := Parse(c.header)
		if len(got) != len(c.want) {
			t.Errorf("Parse(%q) = %v; want %v", c.header, got, c.want)
			continue
		}
		for k, w := range c.want {
			if got[k] != w {
				t.Errorf("Parse(%q)[%q] = %q; want %q", c.header, k, got[k], w)
			}
		}
	}
}

func TestGetSignedPrefixes(t *testing.T) {
	secret := []byte("secret")
	signed, err := SignValue("tok", secret)
	if err != nil {
		t.Fatal(err)
	}
	cookies := Parse("__Secure-st=" + signed + "; __Host-h=" + signed)
	if v, s := GetSigned(cookies, "st", PrefixSecure, secret); s != Valid || v != "tok" {
		t.Errorf("secure prefix: %q, %d", v, s)
	}
	if v, s := GetSigned(cookies, "h", PrefixHost, secret); s != Valid || v != "tok" {
		t.Errorf("host prefix: %q, %d", v, s)
	}
	if _, s := GetSigned(cookies, "st", NoPrefix, secret); s != Absent {
		t.Error("unprefixed lookup found a __Secure- cookie")
	}
	if _, s := GetSigned(cookies, "st", Prefix("other"), secret); s != Absent {
		t.Error("unknown prefix found a cookie")
	}
}

func TestEmptySecretNeverValidates(t *testing.T) {
	if _, err := SerializeSigned("st", "tok", nil, Options{}, now); err == nil {
		t.Error("signed a cookie with an empty secret")
	}
	// "tok." + base64(HMAC-SHA256(empty key, "tok")): computable by anyone.
	mac := hmac.New(sha256.New, nil)
	mac.Write([]byte("tok"))
	forged := map[string]string{"st": "tok." + base64.StdEncoding.EncodeToString(mac.Sum(nil))}
	if v, s := GetSigned(forged, "st", NoPrefix, nil); s == Valid {
		t.Errorf("empty-key signature accepted as %q", v)
	}
}

func TestSerializeRules(t *testing.T) {
	age := func(n int) *int { return &n }
	for _, c := range []struct {
		name  string
		value string
		opt   Options
		want  string
	}{
		{"a", "x y", Options{}, "a=x%20y"},
		{"a", "v", Options{MaxAge: age(0)}, "a=v; Max-Age=0"},
		{"a", "v", Options{MaxAge: age(-1)}, "a=v"},
		{"a", "v", Options{SameSite: "none", Secure: true}, "a=v; Secure; SameSite=None"},
		{"__Secure-a", "v", Options{}, "__Secure-a=v; Secure"},
		{"__Host-a", "v", Options{Path: "/x", Domain: "d"}, "__Host-a=v; Path=/; Secure"},
		{"a", "v", Options{Prefix: PrefixHost, Domain: "d", Path: "/x"}, "__Host-a=v; Path=/x"},
		{"a", "v", Options{Prefix: PrefixSecure}, "__Secure-a=v"},
		{"a", "v", Options{Partitioned: true}, "a=v; Partitioned"},
		{"a", "v", Options{Expires: now.Add(time.Hour)}, "a=v; Expires=Thu, 12 Nov 2026 13:00:00 GMT"},
	} {
		got, err := Serialize(c.name, c.value, c.opt, now)
		if err != nil || got != c.want {
			t.Errorf("Serialize(%q, %+v) = %q, %v; want %q", c.name, c.opt, got, err, c.want)
		}
	}
	tooLong := maxCookieAge + 1
	if _, err := Serialize("a", "v", Options{MaxAge: &tooLong}, now); !errors.Is(err, ErrTooLong) {
		t.Errorf("Max-Age past 400 days: %v", err)
	}
	if _, err := Serialize("a", "v", Options{Expires: now.Add(401 * 24 * time.Hour)}, now); !errors.Is(err, ErrTooLong) {
		t.Errorf("Expires past 400 days: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"a=1; b=2", `a="x"`, "a=%E0", ";=;", "a=1;;b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		for k := range Parse(header) {
			if strings.ContainsRune(k, ';') {
				t.Fatalf("key %q spans a cookie separator", k)
			}
		}
	})
}

func FuzzGetSigned(f *testing.F) {
	secret := []byte("fuzz-secret")
	f.Add("tok", "st=junk")
	f.Add("a.b.c", "st=a.b")
	f.Fuzz(func(t *testing.T, value, header string) {
		// Arbitrary headers never panic and never validate without the secret.
		if v, s := GetSigned(Parse(header), "st", NoPrefix, secret); s == Valid && !strings.Contains(header, v) && !strings.Contains(header, "%") {
			t.Fatalf("valid result %q does not come from the header", v)
		}
		// A value signed here reads back unchanged. JavaScript strings are
		// always valid Unicode; an invalid byte encodes to an escape that
		// decodeURIComponent refuses, so the round trip only holds for UTF-8.
		if value == "" || !utf8.ValidString(value) {
			return
		}
		signed, err := SignValue(value, secret)
		if err != nil {
			t.Fatal(err)
		}
		got, s := GetSigned(map[string]string{"st": mustDecode(t, signed)}, "st", NoPrefix, secret)
		if s != Valid || got != value {
			t.Fatalf("round trip of %q = %q, %d", value, got, s)
		}
	})
}

func mustDecode(t *testing.T, s string) string {
	t.Helper()
	return Parse("x=" + s)["x"]
}
