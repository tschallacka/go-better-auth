// Package cookie parses and writes cookies exactly as better-call 1.3.5 does,
// so a cookie set by either implementation is read the same way by the other.
package cookie

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/crypto"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/jsuri"
)

// Name prefixes.
const (
	SecurePrefix = "__Secure-"
	HostPrefix   = "__Host-"
)

// Prefix selects a name prefix the way better-call's prefix option does.
type Prefix string

// Prefix values. Any other value makes a lookup find nothing.
const (
	NoPrefix     Prefix = ""
	PrefixSecure Prefix = "secure"
	PrefixHost   Prefix = "host"
)

// maxCookieAge is the 400-day cap better-call enforces.
const maxCookieAge = 34560000

// ErrTooLong is returned for a Max-Age or Expires past 400 days.
var ErrTooLong = errors.New("cookie: lifetime longer than 400 days")

// Options mirrors better-call's CookieOptions.
type Options struct {
	Prefix      Prefix
	MaxAge      *int // nil means unset; zero is a valid Max-Age
	Domain      string
	Path        string
	Expires     time.Time // zero means unset
	HTTPOnly    bool
	Secure      bool
	SameSite    string // "lax", "strict" or "none"; first letter is upper-cased on output
	Partitioned bool
}

// Key applies prefix to name. ok is false for an unknown prefix.
func Key(name string, prefix Prefix) (key string, ok bool) {
	switch prefix {
	case NoPrefix:
		return name, true
	case PrefixSecure:
		return SecurePrefix + name, true
	case PrefixHost:
		return HostPrefix + name, true
	}
	return "", false
}

// Parse reads a Cookie header the way better-call's parseCookies does: the
// first occurrence of a name wins, one pair of surrounding quotes is dropped,
// and a value containing '%' is URI-decoded unless decoding fails, in which
// case it is kept as written.
func Parse(header string) map[string]string {
	cookies := map[string]string{}
	index := 0
	for index < len(header) {
		eq := indexFrom(header, '=', index)
		if eq == -1 {
			break
		}
		end := indexFrom(header, ';', index)
		if end == -1 {
			end = len(header)
		} else if end < eq {
			index = strings.LastIndexByte(header[:eq], ';') + 1
			continue
		}
		key := jsuri.Trim(header[index:eq])
		if _, seen := cookies[key]; !seen {
			val := jsuri.Trim(header[eq+1 : end])
			if strings.HasPrefix(val, `"`) {
				if len(val) >= 2 {
					val = val[1 : len(val)-1]
				} else {
					val = ""
				}
			}
			cookies[key] = tryDecode(val)
		}
		index = end + 1
	}
	return cookies
}

func indexFrom(s string, c byte, from int) int {
	i := strings.IndexByte(s[from:], c)
	if i == -1 {
		return -1
	}
	return from + i
}

func tryDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	d, err := jsuri.DecodeURIComponent(s)
	if err != nil {
		return s
	}
	return d
}

// Serialize writes a Set-Cookie value with the value URI-encoded.
func Serialize(name, value string, opt Options, now time.Time) (string, error) {
	return serialize(name, jsuri.EncodeURIComponent(value), opt, now)
}

// SerializeSigned writes "value.signature", URI-encoded, as setSignedCookie
// does.
func SerializeSigned(name, value string, secret []byte, opt Options, now time.Time) (string, error) {
	signed, err := SignValue(value, secret)
	if err != nil {
		return "", err
	}
	return serialize(name, signed, opt, now)
}

// SignValue returns the encoded "value.signature" a signed cookie carries.
func SignValue(value string, secret []byte) (string, error) {
	sig, err := crypto.Sign(value, secret)
	if err != nil {
		return "", err
	}
	return jsuri.EncodeURIComponent(value + "." + sig), nil
}

// serialize follows better-call's _serialize line by line, including its
// quirks: the __Secure-/__Host- name rules look at the name as given, not at
// the prefix option, and Partitioned sets Secure only after Secure has been
// written, so it never appears from Partitioned alone.
func serialize(name, value string, opt Options, now time.Time) (string, error) {
	var b strings.Builder
	switch opt.Prefix {
	case PrefixSecure:
		b.WriteString(SecurePrefix + name + "=" + value)
	case PrefixHost:
		b.WriteString(HostPrefix + name + "=" + value)
	default:
		b.WriteString(name + "=" + value)
	}
	if strings.HasPrefix(name, SecurePrefix) {
		opt.Secure = true
	}
	if strings.HasPrefix(name, HostPrefix) {
		opt.Secure = true
		opt.Path = "/"
		opt.Domain = ""
	}
	if opt.MaxAge != nil && *opt.MaxAge >= 0 {
		if *opt.MaxAge > maxCookieAge {
			return "", ErrTooLong
		}
		b.WriteString("; Max-Age=" + strconv.Itoa(*opt.MaxAge))
	}
	if opt.Domain != "" && opt.Prefix != PrefixHost {
		b.WriteString("; Domain=" + opt.Domain)
	}
	if opt.Path != "" {
		b.WriteString("; Path=" + opt.Path)
	}
	if !opt.Expires.IsZero() {
		if opt.Expires.Sub(now) > maxCookieAge*time.Second {
			return "", ErrTooLong
		}
		b.WriteString("; Expires=" + opt.Expires.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}
	if opt.HTTPOnly {
		b.WriteString("; HttpOnly")
	}
	if opt.Secure {
		b.WriteString("; Secure")
	}
	if opt.SameSite != "" {
		b.WriteString("; SameSite=" + strings.ToUpper(opt.SameSite[:1]) + opt.SameSite[1:])
	}
	if opt.Partitioned {
		b.WriteString("; Partitioned")
	}
	return b.String(), nil
}

// SignedState is the outcome of reading a signed cookie. better-call returns
// null for Absent, false for Invalid and the value for Valid; callers treat
// Absent and Invalid differently in places, so both are kept.
type SignedState int

// SignedState values.
const (
	Absent SignedState = iota
	Invalid
	Valid
)

// GetSigned reads a signed cookie from parsed cookies as getSignedCookie does.
func GetSigned(cookies map[string]string, name string, prefix Prefix, secret []byte) (string, SignedState) {
	key, ok := Key(name, prefix)
	if !ok {
		return "", Absent
	}
	value := cookies[key]
	if value == "" {
		return "", Absent
	}
	pos := strings.LastIndexByte(value, '.')
	if pos < 1 {
		return "", Absent
	}
	signed, sig := value[:pos], value[pos+1:]
	if jsuri.UTF16Len(sig) != 44 || !strings.HasSuffix(sig, "=") {
		return "", Absent
	}
	if !crypto.VerifySignature(sig, signed, secret) {
		return "", Invalid
	}
	return signed, Valid
}
