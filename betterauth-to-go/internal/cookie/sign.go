package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Sign returns the signed cookie value: value, a dot, and the base64 HMAC-SHA256
// of value under secret. The result is percent-encoded like encodeURIComponent.
func Sign(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	raw := value + "." + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Verify checks a value written by Sign and returns it. ok is false for any
// malformed, truncated or tampered input.
func Verify(signed, secret string) (value string, ok bool) {
	raw, err := url.PathUnescape(signed)
	if err != nil {
		return "", false
	}
	i := strings.LastIndexByte(raw, '.')
	if i <= 0 {
		return "", false
	}
	value, sig := raw[:i], raw[i+1:]
	if len(sig) != base64.StdEncoding.EncodedLen(sha256.Size) {
		return "", false
	}
	got, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(got) != sha256.Size || base64.StdEncoding.EncodeToString(got) != sig {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return "", false
	}
	return value, true
}
