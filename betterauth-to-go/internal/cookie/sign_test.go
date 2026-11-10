package cookie

import "testing"

// Vectors are HMAC-SHA256 with the made-up secret below, in the form
// better-auth 1.6.14 writes them (makeSignature: base64 of the MAC, then
// the cookie value percent-encoded).
const testSecret = "made-up-secret-for-tests-0123456789"

const (
	vecValue1  = "tokenABC123"
	vecSigned1 = "tokenABC123.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D"
	vecRaw1    = "tokenABC123.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU="

	vecValue2  = "abc+/=d"
	vecSigned2 = "abc%2B%2F%3Dd.GJNLbpC9b22gVfRXxecP7bhyHtaYhx5UYfy8Jr0dkRY%3D"
	vecRaw2    = "abc+/=d.GJNLbpC9b22gVfRXxecP7bhyHtaYhx5UYfy8Jr0dkRY="
)

func TestSignVerify(t *testing.T) {
	t.Run("sign reproduces vectors", func(t *testing.T) {
		if got := Sign(vecValue1, testSecret); got != vecSigned1 {
			t.Errorf("Sign = %q, want %q", got, vecSigned1)
		}
		if got := Sign(vecValue2, testSecret); got != vecSigned2 {
			t.Errorf("Sign = %q, want %q", got, vecSigned2)
		}
	})

	accept := map[string]struct {
		in    string
		value string
	}{
		"encoded vector":                  {vecSigned1, vecValue1},
		"unencoded = in signature":        {vecRaw1, vecValue1},
		"encoded vector 2":                {vecSigned2, vecValue2},
		"lowercase hex":                   {"abc%2b%2f%3dd.GJNLbpC9b22gVfRXxecP7bhyHtaYhx5UYfy8Jr0dkRY%3d", vecValue2},
		"unencoded = + / left as is":      {vecRaw2, vecValue2},
		"plus stays plus, not a space":    {"abc+/=d.GJNLbpC9b22gVfRXxecP7bhyHtaYhx5UYfy8Jr0dkRY%3D", vecValue2},
		"value with %25 round trips once": {Sign("a%25", testSecret), "a%25"},
	}
	for name, c := range accept {
		t.Run(name, func(t *testing.T) {
			value, ok := Verify(c.in, testSecret)
			if !ok || value != c.value {
				t.Errorf("Verify(%q) = %q, %v; want %q, true", c.in, value, ok, c.value)
			}
		})
	}

	reject := map[string]string{
		"changed value":       "tokenABC124.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D",
		"changed signature":   "tokenABC123.rqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D",
		"truncated signature": "tokenABC123.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9%3D",
		"missing dot":         "tokenABC123qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D",
		"empty string":        "",
		"extra suffix":        vecSigned1 + "x",
		"invalid escape %":    "tokenABC123%.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D",
		"invalid escape %zz":  "tokenABC123%zz.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D",
		"invalid escape %4":   "tokenABC123%4.qqJ3SEReVpc7LgFxEtdfwTOtTE57T4V4yoNxsp9D9uU%3D",
	}
	for name, in := range reject {
		t.Run("rejects "+name, func(t *testing.T) {
			if value, ok := Verify(in, testSecret); ok {
				t.Errorf("Verify(%q) = %q, true; want false", in, value)
			}
		})
	}

	t.Run("rejects wrong secret", func(t *testing.T) {
		if _, ok := Verify(vecSigned1, "made-up-other-secret-0123456789"); ok {
			t.Error("Verify with wrong secret returned true")
		}
	})
}
