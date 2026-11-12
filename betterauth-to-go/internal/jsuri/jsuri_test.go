package jsuri

import (
	"encoding/hex"
	"strconv"
	"testing"
	"unicode/utf8"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
)

func TestEncodeURIComponentMatchesNode(t *testing.T) {
	for _, c := range testvectors.LoadCrypto(t).Builtins.EncodeURIComponent {
		if got := EncodeURIComponent(c.In); got != c.Out {
			t.Errorf("EncodeURIComponent(%q) = %q; node %q", c.In, got, c.Out)
		}
	}
}

func TestDecodeURIComponentMatchesNode(t *testing.T) {
	for _, c := range testvectors.LoadCrypto(t).Builtins.DecodeURIComponent {
		got, err := DecodeURIComponent(c.In)
		if c.Error != "" {
			if err == nil {
				t.Errorf("DecodeURIComponent(%q) = %q; node threw %s", c.In, got, c.Error)
			}
			continue
		}
		if err != nil || got != c.Value {
			t.Errorf("DecodeURIComponent(%q) = %q, %v; node %q", c.In, got, err, c.Value)
		}
	}
}

func TestAtobMatchesNode(t *testing.T) {
	for _, c := range testvectors.LoadCrypto(t).Builtins.Atob {
		got, err := Atob(c.In)
		if c.Error != "" {
			if err == nil {
				t.Errorf("Atob(%q) = %x; node threw %s", c.In, got, c.Error)
			}
			continue
		}
		if err != nil || hex.EncodeToString(got) != c.Hex {
			t.Errorf("Atob(%q) = %x, %v; node %s", c.In, got, err, c.Hex)
		}
	}
}

func TestParseIntMatchesNode(t *testing.T) {
	for _, c := range testvectors.LoadCrypto(t).Builtins.ParseInt {
		v, _, ok, overflow := ParseInt(c.In)
		if c.Out == nil {
			if ok {
				t.Errorf("ParseInt(%q) = %d; node NaN", c.In, v)
			}
			continue
		}
		if !ok {
			t.Errorf("ParseInt(%q) = NaN; node %s", c.In, *c.Out)
			continue
		}
		if overflow {
			if len(*c.Out) < 19 {
				t.Errorf("ParseInt(%q) overflowed; node %s fits", c.In, *c.Out)
			}
			continue
		}
		if strconv.FormatInt(v, 10) != *c.Out {
			t.Errorf("ParseInt(%q) = %d; node %s", c.In, v, *c.Out)
		}
	}
}

func TestTrimMatchesNode(t *testing.T) {
	for _, c := range testvectors.LoadCrypto(t).Builtins.Trim {
		if got := Trim(c.In); got != c.Out {
			t.Errorf("Trim(%q) = %q; node %q", c.In, got, c.Out)
		}
	}
}

func TestUTF16Len(t *testing.T) {
	for s, want := range map[string]int{"": 0, "abc": 3, "ü": 1, "€": 1, "😀": 2} {
		if got := UTF16Len(s); got != want {
			t.Errorf("UTF16Len(%q) = %d; want %d", s, got, want)
		}
	}
}

func FuzzURIComponentRoundTrip(f *testing.F) {
	for _, s := range []string{"", "a b", "ünï€😀", "%", "-_.!~*'()"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip("JavaScript strings are always valid Unicode")
		}
		got, err := DecodeURIComponent(EncodeURIComponent(s))
		if err != nil || got != s {
			t.Fatalf("round trip of %q = %q, %v", s, got, err)
		}
	})
}

func FuzzDecodeURIComponent(f *testing.F) {
	for _, s := range []string{"%C3%BC", "%E0%A4%A", "%ED%A0%80", "a%zz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := DecodeURIComponent(s)
		if err == nil && utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("decoded %q to invalid UTF-8 %q", s, got)
		}
	})
}

func FuzzAtob(f *testing.F) {
	for _, s := range []string{"YQ==", "YW Jj", "Y", "!!!!"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Atob(s)
	})
}
