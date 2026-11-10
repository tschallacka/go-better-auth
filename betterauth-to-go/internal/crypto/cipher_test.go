package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// Vectors made with the real better-auth 1.6.14 symmetricEncrypt (string key), made-up secret.
const (
	testSecret  = "made-up-secret-for-wynn-vectors-0001"
	realVectorA = "d1292b06ef676b8bf31401f9b75b88e2b4082871ecfe1cab4b22696752291d492924df595050d4f748c0058b478a6b97a18816f02badbe646b49"
	plainA      = "hello, better-auth"
	realVectorB = "35e19ac3c30640e21816447066954eea836e6aa1a7b54ad64afa90717f8f1cee4241f3516c2719ce77045f8129571305d4c3044ac9299be51cedfbdc2163dfe67075c86db181aef20ee96128b3699b5886dbb4e485fea212879760d5dfd2"
	plainB      = "naïve ✓ 42 and a longer line of text to span blocks"
)

func TestCipherCompat(t *testing.T) {
	vectors := []struct{ hex, plain string }{{realVectorA, plainA}, {realVectorB, plainB}}

	t.Run("real library vectors decrypt to the original text", func(t *testing.T) {
		for _, v := range vectors {
			got, err := Decrypt(testSecret, v.hex)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if got != v.plain {
				t.Fatalf("Decrypt = %q, want %q", got, v.plain)
			}
		}
	})

	t.Run("encrypt then decrypt round trip", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{7}, 24)
		ct, err := Encrypt(testSecret, plainB, bytes.NewReader(nonce))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if want := 2 * (24 + len(plainB) + 16); len(ct) != want {
			t.Fatalf("Encrypt length = %d hex chars, want %d", len(ct), want)
		}
		got, err := Decrypt(testSecret, ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != plainB {
			t.Fatalf("Decrypt = %q, want %q", got, plainB)
		}
	})

	t.Run("encrypt refuses a nil random source", func(t *testing.T) {
		if _, err := Encrypt(testSecret, plainA, nil); err == nil {
			t.Fatal("Encrypt with nil random source: want error")
		}
	})

	t.Run("tampered data fails with no plaintext", func(t *testing.T) {
		for _, v := range vectors {
			pos := len(v.hex) / 2
			flipped := v.hex[:pos] + "0" + v.hex[pos+1:]
			if v.hex[pos] == '0' {
				flipped = v.hex[:pos] + "1" + v.hex[pos+1:]
			}
			got, err := Decrypt(testSecret, flipped)
			if err == nil {
				t.Fatal("Decrypt of a flipped byte: want error")
			}
			if got != "" {
				t.Fatalf("Decrypt of a flipped byte returned plaintext %q", got)
			}
		}
	})

	t.Run("truncated data fails", func(t *testing.T) {
		for _, v := range vectors {
			if _, err := Decrypt(testSecret, v.hex[:len(v.hex)-2]); err == nil {
				t.Fatal("Decrypt of data missing its last byte: want error")
			}
		}
		if _, err := Decrypt(testSecret, realVectorA[:60]); err == nil {
			t.Fatal("Decrypt of data shorter than nonce and tag: want error")
		}
		if _, err := Decrypt(testSecret, ""); err == nil {
			t.Fatal("Decrypt of empty data: want error")
		}
	})

	t.Run("wrong secret fails", func(t *testing.T) {
		if _, err := Decrypt("made-up-other-secret-0002", realVectorA); err == nil {
			t.Fatal("Decrypt with wrong secret: want error")
		}
	})

	t.Run("non-hex data fails", func(t *testing.T) {
		if _, err := Decrypt(testSecret, "zz"+realVectorA); err == nil {
			t.Fatal("Decrypt of non-hex data: want error")
		}
	})

	t.Run("versioned envelope is refused", func(t *testing.T) {
		if _, err := Decrypt(testSecret, "$ba$1$"+realVectorA); err == nil || !strings.Contains(err.Error(), "versioned") {
			t.Fatalf("Decrypt of versioned envelope: err = %v, want versioned refusal", err)
		}
	})
}
