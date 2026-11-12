package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
)

func TestVerifiesLibraryHashes(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, h := range v.PasswordHashes {
		ok, err := VerifyPassword(h.Hash, h.Password)
		if err != nil || !ok {
			t.Errorf("VerifyPassword(%q) = %v, %v; want true", h.Password, ok, err)
		}
	}
	for _, c := range v.PasswordChecks {
		ok, err := VerifyPassword(c.Hash, c.Password)
		if err != nil || ok != c.OK {
			t.Errorf("VerifyPassword(%q) = %v, %v; library said %v", c.Password, ok, err, c.OK)
		}
	}
}

var hashFormat = regexp.MustCompile(`^[0-9a-f]{32}:[0-9a-f]{128}$`)

func TestHashPassword(t *testing.T) {
	h, err := HashPassword(rand.Reader, "s3cret pässword")
	if err != nil {
		t.Fatal(err)
	}
	if !hashFormat.MatchString(h) {
		t.Fatalf("hash %q is not saltHex:keyHex", h)
	}
	if ok, _ := VerifyPassword(h, "s3cret pässword"); !ok {
		t.Error("own hash does not verify")
	}
	if ok, _ := VerifyPassword(h, "s3cret password"); ok {
		t.Error("wrong password verified")
	}
	h2, _ := HashPassword(rand.Reader, "s3cret pässword")
	if h == h2 {
		t.Error("two hashes of one password are equal; salt is not random")
	}
}

func TestHashPasswordNeedsRandomness(t *testing.T) {
	if _, err := HashPassword(bytes.NewReader(make([]byte, 5)), "x"); err == nil {
		t.Error("short random source accepted")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	for _, h := range []string{"", "nocolon", ":key", "salt:", ":"} {
		if _, err := VerifyPassword(h, "x"); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("VerifyPassword(%q) error = %v; want ErrInvalidHash", h, err)
		}
	}
	v := testvectors.LoadCrypto(t)
	h := v.PasswordHashes[0]
	// The library splits on ":" and reads the first two parts only.
	if ok, err := VerifyPassword(h.Hash+":trailing", h.Password); err != nil || !ok {
		t.Errorf("hash with a trailing part = %v, %v; want true like the library", ok, err)
	}
	upper := strings.ToUpper(h.Hash)
	if ok, _ := VerifyPassword(upper, h.Password); ok {
		t.Error("uppercase key verified; the library compares lowercase hex text")
	}
}

func TestDecryptsLibraryCiphertexts(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, s := range v.Symmetric {
		got, err := Decrypt(s.Secret, s.Ciphertext)
		if err != nil || got != s.Plaintext {
			t.Errorf("Decrypt(%q) = %q, %v; want %q", s.Ciphertext, got, err, s.Plaintext)
		}
		if _, err := Decrypt(s.Secret+"x", s.Ciphertext); !errors.Is(err, ErrDecrypt) {
			t.Errorf("wrong secret: error = %v; want ErrDecrypt", err)
		}
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	for _, p := range []string{"", "JBSWY3DPEHPK3PXP", "ünïcödé"} {
		ct, err := Encrypt(rand.Reader, "secret", p)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != 2*(24+len(p)+16) {
			t.Errorf("ciphertext length %d; want hex of nonce+plaintext+tag", len(ct))
		}
		got, err := Decrypt("secret", ct)
		if err != nil || got != p {
			t.Errorf("round trip of %q = %q, %v", p, got, err)
		}
	}
}

func TestDecryptRejectsDamage(t *testing.T) {
	ct, _ := Encrypt(rand.Reader, "secret", "payload")
	flip := []byte(ct)
	if flip[60] == '0' {
		flip[60] = '1'
	} else {
		flip[60] = '0'
	}
	for name, data := range map[string]string{
		"flipped":   string(flip),
		"truncated": ct[:len(ct)-2],
		"odd hex":   ct[:len(ct)-1],
		"not hex":   "zz" + ct[2:],
		"too short": ct[:40],
		"empty":     "",
	} {
		if _, err := Decrypt("secret", data); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: error = %v; want ErrDecrypt", name, err)
		}
	}
}

func keyringFrom(keys map[string]string, current int64, legacy string) Keyring {
	k := Keyring{Keys: map[int64]string{}, Current: current, Legacy: legacy}
	for s, secret := range keys {
		n, _ := strconv.ParseInt(s, 10, 64)
		k.Keys[n] = secret
	}
	return k
}

func TestKeyringReadsLibraryPayloads(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, s := range v.SymmetricVersioned {
		k := keyringFrom(s.Keys, s.CurrentVersion, s.LegacySecret)
		got, err := k.Decrypt(s.Ciphertext)
		if err != nil || got != s.Decrypted {
			t.Errorf("Keyring.Decrypt(%q) = %q, %v; want %q", s.Ciphertext, got, err, s.Decrypted)
		}
		ct, err := k.Encrypt(rand.Reader, s.Plaintext)
		if err != nil || !strings.HasPrefix(ct, "$ba$"+strconv.FormatInt(s.CurrentVersion, 10)+"$") {
			t.Errorf("Keyring.Encrypt = %q, %v", ct, err)
		}
		if got, err := k.Decrypt(ct); err != nil || got != s.Plaintext {
			t.Errorf("round trip = %q, %v", got, err)
		}
	}
}

func TestKeyringFailures(t *testing.T) {
	k := Keyring{Keys: map[int64]string{1: "one"}, Current: 2}
	if _, err := k.Encrypt(rand.Reader, "x"); err == nil {
		t.Error("encrypting under a missing current version succeeded")
	}
	k.Current = 1
	ct, _ := k.Encrypt(rand.Reader, "x")
	retired := Keyring{Keys: map[int64]string{2: "two"}, Current: 2}
	if _, err := retired.Decrypt(ct); err == nil {
		t.Error("payload of a retired version decrypted")
	}
	bare, _ := Encrypt(rand.Reader, "legacy", "x")
	if _, err := retired.Decrypt(bare); err == nil {
		t.Error("bare payload decrypted without a legacy secret")
	}
}

func TestParseEnvelope(t *testing.T) {
	for _, c := range []struct {
		in      string
		ok      bool
		version int64
		ct      string
	}{
		{"$ba$2$abcd", true, 2, "abcd"},
		{"$ba$2abc$abcd", true, 2, "abcd"}, // parseInt reads the leading digits
		{"$ba$ 3$abcd", true, 3, "abcd"},   // and skips leading whitespace
		{"$ba$+4$abcd", true, 4, "abcd"},
		{"$ba$-0$abcd", true, 0, "abcd"},
		{"$ba$-1$abcd", false, 0, ""},
		{"$ba$$abcd", false, 0, ""},
		{"$ba$x$abcd", false, 0, ""},
		{"$ba$3", false, 0, ""},
		{"abcd", false, 0, ""},
		{"$ba$1$a$b", true, 1, "a$b"},
		{"$ba$99999999999999999999$ab", true, -1, "ab"},
	} {
		env, ok := ParseEnvelope(c.in)
		if ok != c.ok || (ok && (env.Version != c.version || env.Ciphertext != c.ct)) {
			t.Errorf("ParseEnvelope(%q) = %+v, %v; want version %d, %q, %v", c.in, env, ok, c.version, c.ct, c.ok)
		}
	}
}

func TestSignMatchesLibrary(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, s := range v.Signatures {
		if got := Sign(s.Value, []byte(s.Secret)); got != s.Signature {
			t.Errorf("Sign(%q) = %q; library %q", s.Value, got, s.Signature)
		}
		if !VerifySignature(s.Signature, s.Value, []byte(s.Secret)) {
			t.Errorf("VerifySignature rejects the library's signature of %q", s.Value)
		}
		if VerifySignature(s.Signature, s.Value+"x", []byte(s.Secret)) {
			t.Errorf("VerifySignature accepts a signature for another value")
		}
	}
}

func TestConstantTimeEqualMatchesLibrary(t *testing.T) {
	v := testvectors.LoadCrypto(t)
	for _, c := range v.ConstantTimeEqual {
		if got := ConstantTimeEqual(c.A, c.B); got != c.Equal {
			t.Errorf("ConstantTimeEqual(%q, %q) = %v; library %v", c.A, c.B, got, c.Equal)
		}
	}
}

func TestRandomString(t *testing.T) {
	s, err := RandomString(rand.Reader, 32, DefaultAlphabet)
	if err != nil || len(s) != 32 {
		t.Fatalf("RandomString = %q, %v", s, err)
	}
	for _, c := range s {
		if !strings.ContainsRune(DefaultAlphabet, c) {
			t.Fatalf("character %q is outside the alphabet", c)
		}
	}
	if _, err := RandomString(rand.Reader, 0, DefaultAlphabet); err == nil {
		t.Error("length 0 accepted")
	}
}

func TestRandomStringRejectsBiasedBytes(t *testing.T) {
	// Alphabet of 3: bytes 0..254 are usable (maxValid 255), 255 is rejected.
	src := bytes.NewReader([]byte{255, 255, 0, 4, 255, 255, 255, 255, 2, 7, 0, 0})
	got, err := RandomString(src, 2, "abc")
	if err != nil {
		t.Fatal(err)
	}
	// First buffer of 4 bytes: 255 and 255 rejected, 0 -> a, 4 -> b.
	if got != "ab" {
		t.Errorf("RandomString = %q; want ab", got)
	}
	got, err = RandomString(bytes.NewReader([]byte{255, 255, 255, 255, 2, 7, 0, 0}), 2, "abc")
	if err != nil || got != "cb" {
		t.Errorf("refill across buffers = %q, %v; want cb", got, err)
	}
}
