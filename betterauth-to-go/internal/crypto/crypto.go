// Package crypto holds the primitives better-auth 1.6.14 writes to storage
// and to cookies, in formats both implementations can read: scrypt password
// hashes, XChaCha20-Poly1305 secrets, HMAC-SHA256 signatures and random
// identifiers. Every function takes its random source explicitly.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/jsuri"
)

// scrypt parameters of @better-auth/utils/password 0.4.1.
const (
	scryptN      = 16384
	scryptR      = 16
	scryptP      = 1
	scryptKeyLen = 64
	saltLen      = 16
)

// ErrInvalidHash is returned for a stored hash that is not "salt:key".
var ErrInvalidHash = errors.New("crypto: invalid password hash")

// HashPassword returns "saltHex:keyHex". The salt is 16 random bytes rendered
// as 32 hex characters, and that hex text (not the raw bytes) is the scrypt
// salt, exactly as the library does.
func HashPassword(rand io.Reader, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return "", fmt.Errorf("crypto: reading salt: %w", err)
	}
	saltHex := hex.EncodeToString(salt)
	key, err := passwordKey(password, saltHex)
	if err != nil {
		return "", err
	}
	return saltHex + ":" + hex.EncodeToString(key), nil
}

// VerifyPassword reports whether password matches hash. Like the library it
// splits on ":" and uses the first two parts, so trailing parts are ignored.
// Unlike the library (D12) the hex keys are compared in constant time.
func VerifyPassword(hash, password string) (bool, error) {
	parts := strings.Split(hash, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return false, ErrInvalidHash
	}
	key, err := passwordKey(password, parts[0])
	if err != nil {
		return false, err
	}
	return ConstantTimeEqual(hex.EncodeToString(key), parts[1]), nil
}

func passwordKey(password, salt string) ([]byte, error) {
	key, err := scrypt.Key([]byte(norm.NFKC.String(password)), []byte(salt), scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: scrypt: %w", err)
	}
	return key, nil
}

// ConstantTimeEqual compares two strings without an early exit.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ErrDecrypt covers every failure to open a symmetric payload.
var ErrDecrypt = errors.New("crypto: cannot decrypt")

func symmetricKey(secret string) []byte {
	k := sha256.Sum256([]byte(secret))
	return k[:]
}

// Encrypt seals plaintext with XChaCha20-Poly1305 under SHA-256(secret) and
// returns hex(nonce || ciphertext || tag), the library's bare-hex format.
func Encrypt(rand io.Reader, secret, plaintext string) (string, error) {
	aead, err := chacha20poly1305.NewX(symmetricKey(secret))
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return "", fmt.Errorf("crypto: reading nonce: %w", err)
	}
	return hex.EncodeToString(aead.Seal(nonce, nonce, jsuri.EncodeUTF8(plaintext), nil)), nil
}

// Decrypt opens a bare-hex payload written by Encrypt or by the library.
func Decrypt(secret, data string) (string, error) {
	raw, err := hex.DecodeString(data)
	if err != nil {
		return "", ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(symmetricKey(secret))
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return "", ErrDecrypt
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", ErrDecrypt
	}
	return jsuri.DecodeUTF8(plain), nil
}

// envelopePrefix marks a versioned payload: "$ba$<version>$<hex>".
const envelopePrefix = "$ba$"

// Envelope is a parsed versioned payload.
type Envelope struct {
	Version    int64
	Ciphertext string
}

// ParseEnvelope mirrors the library's parseEnvelope, including its use of
// parseInt: "$ba$2abc$..." is version 2 and "$ba$-0$..." is version 0.
func ParseEnvelope(data string) (Envelope, bool) {
	if !strings.HasPrefix(data, envelopePrefix) {
		return Envelope{}, false
	}
	rest := data[len(envelopePrefix):]
	sep := strings.IndexByte(rest, '$')
	if sep == -1 {
		return Envelope{}, false
	}
	v, negative, ok, overflow := jsuri.ParseInt(rest[:sep])
	if !ok || (negative && v != 0) {
		return Envelope{}, false
	}
	if overflow {
		v = -1 // a version no keyring can hold
	}
	return Envelope{Version: v, Ciphertext: rest[sep+1:]}, true
}

// Keyring is the library's versioned secret configuration: payloads are
// written under Current and read under the version their envelope names.
// Legacy, when set, reads bare-hex payloads written before versioning.
type Keyring struct {
	Keys    map[int64]string
	Current int64
	Legacy  string
}

// Encrypt writes "$ba$<Current>$<hex>".
func (k Keyring) Encrypt(rand io.Reader, plaintext string) (string, error) {
	secret := k.Keys[k.Current]
	if secret == "" {
		return "", fmt.Errorf("crypto: secret version %d not found in keys", k.Current)
	}
	ct, err := Encrypt(rand, secret, plaintext)
	if err != nil {
		return "", err
	}
	return envelopePrefix + strconv.FormatInt(k.Current, 10) + "$" + ct, nil
}

// Decrypt reads an envelope under its own version, or a bare-hex payload under
// Legacy.
func (k Keyring) Decrypt(data string) (string, error) {
	if env, ok := ParseEnvelope(data); ok {
		secret := k.Keys[env.Version]
		if secret == "" {
			return "", fmt.Errorf("crypto: secret version %d not found in keys", env.Version)
		}
		return Decrypt(secret, env.Ciphertext)
	}
	if k.Legacy != "" {
		return Decrypt(k.Legacy, data)
	}
	return "", errors.New("crypto: bare-hex payload and no legacy secret")
}

// ErrEmptySecret is returned for a zero-length signing key. The library
// cannot sign or verify with one either (WebCrypto rejects it), and an empty
// HMAC key would let anyone mint valid signatures.
var ErrEmptySecret = errors.New("crypto: empty secret")

// Sign returns base64(HMAC-SHA256(secret, value)), standard alphabet with
// padding, as makeSignature does.
func Sign(value string, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", ErrEmptySecret
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifySignature reports whether sig, decoded the way atob decodes it, is the
// HMAC of value. Any decoding failure, and an empty secret, is a mismatch.
func VerifySignature(sig, value string, secret []byte) bool {
	if len(secret) == 0 {
		return false
	}
	got, err := jsuri.Atob(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return hmac.Equal(got, mac.Sum(nil))
}

// Alphabets of createRandomStringGenerator.
const (
	LowerAlpha = "abcdefghijklmnopqrstuvwxyz"
	UpperAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits     = "0123456789"
	DashUnder  = "-_"
)

// DefaultAlphabet is generateRandomString's: a-z, 0-9, A-Z, -_ in that order.
const DefaultAlphabet = LowerAlpha + Digits + UpperAlpha + DashUnder

// RandomString draws length characters from alphabet by rejection sampling,
// with no modulo bias, as createRandomStringGenerator does.
func RandomString(rand io.Reader, length int, alphabet string) (string, error) {
	if length <= 0 {
		return "", errors.New("crypto: length must be a positive integer")
	}
	if alphabet == "" || len(alphabet) > 256 {
		return "", errors.New("crypto: alphabet must hold 1 to 256 characters")
	}
	maxValid := (256 / len(alphabet)) * len(alphabet)
	out := make([]byte, 0, length)
	buf := make([]byte, length*2)
	idx := len(buf)
	for len(out) < length {
		if idx >= len(buf) {
			if _, err := io.ReadFull(rand, buf); err != nil {
				return "", fmt.Errorf("crypto: reading random bytes: %w", err)
			}
			idx = 0
		}
		r := int(buf[idx])
		idx++
		if r < maxValid {
			out = append(out, alphabet[r%len(alphabet)])
		}
	}
	return string(out), nil
}
