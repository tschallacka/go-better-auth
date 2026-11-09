package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt seals plaintext with a key derived from secret and returns the bare hex of
// nonce || ciphertext || tag, as better-auth does for a plain string secret.
func Encrypt(secret, plaintext string, random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("cipher: nil random source")
	}
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", fmt.Errorf("cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", fmt.Errorf("cipher: nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(sealed), nil
}

// Decrypt opens the bare hex written by Encrypt. Versioned "$ba$" envelopes are refused,
// and a wrong key or tampered data returns an error with no plaintext.
func Decrypt(secret, data string) (string, error) {
	if strings.HasPrefix(data, "$ba$") {
		return "", errors.New("cipher: versioned envelope is not supported")
	}
	raw, err := hex.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("cipher: decode: %w", err)
	}
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", fmt.Errorf("cipher: %w", err)
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("cipher: data too short")
	}
	nonce, sealed := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", errors.New("cipher: authentication failed")
	}
	return string(plain), nil
}
