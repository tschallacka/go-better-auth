// Package idgen makes random identifiers and tokens.
package idgen

import (
	"errors"
	"io"
)

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomString returns n characters drawn from the 62-character alphabet
// a-z, A-Z, 0-9. Bytes at or above the largest multiple of 62 below 256 are
// rejected, so every character is equally likely.
func RandomString(random io.Reader, n int) (string, error) {
	if n < 0 {
		return "", errors.New("idgen: negative length")
	}
	const limit = 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		need := n - len(out)
		if _, err := io.ReadFull(random, buf[:need]); err != nil {
			return "", err
		}
		for _, b := range buf[:need] {
			if int(b) < limit {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
