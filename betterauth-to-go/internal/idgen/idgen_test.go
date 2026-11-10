package idgen

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failReader struct{ err error }

func (r failReader) Read([]byte) (int, error) { return 0, r.err }

func TestRandomString(t *testing.T) {
	t.Run("length and alphabet", func(t *testing.T) {
		src := make([]byte, 4096)
		for i := range src {
			src[i] = byte(i)
		}
		for _, n := range []int{0, 1, 7, 64, 1000} {
			s, err := RandomString(bytes.NewReader(src), n)
			if err != nil {
				t.Fatalf("n=%d: unexpected error: %v", n, err)
			}
			if len(s) != n {
				t.Fatalf("n=%d: got length %d", n, len(s))
			}
			for _, c := range s {
				if !strings.ContainsRune(alphabet, c) {
					t.Fatalf("n=%d: character %q not in alphabet", n, c)
				}
			}
		}
	})

	t.Run("negative length", func(t *testing.T) {
		if _, err := RandomString(bytes.NewReader(nil), -1); err == nil {
			t.Fatal("expected error for negative length")
		}
	})

	t.Run("reader error propagates", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := RandomString(failReader{boom}, 5); !errors.Is(err, boom) {
			t.Fatalf("got error %v, want %v", err, boom)
		}
	})

	t.Run("short reader fails", func(t *testing.T) {
		if _, err := RandomString(bytes.NewReader([]byte{1}), 2); err == nil {
			t.Fatal("expected error when the reader runs dry")
		}
	})

	t.Run("values at or above 248 are skipped", func(t *testing.T) {
		src := []byte{248, 255, 0, 61, 62}
		got, err := RandomString(bytes.NewReader(src), 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "a9a"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("247 is the last accepted byte", func(t *testing.T) {
		got, err := RandomString(bytes.NewReader([]byte{247}), 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "9"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("no modulo bias over accepted bytes", func(t *testing.T) {
		src := make([]byte, 248)
		for i := range src {
			src[i] = byte(i)
		}
		got, err := RandomString(bytes.NewReader(src), 248)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		counts := make(map[rune]int)
		for _, c := range got {
			counts[c]++
		}
		if len(counts) != len(alphabet) {
			t.Fatalf("got %d distinct characters, want %d", len(counts), len(alphabet))
		}
		for _, c := range alphabet {
			if counts[c] != 4 {
				t.Fatalf("character %q appeared %d times, want 4", c, counts[c])
			}
		}
	})
}
