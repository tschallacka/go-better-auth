// Package jsuri reproduces the JavaScript built-ins whose exact behaviour is
// visible on better-auth's wire format: encodeURIComponent,
// decodeURIComponent, atob, String.prototype.trim, parseInt and UTF-16
// length. Go's own url and base64 packages differ in edge cases, and those
// differences would change which cookies and envelopes are accepted.
package jsuri

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrURI is the equivalent of JavaScript's URIError.
var ErrURI = errors.New("jsuri: malformed URI sequence")

// ErrBase64 is the equivalent of atob's InvalidCharacterError.
var ErrBase64 = errors.New("jsuri: invalid base64")

const upperHex = "0123456789ABCDEF"

// unreserved reports the characters encodeURIComponent leaves as they are.
func unreserved(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '!', '~', '*', '\'', '(', ')':
		return true
	}
	return false
}

// EncodeURIComponent percent-encodes s as JavaScript does, with uppercase hex.
// A JavaScript string cannot hold invalid UTF-8; a Go string can, and such
// bytes are encoded one by one rather than rejected.
func EncodeURIComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0xF])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func escapedByte(s string, i int) (byte, bool) {
	if i+2 >= len(s) || s[i] != '%' {
		return 0, false
	}
	hi, ok1 := unhex(s[i+1])
	lo, ok2 := unhex(s[i+2])
	return hi<<4 | lo, ok1 && ok2
}

// DecodeURIComponent decodes s as JavaScript does: every %XX sequence is
// decoded, a malformed escape or an escaped byte sequence that is not valid
// UTF-8 (overlong forms and surrogates included) is an error.
func DecodeURIComponent(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}
		first, ok := escapedByte(s, i)
		if !ok {
			return "", ErrURI
		}
		i += 3
		if first < 0x80 {
			b.WriteByte(first)
			continue
		}
		var n int
		switch {
		case first&0xE0 == 0xC0:
			n = 2
		case first&0xF0 == 0xE0:
			n = 3
		case first&0xF8 == 0xF0:
			n = 4
		default:
			return "", ErrURI
		}
		seq := []byte{first}
		for k := 1; k < n; k++ {
			c, ok := escapedByte(s, i)
			if !ok || c&0xC0 != 0x80 {
				return "", ErrURI
			}
			seq = append(seq, c)
			i += 3
		}
		r, size := utf8.DecodeRune(seq)
		if r == utf8.RuneError && size <= 1 {
			return "", ErrURI
		}
		b.Write(seq)
	}
	return b.String(), nil
}

// asciiWhitespace is the set atob strips before decoding.
func asciiWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

// Atob decodes s with the WHATWG forgiving-base64 algorithm used by atob:
// ASCII whitespace is removed, up to two trailing '=' are dropped when the
// length is a multiple of four, and the padding bits of the final character
// are ignored.
func Atob(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !asciiWhitespace(s[i]) {
			clean = append(clean, s[i])
		}
	}
	if len(clean)%4 == 0 {
		if len(clean) > 0 && clean[len(clean)-1] == '=' {
			clean = clean[:len(clean)-1]
			if len(clean) > 0 && clean[len(clean)-1] == '=' {
				clean = clean[:len(clean)-1]
			}
		}
	}
	if len(clean)%4 == 1 {
		return nil, ErrBase64
	}
	for _, c := range clean {
		ok := 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/'
		if !ok {
			return nil, ErrBase64
		}
	}
	out, err := base64.RawStdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil, ErrBase64
	}
	return out, nil
}

// DecodeUTF8 is new TextDecoder().decode(b): a leading byte-order mark is
// dropped and every maximal invalid subpart becomes one U+FFFD, following the
// WHATWG UTF-8 decoder. Go's own conversions group replacements differently.
func DecodeUTF8(b []byte) string {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	return decodeUTF8(b)
}

// decodeUTF8 is the WHATWG decoder without the byte-order-mark step.
func decodeUTF8(b []byte) string {
	var out strings.Builder
	out.Grow(len(b))
	var cp rune
	needed, seen := 0, 0
	lower, upper := byte(0x80), byte(0xBF)
	for i := 0; i < len(b); {
		c := b[i]
		if needed == 0 {
			i++
			switch {
			case c <= 0x7F:
				out.WriteByte(c)
			case 0xC2 <= c && c <= 0xDF:
				needed, cp = 1, rune(c&0x1F)
			case 0xE0 <= c && c <= 0xEF:
				if c == 0xE0 {
					lower = 0xA0
				}
				if c == 0xED {
					upper = 0x9F
				}
				needed, cp = 2, rune(c&0x0F)
			case 0xF0 <= c && c <= 0xF4:
				if c == 0xF0 {
					lower = 0x90
				}
				if c == 0xF4 {
					upper = 0x8F
				}
				needed, cp = 3, rune(c&0x07)
			default:
				out.WriteRune(utf8.RuneError)
			}
			continue
		}
		if c < lower || c > upper {
			// Emit the replacement and reprocess this byte as a fresh start.
			needed, seen, cp = 0, 0, 0
			lower, upper = 0x80, 0xBF
			out.WriteRune(utf8.RuneError)
			continue
		}
		lower, upper = 0x80, 0xBF
		cp = cp<<6 | rune(c&0x3F)
		seen++
		i++
		if seen == needed {
			out.WriteRune(cp)
			needed, seen, cp = 0, 0, 0
		}
	}
	if needed != 0 {
		out.WriteRune(utf8.RuneError)
	}
	return out.String()
}

// EncodeUTF8 is new TextEncoder().encode(s) for a Go string: a JavaScript
// string cannot carry invalid UTF-8, so such bytes are replaced the way
// DecodeUTF8 would read them.
func EncodeUTF8(s string) []byte {
	if utf8.ValidString(s) {
		return []byte(s)
	}
	return []byte(decodeUTF8([]byte(s)))
}

// UTF16Len is a JavaScript string's length for s.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// isJSSpace reports the WhiteSpace and LineTerminator code points that
// String.prototype.trim and parseInt skip.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return 0x2000 <= r && r <= 0x200A
}

// Trim is String.prototype.trim.
func Trim(s string) string {
	return strings.TrimFunc(s, isJSSpace)
}

// ParseInt is parseInt(s, 10) restricted to what callers need: leading
// whitespace is skipped, an optional sign is read, then as many decimal digits
// as follow. ok is false where JavaScript returns NaN. A value that does not
// fit in an int64 reports overflow; JavaScript would return a large float.
func ParseInt(s string) (v int64, negative, ok, overflow bool) {
	s = strings.TrimLeftFunc(s, isJSSpace)
	if s != "" && (s[0] == '+' || s[0] == '-') {
		negative = s[0] == '-'
		s = s[1:]
	}
	digits := 0
	for digits < len(s) && '0' <= s[digits] && s[digits] <= '9' {
		d := int64(s[digits] - '0')
		if v > (1<<63-1-d)/10 {
			overflow = true
		} else if !overflow {
			v = v*10 + d
		}
		digits++
	}
	if digits == 0 {
		return 0, false, false, false
	}
	if negative {
		v = -v
	}
	return v, negative, true, overflow
}
