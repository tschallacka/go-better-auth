package difftest

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNormalizeMasksValuesNotShapes(t *testing.T) {
	in := decode(t, `{"token":"abcdefgh","user":{"id":"u1","createdAt":"2026-11-12T10:00:00.123Z","image":null},"list":[{"id":"x"}],"none":null}`)
	got := Normalize(in, "id", "token", "createdAt", "image", "none")
	want := decode(t, `{"token":"<string:8>","user":{"id":"<string:2>","createdAt":"<iso8601-ms>","image":null},"list":[{"id":"<string:1>"}],"none":null}`)
	if d := Diff(got, want); d != "" {
		t.Error(d)
	}

	same := func(a, b string) bool {
		return Diff(Normalize(decode(t, a), "v"), Normalize(decode(t, b), "v")) == ""
	}
	if !same(`{"v":"aaaa"}`, `{"v":"bbbb"}`) {
		t.Error("two values of the same shape differ after masking")
	}
	for _, c := range [][2]string{
		{`{"v":"2026-11-12T10:00:00.123Z"}`, `{"v":"2026-11-12T10:00:00.123456789Z"}`}, // Go's default time format
		{`{"v":"2026-11-12T10:00:00.123Z"}`, `{"v":"2026-11-12T10:00:00Z"}`},
		{`{"v":"abc"}`, `{"v":""}`},
		{`{"v":"12"}`, `{"v":12}`},
		{`{"v":"abc"}`, `{"v":null}`},
		{`{"v":"abcd"}`, `{"v":"abc"}`},
	} {
		if same(c[0], c[1]) {
			t.Errorf("%s and %s compare equal after masking", c[0], c[1])
		}
	}
}

func TestDiffRefusesUnencodable(t *testing.T) {
	bad := map[string]any{"f": func() {}}
	if d := Diff(bad, bad); !strings.Contains(d, "cannot compare") {
		t.Errorf("Diff of unencodable values = %q; want a failure", d)
	}
}
