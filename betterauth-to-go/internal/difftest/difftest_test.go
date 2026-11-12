package difftest

import "testing"

func TestNormalize(t *testing.T) {
	in := map[string]any{
		"token": "abc",
		"user":  map[string]any{"id": "u1", "name": "Ann", "image": nil},
		"list":  []any{map[string]any{"id": "x", "role": "owner"}},
		"none":  nil,
	}
	got := Normalize(in, "id", "token", "image", "none")
	want := map[string]any{
		"token": Masked,
		"user":  map[string]any{"id": Masked, "name": "Ann", "image": nil},
		"list":  []any{map[string]any{"id": Masked, "role": "owner"}},
		"none":  nil,
	}
	if d := Diff(got, want); d != "" {
		t.Error(d)
	}
	if Diff(Normalize(map[string]any{"id": "a"}, "id"), Normalize(map[string]any{"id": "b"}, "id")) != "" {
		t.Error("masked values still differ")
	}
	if Diff(Normalize(map[string]any{"id": "a"}, "id"), Normalize(map[string]any{"id": nil}, "id")) == "" {
		t.Error("a present value and a null compare equal after masking")
	}
}
