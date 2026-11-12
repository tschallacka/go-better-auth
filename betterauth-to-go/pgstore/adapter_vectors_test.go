package pgstore_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/migrations"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
)

type adapterVectors struct {
	Generator string `json:"generator"`
	Seed      string `json:"seed"`
	Queries   []struct {
		Name  string `json:"name"`
		Where []struct {
			Field     string          `json:"field"`
			Operator  string          `json:"operator"`
			Value     json.RawMessage `json:"value"`
			Mode      string          `json:"mode"`
			Connector string          `json:"connector"`
		} `json:"where"`
		Options struct {
			SortBy *struct {
				Field     string `json:"field"`
				Direction string `json:"direction"`
			} `json:"sortBy"`
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		} `json:"options"`
		IDs   []string `json:"ids"`
		Count *int64   `json:"count"`
		Error string   `json:"error"`
	} `json:"queries"`
}

// Where the Go store deliberately returns something else, and why.
var adapterDivergences = map[string][]string{
	"contains wildcards (D13)":   {"u3"},
	"starts with wildcard (D13)": {"u3"},
}

func decodeValue(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var d struct {
		Date *string `json:"$date"`
	}
	if json.Unmarshal(raw, &d) == nil && d.Date != nil {
		ts, err := time.Parse(time.RFC3339, *d.Date)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v // string, bool, nil or []any
}

// TestMatchesLibraryAdapter runs the queries testdata/gen/adapter-vectors.mjs
// put through better-auth's own adapter, over the same rows, and expects the
// same rows back.
func TestMatchesLibraryAdapter(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testvectors.FixturesDir(), "adapter-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v adapterVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Generator != "better-auth 1.6.14" {
		t.Fatalf("vectors from %q", v.Generator)
	}
	pool := testdb.Fresh(t)
	core, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, pool, core)
	testdb.Exec(t, pool, v.Seed)
	s := pgstore.New(pool)

	for _, q := range v.Queries {
		var where []betterauth.Where
		for _, c := range q.Where {
			where = append(where, betterauth.Where{
				Column:      c.Field,
				Operator:    betterauth.Operator(c.Operator),
				Value:       decodeValue(t, c.Value),
				Insensitive: c.Mode == "insensitive",
				Connector:   betterauth.Connector(c.Connector),
			})
		}
		opt := betterauth.FindOptions{Limit: q.Options.Limit, Offset: q.Options.Offset}
		if sb := q.Options.SortBy; sb != nil {
			opt.Sort = &betterauth.Sort{Column: sb.Field, Desc: sb.Direction == "desc"}
		}
		rows, err := s.FindMany(ctx, "user", where, opt)
		if q.Error != "" {
			if err == nil {
				t.Errorf("%s: returned %v; the library's query failed (%s)", q.Name, ids(t, rows), q.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v; the library returned %v", q.Name, err, q.IDs)
			continue
		}
		got := make([]string, len(rows))
		for i, r := range rows {
			got[i] = r["id"].(string)
		}
		if opt.Sort == nil {
			sort.Strings(got)
		}
		want := q.IDs
		if d, ok := adapterDivergences[q.Name]; ok {
			want = d
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %v; library %v", q.Name, got, q.IDs)
		}
		if opt.Sort == nil && opt.Limit == 0 && q.Count != nil {
			if n, err := s.Count(ctx, "user", where); err != nil || (n != *q.Count && adapterDivergences[q.Name] == nil) {
				t.Errorf("%s: count %d, %v; library %d", q.Name, n, err, *q.Count)
			}
		}
	}
}
