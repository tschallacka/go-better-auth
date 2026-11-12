package pgstore_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/migrations"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
)

var ctx = context.Background()

func coreStore(t *testing.T) *pgstore.Store {
	t.Helper()
	pool := testdb.Fresh(t)
	sql, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, pool, sql)
	return pgstore.New(pool)
}

var t0 = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func addUser(t *testing.T, s betterauth.Store, id, name, email string) betterauth.Row {
	t.Helper()
	r, err := s.Create(ctx, "user", betterauth.Row{
		"id": id, "name": name, "email": email, "emailVerified": false,
		"createdAt": t0, "updatedAt": t0,
	})
	if err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
	return r
}

func ids(t *testing.T, rows []betterauth.Row) []string {
	t.Helper()
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r["id"].(string)
	}
	sort.Strings(out)
	return out
}

func findIDs(t *testing.T, s betterauth.Store, where ...betterauth.Where) []string {
	t.Helper()
	rows, err := s.FindMany(ctx, "user", where, betterauth.FindOptions{})
	if err != nil {
		t.Fatalf("FindMany(%+v): %v", where, err)
	}
	return ids(t, rows)
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCreateReturnsTypedRow(t *testing.T) {
	s := coreStore(t)
	r := addUser(t, s, "u1", "Ann", "ann@example.com")
	if r["email"] != "ann@example.com" || r["emailVerified"] != false || r["image"] != nil {
		t.Errorf("row %v", r)
	}
	if ts, ok := r["createdAt"].(time.Time); !ok || !ts.Equal(t0) {
		t.Errorf("createdAt %#v; want time.Time %v", r["createdAt"], t0)
	}
	if _, err := s.Create(ctx, "user", betterauth.Row{"id": "u2", "name": "Dup", "email": "ann@example.com",
		"emailVerified": false, "createdAt": t0, "updatedAt": t0}); err == nil {
		t.Error("duplicate email accepted; the unique constraint is not in force")
	}
}

func TestOperators(t *testing.T) {
	s := coreStore(t)
	addUser(t, s, "u1", "Ann", "Ann@Example.com")
	addUser(t, s, "u2", "Bob", "bob@example.com")
	addUser(t, s, "u3", "50%_off", "c@example.org")
	addUser(t, s, "u4", "50xyoff", "d@example.org")
	if _, err := s.Update(ctx, "user", []betterauth.Where{{Column: "id", Value: "u2"}}, betterauth.Row{"image": "x.png"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		where []betterauth.Where
		want  []string
	}{
		{"eq default", []betterauth.Where{{Column: "name", Value: "Ann"}}, []string{"u1"}},
		{"eq is case sensitive", []betterauth.Where{{Column: "email", Value: "ann@example.com"}}, []string{}},
		{"eq insensitive", []betterauth.Where{{Column: "email", Value: "ann@example.com", Insensitive: true}}, []string{"u1"}},
		{"ne", []betterauth.Where{{Column: "name", Operator: betterauth.Ne, Value: "Ann"}}, []string{"u2", "u3", "u4"}},
		{"eq nil is IS NULL", []betterauth.Where{{Column: "image", Value: nil}}, []string{"u1", "u3", "u4"}},
		{"ne nil is IS NOT NULL", []betterauth.Where{{Column: "image", Operator: betterauth.Ne, Value: nil}}, []string{"u2"}},
		{"in", []betterauth.Where{{Column: "id", Operator: betterauth.In, Value: []string{"u1", "u3", "zz"}}}, []string{"u1", "u3"}},
		{"in insensitive", []betterauth.Where{{Column: "email", Operator: betterauth.In, Value: []string{"ANN@example.COM"}, Insensitive: true}}, []string{"u1"}},
		{"in empty matches nothing", []betterauth.Where{{Column: "id", Operator: betterauth.In, Value: []string{}}}, []string{}},
		{"not in", []betterauth.Where{{Column: "id", Operator: betterauth.NotIn, Value: []string{"u1", "u2"}}}, []string{"u3", "u4"}},
		{"not in empty matches all", []betterauth.Where{{Column: "id", Operator: betterauth.NotIn, Value: []string{}}}, []string{"u1", "u2", "u3", "u4"}},
		{"contains", []betterauth.Where{{Column: "email", Operator: betterauth.Contains, Value: "example.org"}}, []string{"u3", "u4"}},
		{"contains escapes wildcards (D13)", []betterauth.Where{{Column: "name", Operator: betterauth.Contains, Value: "%_"}}, []string{"u3"}},
		{"starts with escapes wildcards", []betterauth.Where{{Column: "name", Operator: betterauth.StartsWith, Value: "50%"}}, []string{"u3"}},
		{"ends with", []betterauth.Where{{Column: "email", Operator: betterauth.EndsWith, Value: ".com"}}, []string{"u1", "u2"}},
		{"contains insensitive", []betterauth.Where{{Column: "email", Operator: betterauth.Contains, Value: "EXAMPLE.COM", Insensitive: true}}, []string{"u1", "u2"}},
		{"gt and lte", []betterauth.Where{
			{Column: "id", Operator: betterauth.Gt, Value: "u1"},
			{Column: "id", Operator: betterauth.Lte, Value: "u3"},
		}, []string{"u2", "u3"}},
		// (AND group) AND (OR group), as the library's adapter combines them.
		{"and with or group", []betterauth.Where{
			{Column: "email", Operator: betterauth.EndsWith, Value: ".org"},
			{Column: "id", Value: "u1", Connector: betterauth.Or},
			{Column: "id", Value: "u4", Connector: betterauth.Or},
		}, []string{"u4"}},
		{"or only", []betterauth.Where{
			{Column: "id", Value: "u1", Connector: betterauth.Or},
			{Column: "id", Value: "u2", Connector: betterauth.Or},
		}, []string{"u1", "u2"}},
	}
	for _, c := range cases {
		if got := findIDs(t, s, c.where...); !eq(got, c.want) {
			t.Errorf("%s: %v; want %v", c.name, got, c.want)
		}
	}
}

func TestInjectionIsInert(t *testing.T) {
	s := coreStore(t)
	addUser(t, s, "u1", "Ann", "a@example.com")
	hostile := `x'); DROP TABLE "user"; --`
	if got := findIDs(t, s, betterauth.Where{Column: "name", Value: hostile}); len(got) != 0 {
		t.Errorf("hostile value matched %v", got)
	}
	if _, err := s.FindMany(ctx, "user", []betterauth.Where{{Column: `name" = 'x' OR "1"="1`, Value: "x"}}, betterauth.FindOptions{}); err == nil {
		t.Error("a hostile column name was accepted as SQL")
	}
	if n, err := s.Count(ctx, "user", nil); err != nil || n != 1 {
		t.Errorf("table damaged: count %d, %v", n, err)
	}
}

func TestFindOptions(t *testing.T) {
	s := coreStore(t)
	for _, id := range []string{"u3", "u1", "u4", "u2"} {
		addUser(t, s, id, "n"+id, id+"@example.com")
	}
	rows, err := s.FindMany(ctx, "user", nil, betterauth.FindOptions{
		Sort: &betterauth.Sort{Column: "id", Desc: true}, Limit: 2, Offset: 1, Select: []string{"id", "email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["id"] != "u3" || rows[1]["id"] != "u2" {
		t.Errorf("sorted page %v; want u3, u2", rows)
	}
	if _, has := rows[0]["name"]; has || len(rows[0]) != 2 {
		t.Errorf("select returned %v; want id and email only", rows[0])
	}
	if _, err := s.FindOne(ctx, "user", []betterauth.Where{{Column: "id", Value: "nope"}}); !errors.Is(err, betterauth.ErrNotFound) {
		t.Errorf("FindOne of nothing: %v; want ErrNotFound", err)
	}
	if n, _ := s.Count(ctx, "user", []betterauth.Where{{Column: "id", Operator: betterauth.Gte, Value: "u2"}}); n != 3 {
		t.Errorf("count %d; want 3", n)
	}
}

func TestUpdateAndDelete(t *testing.T) {
	s := coreStore(t)
	addUser(t, s, "u1", "Same", "a@example.com")
	addUser(t, s, "u2", "Same", "b@example.com")
	addUser(t, s, "u3", "Other", "c@example.com")

	// Update changes every match and returns one, like the library.
	r, err := s.Update(ctx, "user", []betterauth.Where{{Column: "name", Value: "Same"}}, betterauth.Row{"image": "i.png"})
	if err != nil || r["image"] != "i.png" {
		t.Fatalf("Update = %v, %v", r, err)
	}
	if got := findIDs(t, s, betterauth.Where{Column: "image", Value: "i.png"}); !eq(got, []string{"u1", "u2"}) {
		t.Errorf("updated %v; want u1 and u2", got)
	}
	if _, err := s.Update(ctx, "user", []betterauth.Where{{Column: "id", Value: "zz"}}, betterauth.Row{"name": "x"}); !errors.Is(err, betterauth.ErrNotFound) {
		t.Errorf("Update of nothing: %v; want ErrNotFound", err)
	}
	if n, err := s.UpdateMany(ctx, "user", nil, betterauth.Row{"emailVerified": true}); err != nil || n != 3 {
		t.Errorf("UpdateMany = %d, %v", n, err)
	}
	if err := s.Delete(ctx, "user", []betterauth.Where{{Column: "id", Value: "zz"}}); err != nil {
		t.Errorf("Delete of nothing: %v", err)
	}
	if n, err := s.DeleteMany(ctx, "user", []betterauth.Where{{Column: "name", Value: "Same"}}); err != nil || n != 2 {
		t.Errorf("DeleteMany = %d, %v", n, err)
	}
	if _, err := s.Update(ctx, "user", nil, betterauth.Row{}); err == nil {
		t.Error("an update with no data was accepted")
	}
}

func TestCascadeDeletesSessions(t *testing.T) {
	s := coreStore(t)
	addUser(t, s, "u1", "Ann", "a@example.com")
	if _, err := s.Create(ctx, "session", betterauth.Row{"id": "s1", "token": "tok", "userId": "u1",
		"expiresAt": t0.Add(time.Hour), "createdAt": t0, "updatedAt": t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "user", []betterauth.Where{{Column: "id", Value: "u1"}}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count(ctx, "session", nil); n != 0 {
		t.Errorf("%d sessions left after deleting their user", n)
	}
}

func TestTransactions(t *testing.T) {
	s := coreStore(t)
	boom := errors.New("boom")
	err := s.Transaction(ctx, func(tx betterauth.Store) error {
		addUser(t, tx, "u1", "Ann", "a@example.com")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Transaction error %v; want the callback's", err)
	}
	if n, _ := s.Count(ctx, "user", nil); n != 0 {
		t.Error("a rolled-back transaction left a row")
	}

	err = s.Transaction(ctx, func(tx betterauth.Store) error {
		addUser(t, tx, "u1", "Ann", "a@example.com")
		inner := tx.Transaction(ctx, func(tx2 betterauth.Store) error {
			addUser(t, tx2, "u2", "Bob", "b@example.com")
			return boom
		})
		if !errors.Is(inner, boom) {
			t.Errorf("inner error %v", inner)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := findIDs(t, s); !eq(got, []string{"u1"}) {
		t.Errorf("after a rolled-back savepoint: %v; want only u1", got)
	}
}
