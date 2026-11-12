package pgstore_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testdb"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/migrations"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/pgstore"
)

func check(t *testing.T, diffs []pgstore.Difference) []string {
	t.Helper()
	out := make([]string, len(diffs))
	for i, d := range diffs {
		out[i] = d.Table + "." + d.Column + ":" + string(d.Kind)
	}
	sort.Strings(out)
	return out
}

// The library's own DDL for a configuration must satisfy the Go schema built
// for the same configuration, with no differences at all.
func TestCheckSchemaAcceptsLibraryDDL(t *testing.T) {
	for _, name := range testvectors.SchemaScenarios {
		t.Run(name, func(t *testing.T) {
			ddl, err := os.ReadFile(filepath.Join(testvectors.FixturesDir(), "schema", name+".sql"))
			if err != nil {
				t.Fatal(err)
			}
			pool := testdb.Fresh(t)
			testdb.Exec(t, pool, string(ddl))
			s := testvectors.SchemaFor(t, name)
			diffs, err := pgstore.CheckSchema(context.Background(), pool, s)
			if err != nil {
				t.Fatal(err)
			}
			if len(diffs) != 0 {
				t.Errorf("differences on the library's own DDL: %v", check(t, diffs))
			}
		})
	}
}

// The shipped migrations, applied in order, build the phase-A schema.
func TestMigrationsBuildPhaseA(t *testing.T) {
	names := migrations.Names()
	if strings.Join(names, " ") != "0001_core.sql 0002_organization.sql 0003_two_factor.sql 0004_passkey.sql" {
		t.Fatalf("migrations %v", names)
	}
	pool := testdb.Fresh(t)
	ctx := context.Background()
	for i, n := range names {
		sql, err := migrations.Read(n)
		if err != nil {
			t.Fatal(err)
		}
		testdb.Exec(t, pool, sql)
		if i == 0 {
			diffs, err := pgstore.CheckSchema(ctx, pool, testvectors.SchemaFor(t, "core"))
			if err != nil || len(diffs) != 0 {
				t.Errorf("after 0001 the core schema has differences: %v, %v", diffs, err)
			}
		}
	}
	diffs, err := pgstore.CheckSchema(ctx, pool, testvectors.SchemaFor(t, "phase-a"))
	if err != nil || len(diffs) != 0 {
		t.Errorf("after all migrations the phase-A schema has differences: %v, %v", diffs, err)
	}
}

func TestCheckSchemaReportsDrift(t *testing.T) {
	sql, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	pool := testdb.Fresh(t)
	testdb.Exec(t, pool, sql)
	testdb.Exec(t, pool, `
		ALTER TABLE "user" DROP COLUMN "image";
		ALTER TABLE "session" ALTER COLUMN "ipAddress" TYPE integer USING NULL;
		ALTER TABLE "session" ALTER COLUMN "userAgent" SET NOT NULL;
		ALTER TABLE "account" ALTER COLUMN "providerId" DROP NOT NULL;
		ALTER TABLE "session" DROP CONSTRAINT "session_token_key";
		DROP INDEX "account_userId_idx";
		DROP TABLE "verification";`)
	diffs, err := pgstore.CheckSchema(context.Background(), pool, testvectors.SchemaFor(t, "core"))
	if err != nil {
		t.Fatal(err)
	}
	got := check(t, diffs)
	want := []string{
		"account.providerId:missing_not_null",
		"account.userId:missing_index",
		"session.ipAddress:type_mismatch",
		"session.token:missing_unique",
		"session.userAgent:unexpected_not_null",
		"user.image:missing_column",
		"verification.:missing_table", // a table-level difference has no column
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("differences\n got  %v\n want %v", got, want)
	}
	blocking := 0
	for _, d := range diffs {
		if d.Blocking() {
			blocking++
		}
	}
	if blocking != 4 {
		t.Errorf("%d blocking differences; want 4 (missing table, missing column, type, unexpected NOT NULL)", blocking)
	}
}

// Tables are resolved through the whole search_path, as unqualified queries
// are: an empty first schema must not hide tables in a later one.
func TestCheckSchemaFollowsSearchPath(t *testing.T) {
	sql, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	pool := testdb.Fresh(t)
	testdb.Exec(t, pool, sql)
	testdb.Exec(t, pool, `CREATE SCHEMA app; ALTER ROLE CURRENT_USER IN DATABASE `+currentDatabase(t, pool)+` SET search_path = app, public`)
	pool.Reset() // new connections pick up the search_path
	var first string
	if err := pool.QueryRow(context.Background(), "SELECT current_schema()").Scan(&first); err != nil || first != "app" {
		t.Fatalf("current_schema = %q, %v; the test setup did not take", first, err)
	}
	diffs, err := pgstore.CheckSchema(context.Background(), pool, testvectors.SchemaFor(t, "core"))
	if err != nil || len(diffs) != 0 {
		t.Errorf("differences with tables later on the search_path: %v, %v", check(t, diffs), err)
	}
}

func currentDatabase(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) string {
	t.Helper()
	var name string
	if err := pool.QueryRow(context.Background(), "SELECT quote_ident(current_database())").Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

// A composite index led by the column serves lookups on it; a partial unique
// index does not guarantee uniqueness for every row.
func TestCheckSchemaIndexRules(t *testing.T) {
	sql, err := migrations.Read("0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	pool := testdb.Fresh(t)
	testdb.Exec(t, pool, sql)
	testdb.Exec(t, pool, `
		DROP INDEX "account_userId_idx";
		CREATE INDEX "account_user_provider" ON "account" ("userId", "providerId");
		ALTER TABLE "session" DROP CONSTRAINT "session_token_key";
		CREATE UNIQUE INDEX "session_token_partial" ON "session" ("token") WHERE "expiresAt" > '2000-01-01';
		ALTER TABLE "user" DROP CONSTRAINT "user_email_key";
		CREATE UNIQUE INDEX "user_email_name" ON "user" ("email", "name");`)
	diffs, err := pgstore.CheckSchema(context.Background(), pool, testvectors.SchemaFor(t, "core"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(check(t, diffs), " ")
	if got != "session.token:missing_unique user.email:missing_unique" {
		t.Errorf("differences %q; want the partial and the composite unique index rejected, the composite plain index accepted", got)
	}
}
