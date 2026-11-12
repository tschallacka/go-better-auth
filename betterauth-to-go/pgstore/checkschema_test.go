package pgstore_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

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
