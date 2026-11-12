// Package testdb gives each test its own throwaway PostgreSQL database on
// the server named by GBA_TEST_DATABASE_URL (see DEVELOPMENT.md). Test code
// only.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fresh creates an empty database, returns a pool on it, and drops it when
// the test ends. Without GBA_TEST_DATABASE_URL the test is skipped, unless
// GBA_REQUIRE_DATABASE=1 (set in CI), which makes that a failure.
func Fresh(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool, _ := FreshURL(t)
	return pool
}

// FreshURL is Fresh that also returns the database's URL, for handing the
// same database to another process.
func FreshURL(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	admin := os.Getenv("GBA_TEST_DATABASE_URL")
	if admin == "" {
		if os.Getenv("GBA_REQUIRE_DATABASE") == "1" {
			t.Fatal("GBA_TEST_DATABASE_URL is not set; run pg-scratch up and export it")
		}
		t.Skip("GBA_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	name := "gba_test_" + hex.EncodeToString(b)

	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connecting to %s: %v", redact(admin), err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	_ = conn.Close(ctx)

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Errorf("dropping test database: %v", err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("dropping test database: %v", err)
		}
	})
	return pool, u.String()
}

// Exec runs one or more SQL statements or fails the test.
func Exec(t testing.TB, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("executing SQL: %v\n%s", err, sql)
	}
}

func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "the configured URL"
	}
	return u.Redacted()
}
