package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// This test runs against a real Postgres. It is skipped when
// TEST_DATABASE_URL is not set (CI sets it; locally run `docker compose up -d`).
func TestStorePingAndMigrations(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := New(ctx, url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// The first migration must have created the app_meta table.
	var n int
	if err := s.Pool.QueryRow(ctx, "SELECT count(*) FROM app_meta").Scan(&n); err != nil {
		t.Fatalf("query app_meta (did you run `make migrate-up`?): %v", err)
	}
}
