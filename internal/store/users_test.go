package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// Runs against a real Postgres with migrations applied. Skipped without TEST_DATABASE_URL.
func TestUsers(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s, err := New(ctx, url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	email := fmt.Sprintf("store-test-%d@example.com", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), "DELETE FROM users WHERE email = $1", email)
	})

	created, err := s.CreateUser(ctx, email, "$argon2id$fake")
	if err != nil {
		t.Fatalf("CreateUser: %v (did you run `make migrate-up`?)", err)
	}
	if created.ID == "" || created.Email != email {
		t.Fatalf("unexpected user: %+v", created)
	}

	if _, err := s.CreateUser(ctx, email, "$argon2id$other"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("duplicate email: got %v, want ErrEmailTaken", err)
	}

	got, err := s.GetUserByEmail(ctx, email)
	if err != nil || got.ID != created.ID {
		t.Fatalf("GetUserByEmail = %+v, %v", got, err)
	}

	if _, err := s.GetUserByEmail(ctx, "nobody-"+email); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: got %v, want ErrNotFound", err)
	}

	// The CHECK constraint refuses non-normalised emails outright.
	if _, err := s.CreateUser(ctx, "UPPER-"+email, "$argon2id$x"); err == nil || errors.Is(err, ErrEmailTaken) {
		t.Fatalf("upper-case email: got %v, want a constraint error", err)
	}
}
