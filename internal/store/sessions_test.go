package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// Runs against a real Postgres with migrations applied. Skipped without TEST_DATABASE_URL.
func TestSessions(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := New(ctx, url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	stamp := time.Now().UnixNano()
	newUser := func(prefix string) User {
		email := fmt.Sprintf("%s-%d@example.com", prefix, stamp)
		u, err := s.CreateUser(ctx, email, "$argon2id$fake")
		if err != nil {
			t.Fatalf("CreateUser: %v (did you run `make migrate-up`?)", err)
		}
		// Deleting the user cascades to its sessions.
		t.Cleanup(func() { _, _ = s.Pool.Exec(context.Background(), "DELETE FROM users WHERE id::text = $1", u.ID) })
		return u
	}
	user, other := newUser("sess-a"), newUser("sess-b")

	const (
		idleTTL     = 7 * 24 * time.Hour
		absoluteTTL = 30 * 24 * time.Hour
	)
	now := time.Now().UTC().Truncate(time.Microsecond)
	idleCutoff := now.Add(-idleTTL)
	sum := sha256.Sum256([]byte(fmt.Sprintf("token-%d", stamp)))
	hash := sum[:]

	sess, err := s.CreateSession(ctx, user.ID, hash, "test-agent", "127.0.0.1", now, now.Add(absoluteTTL))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, gotUser, err := s.GetLiveSession(ctx, hash, now, idleCutoff)
	if err != nil || got.ID != sess.ID || gotUser.ID != user.ID || gotUser.Email != user.Email {
		t.Fatalf("GetLiveSession = %+v, %+v, %v", got, gotUser, err)
	}

	if _, _, err := s.GetLiveSession(ctx, []byte("unknown-hash-unknown-hash-unknow"), now, idleCutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown hash: got %v, want ErrNotFound", err)
	}

	// Absolute expiry.
	late := now.Add(absoluteTTL + time.Hour)
	if _, _, err := s.GetLiveSession(ctx, hash, late, now.Add(-time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("past absolute expiry: got %v, want ErrNotFound", err)
	}
	// Idle expiry.
	idle := now.Add(idleTTL + time.Hour)
	if _, _, err := s.GetLiveSession(ctx, hash, idle, idle.Add(-idleTTL)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("past idle expiry: got %v, want ErrNotFound", err)
	}

	// Touching moves last_active_at, which keeps the session alive past the idle limit.
	later := now.Add(6 * 24 * time.Hour)
	if err := s.TouchSession(ctx, sess.ID, later); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	check := now.Add(10 * 24 * time.Hour)
	got, _, err = s.GetLiveSession(ctx, hash, check, check.Add(-idleTTL))
	if err != nil || !got.LastActiveAt.Equal(later) {
		t.Fatalf("after touch: %+v, %v", got, err)
	}

	list, err := s.ListLiveSessions(ctx, user.ID, now, idleCutoff)
	if err != nil || len(list) != 1 || list[0].ID != sess.ID {
		t.Fatalf("ListLiveSessions = %+v, %v", list, err)
	}
	if list, _ := s.ListLiveSessions(ctx, other.ID, now, idleCutoff); len(list) != 0 {
		t.Fatalf("other user sees sessions: %+v", list)
	}

	// Another user cannot revoke it; a malformed id is just "not found".
	if ok, err := s.RevokeSession(ctx, other.ID, sess.ID, now); err != nil || ok {
		t.Fatalf("revoke by other user = %v, %v; want false, nil", ok, err)
	}
	if ok, err := s.RevokeSession(ctx, user.ID, "not-a-uuid", now); err != nil || ok {
		t.Fatalf("revoke malformed id = %v, %v; want false, nil", ok, err)
	}
	if ok, err := s.RevokeSession(ctx, user.ID, sess.ID, now); err != nil || !ok {
		t.Fatalf("revoke own = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := s.RevokeSession(ctx, user.ID, sess.ID, now); ok {
		t.Fatal("revoking twice should report false")
	}
	if _, _, err := s.GetLiveSession(ctx, hash, now, idleCutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session still live: %v", err)
	}

	n, err := s.DeleteExpiredSessions(ctx, now.Add(48*time.Hour), now.Add(-1000*time.Hour))
	if err != nil || n < 1 {
		t.Fatalf("DeleteExpiredSessions = %d, %v; want at least 1", n, err)
	}
}
