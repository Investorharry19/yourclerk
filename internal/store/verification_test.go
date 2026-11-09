package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

var msgFor = func(kind EmailPurpose, to string) OutboxMessage {
	return OutboxMessage{Kind: kind, ToEmail: to, Payload: []byte("sealed-" + to)}
}

func (w *world) user(t *testing.T, tn Tenant, email string) User {
	t.Helper()
	u, err := tn.CreateUser(w.ctx, email, "old-hash")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (w *world) issue(t *testing.T, tn Tenant, u User, p EmailPurpose, now time.Time, ttl, cooldown time.Duration) ([]byte, bool) {
	t.Helper()
	_, hash, _ := auth.NewOneTimeToken()
	ok, err := tn.IssueEmailToken(w.ctx, u.ID, p, hash, now, now.Add(ttl), cooldown, msgFor(p, u.Email))
	if err != nil {
		t.Fatal(err)
	}
	return hash, ok
}

func (w *world) outboxCount(t *testing.T, appID string) (n int) {
	t.Helper()
	_ = w.s.Pool.QueryRow(w.ctx, `SELECT count(*) FROM email_outbox WHERE application_id::text = $1`, appID).Scan(&n)
	return
}

func TestVerifyTokenWorksOnceAndExpires(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "v@example.com")
	if u.EmailVerified() {
		t.Fatal("new user already verified")
	}
	hash, ok := w.issue(t, w.ta, u, PurposeVerify, now0, 24*time.Hour, 0)
	if !ok || w.outboxCount(t, w.a.ID) != 1 {
		t.Fatalf("issue: ok=%v outbox=%d", ok, w.outboxCount(t, w.a.ID))
	}

	got, err := w.ta.ConsumeVerifyToken(w.ctx, hash, now0.Add(time.Hour))
	if err != nil || !got.EmailVerified() || !got.EmailVerifiedAt.Equal(now0.Add(time.Hour)) {
		t.Fatalf("consume: %+v %v", got, err)
	}
	if _, err := w.ta.ConsumeVerifyToken(w.ctx, hash, now0.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token worked twice: %v", err)
	}
	if again, _ := w.ta.GetUserByID(w.ctx, u.ID); !again.EmailVerifiedAt.Equal(now0.Add(time.Hour)) {
		t.Fatal("verification time was overwritten")
	}

	// Expiry: valid until the instant it expires, dead from then on.
	h2, _ := w.issue(t, w.ta, w.user(t, w.ta, "e@example.com"), PurposeVerify, now0, time.Hour, 0)
	if _, err := w.ta.ConsumeVerifyToken(w.ctx, h2, now0.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token valid at its expiry instant: %v", err)
	}
	if _, err := w.ta.ConsumeVerifyToken(w.ctx, h2, now0.Add(59*time.Minute)); err != nil {
		t.Fatalf("a failed attempt after expiry must not matter, and a token one minute early works: %v", err)
	}
}

func TestTokensAreBoundToApplicationAndPurpose(t *testing.T) {
	w := newWorld(t)
	ua := w.user(t, w.ta, "same@example.com")
	w.user(t, w.tb, "same@example.com")
	hv, _ := w.issue(t, w.ta, ua, PurposeVerify, now0, time.Hour, 0)
	hr, _ := w.issue(t, w.ta, ua, PurposeReset, now0, time.Hour, 0)

	// The same user, same email, other application: tokens do not cross.
	if _, err := w.tb.ConsumeVerifyToken(w.ctx, hv, now0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("A's verify token accepted by B: %v", err)
	}
	if _, err := w.tb.ResetPassword(w.ctx, hr, "new", now0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("A's reset token accepted by B: %v", err)
	}
	// And a verify token is not a reset token, nor the reverse.
	if _, err := w.ta.ResetPassword(w.ctx, hv, "new", now0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verify token used to reset a password: %v", err)
	}
	if _, err := w.ta.ConsumeVerifyToken(w.ctx, hr, now0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset token used to verify an email: %v", err)
	}
	// None of those failed attempts spent the real tokens.
	if _, err := w.ta.ConsumeVerifyToken(w.ctx, hv, now0); err != nil {
		t.Fatalf("A's own verify token: %v", err)
	}
	if _, err := w.ta.ResetPassword(w.ctx, hr, "new", now0); err != nil {
		t.Fatalf("A's own reset token: %v", err)
	}
	// The database refuses a token row that mixes applications.
	_, err := w.s.Pool.Exec(w.ctx,
		`INSERT INTO verification_tokens (application_id, user_id, purpose, token_hash, expires_at) VALUES ($1, $2, 'verify', $3, now())`,
		w.b.ID, ua.ID, []byte("mixed"))
	if err == nil {
		t.Fatal("inserted a token for a user of another application")
	}
}

func TestResetPasswordRevokesEverySession(t *testing.T) {
	w := newWorld(t)
	alice := w.user(t, w.ta, "alice@example.com")
	bob := w.user(t, w.ta, "bob@example.com")
	aliceB := w.user(t, w.tb, "alice@example.com") // same email, other application
	exp, idle := now0.Add(24*time.Hour), now0.Add(-time.Hour)

	mk := func(tn Tenant, u User) []byte {
		_, h, _ := auth.NewSessionToken()
		if _, err := tn.CreateSession(w.ctx, u.ID, h, "", "", now0, exp); err != nil {
			t.Fatal(err)
		}
		return h
	}
	a1, a2, bobS, otherApp := mk(w.ta, alice), mk(w.ta, alice), mk(w.ta, bob), mk(w.tb, aliceB)

	hash, _ := w.issue(t, w.ta, alice, PurposeReset, now0, time.Hour, 0)
	u, err := w.ta.ResetPassword(w.ctx, hash, "brand-new-hash", now0.Add(time.Minute))
	if err != nil || u.PasswordHash != "brand-new-hash" || !u.EmailVerified() {
		t.Fatalf("reset: %+v %v", u, err)
	}
	for i, h := range [][]byte{a1, a2} {
		if _, _, err := w.ta.GetLiveSession(w.ctx, h, now0.Add(time.Minute), idle); !errors.Is(err, ErrNotFound) {
			t.Fatalf("alice's session %d survived the reset: %v", i, err)
		}
	}
	if _, _, err := w.ta.GetLiveSession(w.ctx, bobS, now0.Add(time.Minute), idle); err != nil {
		t.Fatalf("another user's session was revoked: %v", err)
	}
	if _, _, err := w.tb.GetLiveSession(w.ctx, otherApp, now0.Add(time.Minute), idle); err != nil {
		t.Fatalf("same email in another application was affected: %v", err)
	}
	if b, _ := w.tb.GetUserByID(w.ctx, aliceB.ID); b.PasswordHash != "old-hash" {
		t.Fatal("the other application's user got the new password")
	}
	if _, err := w.ta.ResetPassword(w.ctx, hash, "again", now0.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset token worked twice: %v", err)
	}
}

func TestResetTokenExpires(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "x@example.com")
	hash, _ := w.issue(t, w.ta, u, PurposeReset, now0, time.Hour, 0)
	if _, err := w.ta.ResetPassword(w.ctx, hash, "new", now0.Add(time.Hour+time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired reset token: %v", err)
	}
	if got, _ := w.ta.GetUserByID(w.ctx, u.ID); got.PasswordHash != "old-hash" {
		t.Fatal("password changed by an expired token")
	}
}

func TestNewTokenSupersedesOldAndCooldownLimitsMail(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "c@example.com")
	first, ok := w.issue(t, w.ta, u, PurposeReset, now0, time.Hour, time.Minute)
	if !ok {
		t.Fatal("first issue refused")
	}
	// Within the cooldown: nothing is created, nothing is queued.
	if _, ok := w.issue(t, w.ta, u, PurposeReset, now0.Add(30*time.Second), time.Hour, time.Minute); ok {
		t.Fatal("second issue inside the cooldown was allowed")
	}
	if n := w.outboxCount(t, w.a.ID); n != 1 {
		t.Fatalf("outbox has %d messages, want 1", n)
	}
	// The cooldown is per purpose.
	if _, ok := w.issue(t, w.ta, u, PurposeVerify, now0.Add(30*time.Second), time.Hour, time.Minute); !ok {
		t.Fatal("verify blocked by a reset cooldown")
	}
	// After it, a new token replaces the old one.
	second, ok := w.issue(t, w.ta, u, PurposeReset, now0.Add(2*time.Minute), time.Hour, time.Minute)
	if !ok {
		t.Fatal("issue after the cooldown refused")
	}
	if _, err := w.ta.ResetPassword(w.ctx, first, "x", now0.Add(3*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded token still works: %v", err)
	}
	if _, err := w.ta.ResetPassword(w.ctx, second, "x", now0.Add(3*time.Minute)); err != nil {
		t.Fatalf("newest token: %v", err)
	}
}

// If the email cannot be queued, the token must not exist either.
func TestIssueEmailTokenIsAtomic(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "atomic@example.com")
	_, hash, _ := auth.NewOneTimeToken()
	bad := OutboxMessage{Kind: PurposeVerify, ToEmail: u.Email, Payload: nil} // payload is NOT NULL
	if _, err := w.ta.IssueEmailToken(w.ctx, u.ID, PurposeVerify, hash, now0, now0.Add(time.Hour), 0, bad); err == nil {
		t.Fatal("issue succeeded without a queueable email")
	}
	if _, err := w.ta.ConsumeVerifyToken(w.ctx, hash, now0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a token was stored although queueing failed: %v", err)
	}
}

func TestOutboxClaimRetryAndGiveUp(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "q@example.com")
	w.issue(t, w.ta, u, PurposeVerify, now0, time.Hour, 0)
	lease := time.Minute

	mine := func(items []OutboxItem) (out []OutboxItem) {
		for _, it := range items {
			if it.ApplicationID == w.a.ID {
				out = append(out, it)
			}
		}
		return
	}
	claim := func(at time.Time) []OutboxItem {
		items, err := w.s.ClaimOutbox(w.ctx, at, 100, lease)
		if err != nil {
			t.Fatal(err)
		}
		return mine(items)
	}

	got := claim(now0)
	if len(got) != 1 || got[0].Attempts != 1 || got[0].ToEmail != u.Email || string(got[0].Payload) != "sealed-q@example.com" {
		t.Fatalf("first claim = %+v", got)
	}
	id := got[0].ID
	// Leased: not handed out again while the lease holds...
	if n := len(claim(now0.Add(30 * time.Second))); n != 0 {
		t.Fatalf("a leased message was claimed again (%d)", n)
	}
	// ...but a worker that died does not lose it.
	if got := claim(now0.Add(2 * time.Minute)); len(got) != 1 || got[0].Attempts != 2 {
		t.Fatalf("after the lease lapsed: %+v", got)
	}

	// A failure with a retry time: not due until then.
	retry := now0.Add(10 * time.Minute)
	if err := w.s.MarkOutboxFailed(w.ctx, id, "smtp down", &retry, now0); err != nil {
		t.Fatal(err)
	}
	if n := len(claim(now0.Add(5 * time.Minute))); n != 0 {
		t.Fatalf("claimed before its retry time (%d)", n)
	}
	if got := claim(retry); len(got) != 1 || got[0].Attempts != 3 {
		t.Fatalf("at its retry time: %+v", got)
	}

	// Giving up: dead, never claimed again, payload wiped, error kept.
	if err := w.s.MarkOutboxFailed(w.ctx, id, "permanent", nil, retry); err != nil {
		t.Fatal(err)
	}
	if n := len(claim(retry.Add(24 * time.Hour))); n != 0 {
		t.Fatalf("a dead message was claimed (%d)", n)
	}
	var status, lastErr string
	var plen int
	_ = w.s.Pool.QueryRow(w.ctx, `SELECT status, last_error, length(payload) FROM email_outbox WHERE id::text = $1`, id).Scan(&status, &lastErr, &plen)
	if status != "dead" || lastErr != "permanent" || plen != 0 {
		t.Fatalf("dead row: %s %q payload=%d", status, lastErr, plen)
	}
}

func TestOutboxSentWipesPayload(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "s@example.com")
	w.issue(t, w.ta, u, PurposeVerify, now0, time.Hour, 0)
	items, _ := w.s.ClaimOutbox(w.ctx, now0, 100, time.Minute)
	var id string
	for _, it := range items {
		if it.ApplicationID == w.a.ID {
			id = it.ID
		}
	}
	if id == "" {
		t.Fatal("message not claimed")
	}
	if err := w.s.MarkOutboxSent(w.ctx, id, now0); err != nil {
		t.Fatal(err)
	}
	var status string
	var plen int
	_ = w.s.Pool.QueryRow(w.ctx, `SELECT status, length(payload) FROM email_outbox WHERE id::text = $1`, id).Scan(&status, &plen)
	if status != "sent" || plen != 0 {
		t.Fatalf("sent row: %s payload=%d", status, plen)
	}
	if n, err := w.s.DeleteOldOutbox(w.ctx, now0.Add(8*24*time.Hour)); err != nil || n < 1 {
		t.Fatalf("cleanup of sent messages: %d %v", n, err)
	}
}

// Several workers at once never receive the same message.
func TestOutboxClaimsDoNotOverlapAcrossWorkers(t *testing.T) {
	w := newWorld(t)
	for i := 0; i < 20; i++ {
		u := w.user(t, w.ta, "u"+string(rune('a'+i))+"@example.com")
		w.issue(t, w.ta, u, PurposeVerify, now0, time.Hour, 0)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				items, err := w.s.ClaimOutbox(context.Background(), now0, 3, time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				n := 0
				mu.Lock()
				for _, it := range items {
					if it.ApplicationID == w.a.ID {
						seen[it.ID]++
						n++
					}
				}
				mu.Unlock()
				if len(items) == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	if len(seen) != 20 {
		t.Fatalf("claimed %d of 20 messages", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("message %s claimed %d times", id, n)
		}
	}
}

func TestDeleteExpiredVerificationTokens(t *testing.T) {
	w := newWorld(t)
	u := w.user(t, w.ta, "old@example.com")
	hash, _ := w.issue(t, w.ta, u, PurposeVerify, now0, time.Hour, 0)
	if n, _ := w.s.DeleteExpiredVerificationTokens(w.ctx, now0.Add(2*time.Hour)); n != 0 {
		_ = n // other tests' rows may exist; ours is only an hour past expiry and must survive
	}
	var c int
	_ = w.s.Pool.QueryRow(w.ctx, `SELECT count(*) FROM verification_tokens WHERE token_hash = $1`, hash).Scan(&c)
	if c != 1 {
		t.Fatal("a token one hour past expiry was already deleted")
	}
	_, _ = w.s.DeleteExpiredVerificationTokens(w.ctx, now0.Add(26*time.Hour))
	_ = w.s.Pool.QueryRow(w.ctx, `SELECT count(*) FROM verification_tokens WHERE token_hash = $1`, hash).Scan(&c)
	if c != 0 {
		t.Fatal("an old token was not cleaned up")
	}
}
