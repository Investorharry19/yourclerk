package mail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

const testSecret = "worker-test-secret-worker-test-secret"

type row struct {
	item    store.OutboxItem
	status  string
	next    time.Time
	locked  time.Time
	lastErr string
}

// fakeOutbox follows the same rules as the SQL queue.
type fakeOutbox struct {
	mu   sync.Mutex
	rows []*row
}

func (f *fakeOutbox) add(it store.OutboxItem, now time.Time) {
	f.rows = append(f.rows, &row{item: it, status: "pending", next: now})
}

func (f *fakeOutbox) ClaimOutbox(_ context.Context, now time.Time, limit int, lease time.Duration) ([]store.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.OutboxItem
	for _, r := range f.rows {
		if len(out) == limit {
			break
		}
		if r.status == "pending" && !r.next.After(now) && !r.locked.After(now) {
			r.item.Attempts++
			r.locked = now.Add(lease)
			out = append(out, r.item)
		}
	}
	return out, nil
}

func (f *fakeOutbox) find(id string) *row {
	for _, r := range f.rows {
		if r.item.ID == id {
			return r
		}
	}
	return nil
}

func (f *fakeOutbox) MarkOutboxSent(_ context.Context, id string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.find(id)
	r.status, r.item.Payload, r.locked = "sent", nil, time.Time{}
	return nil
}

func (f *fakeOutbox) MarkOutboxFailed(_ context.Context, id, msg string, retryAt *time.Time, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.find(id)
	r.lastErr, r.locked = msg, time.Time{}
	if retryAt == nil {
		r.status, r.item.Payload = "dead", nil
	} else {
		r.next = *retryAt
	}
	return nil
}

type flakyMailer struct {
	mu       sync.Mutex
	failures int // fail this many times, then succeed
	calls    int
	sent     []Message
}

func (m *flakyMailer) Send(_ context.Context, _ string, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.failures > 0 {
		m.failures--
		return errors.New("provider unavailable")
	}
	m.sent = append(m.sent, msg)
	return nil
}

type harness struct {
	t      *testing.T
	box    *fakeOutbox
	mailer *flakyMailer
	w      *Worker
	now    time.Time
	sealer *auth.Sealer
}

func newHarness(t *testing.T) *harness {
	sealer, err := auth.NewSealer(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, box: &fakeOutbox{}, mailer: &flakyMailer{}, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), sealer: sealer}
	h.w = &Worker{
		Outbox: h.box, Mailer: h.mailer, Sealer: sealer, From: "a@example.com",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return h.now },
		MaxAttempts: 4,
	}
	return h
}

func (h *harness) enqueue(id, appID, to string) {
	payload, err := Seal(h.sealer, appID, Message{To: to, Subject: "s", Text: "link for " + to})
	if err != nil {
		h.t.Fatal(err)
	}
	h.box.add(store.OutboxItem{ID: id, ApplicationID: appID, Kind: "verify", ToEmail: to, Payload: payload}, h.now)
}

func (h *harness) run() (int, int) {
	h.t.Helper()
	sent, failed, err := h.w.ProcessOnce(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return sent, failed
}

func TestWorkerSendsAndWipesPayload(t *testing.T) {
	h := newHarness(t)
	h.enqueue("m1", "app-1", "a@example.com")
	h.enqueue("m2", "app-2", "b@example.com")
	if sent, failed := h.run(); sent != 2 || failed != 0 {
		t.Fatalf("sent=%d failed=%d", sent, failed)
	}
	if len(h.mailer.sent) != 2 || h.mailer.sent[0].Text != "link for a@example.com" {
		t.Fatalf("delivered = %+v", h.mailer.sent)
	}
	for _, r := range h.box.rows {
		if r.status != "sent" || r.item.Payload != nil {
			t.Fatalf("row %s: %s payload=%v", r.item.ID, r.status, r.item.Payload)
		}
	}
	if sent, _ := h.run(); sent != 0 {
		t.Fatal("a sent message was sent again")
	}
}

// A failed send is retried with growing delays, and eventually succeeds.
func TestWorkerRetriesWithBackoff(t *testing.T) {
	h := newHarness(t)
	h.mailer.failures = 2
	h.enqueue("m1", "app-1", "a@example.com")

	if sent, failed := h.run(); sent != 0 || failed != 1 {
		t.Fatalf("attempt 1: sent=%d failed=%d", sent, failed)
	}
	r := h.box.rows[0]
	if want := h.now.Add(30 * time.Second); !r.next.Equal(want) || r.status != "pending" || r.lastErr == "" {
		t.Fatalf("after attempt 1: next=%v status=%s err=%q", r.next, r.status, r.lastErr)
	}

	// Not due yet: nothing happens.
	h.now = h.now.Add(29 * time.Second)
	if sent, failed := h.run(); sent+failed != 0 || h.mailer.calls != 1 {
		t.Fatalf("retried too early (calls=%d)", h.mailer.calls)
	}

	h.now = h.now.Add(2 * time.Second)
	if _, failed := h.run(); failed != 1 {
		t.Fatal("attempt 2 should fail")
	}
	if want := h.now.Add(time.Minute); !r.next.Equal(want) {
		t.Fatalf("second backoff: next=%v want %v", r.next, want)
	}

	h.now = h.now.Add(time.Minute)
	if sent, failed := h.run(); sent != 1 || failed != 0 {
		t.Fatalf("attempt 3: sent=%d failed=%d", sent, failed)
	}
	if r.status != "sent" || h.mailer.calls != 3 {
		t.Fatalf("status=%s calls=%d", r.status, h.mailer.calls)
	}
}

func TestWorkerGivesUpAfterMaxAttempts(t *testing.T) {
	h := newHarness(t)
	h.mailer.failures = 1000
	h.enqueue("m1", "app-1", "a@example.com")
	for i := 0; i < 10; i++ {
		h.run()
		h.now = h.now.Add(2 * time.Hour)
	}
	r := h.box.rows[0]
	if r.status != "dead" || r.item.Payload != nil || h.mailer.calls != 4 {
		t.Fatalf("status=%s calls=%d (want dead after exactly 4 attempts)", r.status, h.mailer.calls)
	}
}

// One bad message must not hold up the others behind it.
func TestWorkerFailureDoesNotBlockOtherMessages(t *testing.T) {
	h := newHarness(t)
	h.enqueue("bad", "app-1", "a@example.com")
	h.enqueue("good", "app-1", "b@example.com")
	h.mailer.failures = 1 // the first send fails
	sent, failed := h.run()
	if sent != 1 || failed != 1 || h.box.rows[1].status != "sent" {
		t.Fatalf("sent=%d failed=%d", sent, failed)
	}
}

func TestWorkerDropsUnreadablePayloads(t *testing.T) {
	h := newHarness(t)
	h.enqueue("wrong-app", "app-1", "a@example.com")
	h.box.rows[0].item.ApplicationID = "app-2" // payload was sealed for app-1
	h.box.add(store.OutboxItem{ID: "garbage", ApplicationID: "app-1", Payload: []byte("not encrypted at all")}, h.now)

	if sent, failed := h.run(); sent != 0 || failed != 2 {
		t.Fatalf("sent=%d failed=%d", sent, failed)
	}
	for _, r := range h.box.rows {
		if r.status != "dead" {
			t.Fatalf("%s: %s; an unreadable payload cannot be fixed by retrying", r.item.ID, r.status)
		}
	}
	if h.mailer.calls != 0 {
		t.Fatal("mailer called with an unreadable payload")
	}
}

func TestWorkerLeaseLetsCrashedWorkersMessagesRecover(t *testing.T) {
	h := newHarness(t)
	h.enqueue("m1", "app-1", "a@example.com")
	// A worker claims the message and dies before sending or recording anything.
	if _, err := h.box.ClaimOutbox(context.Background(), h.now, 10, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if sent, failed := h.run(); sent+failed != 0 {
		t.Fatal("a leased message was processed by a second worker")
	}
	h.now = h.now.Add(3 * time.Minute)
	if sent, _ := h.run(); sent != 1 {
		t.Fatal("the message was lost with the crashed worker")
	}
}

func TestWorkerRunStopsOnCancel(t *testing.T) {
	h := newHarness(t)
	h.w.Interval = 5 * time.Millisecond
	h.enqueue("m1", "app-1", "a@example.com")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.w.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for {
		h.mailer.mu.Lock()
		n := len(h.mailer.sent)
		h.mailer.mu.Unlock()
		if n == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("worker did not deliver")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}
