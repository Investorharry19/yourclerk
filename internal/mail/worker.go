package mail

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

// Outbox is the part of the store the worker uses.
type Outbox interface {
	// ClaimOutbox leases up to limit due messages to this worker for lease, and counts the attempt.
	ClaimOutbox(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]store.OutboxItem, error)
	MarkOutboxSent(ctx context.Context, id string, now time.Time) error
	// MarkOutboxFailed records the error. retryAt == nil gives up: the message becomes "dead".
	MarkOutboxFailed(ctx context.Context, id, errMsg string, retryAt *time.Time, now time.Time) error
}

const (
	DefaultMaxAttempts = 8
	baseBackoff        = 30 * time.Second
	maxBackoff         = time.Hour
	sendTimeout        = 30 * time.Second
)

// Backoff is the wait before attempt number attempts+1: 30s, 1m, 2m, 4m ... capped at 1h.
func Backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := baseBackoff
	for i := 1; i < attempts && d < maxBackoff; i++ {
		d *= 2
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// Worker drains the email outbox: claim, decrypt, send, then mark sent or
// schedule a retry. Delivery is at-least-once: if the process dies between a
// send and its bookkeeping, the lease lapses and the message is sent again.
type Worker struct {
	Outbox      Outbox
	Mailer      Mailer
	Sealer      *auth.Sealer
	From        string
	Log         *slog.Logger
	Now         func() time.Time
	Interval    time.Duration // poll period; default 3s
	Batch       int           // default 10
	MaxAttempts int           // default DefaultMaxAttempts
	Lease       time.Duration // default 2m
}

func (w *Worker) defaults() {
	if w.Now == nil {
		w.Now = time.Now
	}
	if w.Interval <= 0 {
		w.Interval = 3 * time.Second
	}
	if w.Batch <= 0 {
		w.Batch = 10
	}
	if w.MaxAttempts <= 0 {
		w.MaxAttempts = DefaultMaxAttempts
	}
	if w.Lease <= 0 {
		w.Lease = 2 * time.Minute
	}
}

// Run polls until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.defaults()
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		if _, _, err := w.ProcessOnce(ctx); err != nil && ctx.Err() == nil {
			w.Log.Error("email worker", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ProcessOnce handles one batch and returns how many messages were sent and how many failed.
func (w *Worker) ProcessOnce(ctx context.Context) (sent, failed int, err error) {
	w.defaults()
	items, err := w.Outbox.ClaimOutbox(ctx, w.Now(), w.Batch, w.Lease)
	if err != nil {
		return 0, 0, fmt.Errorf("claim outbox: %w", err)
	}
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		if w.deliver(ctx, it) {
			sent++
		} else {
			failed++
		}
	}
	return sent, failed, nil
}

func (w *Worker) deliver(ctx context.Context, it store.OutboxItem) bool {
	log := w.Log.With("outbox_id", it.ID, "application_id", it.ApplicationID, "kind", it.Kind, "attempt", it.Attempts)

	msg, err := Open(w.Sealer, it.ApplicationID, it.Payload)
	if err != nil {
		// Retrying cannot fix an undecryptable payload (SECRET_KEY changed, or a
		// corrupted row), so give up at once.
		log.Error("email payload unreadable; giving up", "err", err)
		w.mark(ctx, it, "payload unreadable: "+err.Error(), nil)
		return false
	}

	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	err = w.Mailer.Send(sctx, w.From, msg)
	cancel()
	if err == nil {
		if mErr := w.Outbox.MarkOutboxSent(context.WithoutCancel(ctx), it.ID, w.Now()); mErr != nil {
			log.Error("email sent but not recorded; it may be sent again", "err", mErr)
		}
		log.Info("email sent")
		return true
	}

	if it.Attempts >= w.MaxAttempts {
		log.Error("email send failed; giving up", "err", err)
		w.mark(ctx, it, err.Error(), nil)
		return false
	}
	retry := w.Now().Add(Backoff(it.Attempts))
	log.Warn("email send failed; will retry", "err", err, "retry_at", retry)
	w.mark(ctx, it, err.Error(), &retry)
	return false
}

func (w *Worker) mark(ctx context.Context, it store.OutboxItem, msg string, retryAt *time.Time) {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if err := w.Outbox.MarkOutboxFailed(context.WithoutCancel(ctx), it.ID, msg, retryAt, w.Now()); err != nil {
		w.Log.Error("record email failure", "err", err, "outbox_id", it.ID)
	}
}
