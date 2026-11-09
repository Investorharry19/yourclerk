package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/Investorharry19/yourclerk/internal/store"
)

// cleanup removes dead rows once at startup and then every interval, until ctx
// is cancelled: sessions (judged by each application's own idle timeout),
// spent or long-expired email tokens, and delivered or abandoned queued emails.
func cleanup(ctx context.Context, log *slog.Logger, db *store.Store, every time.Duration) {
	run := func() {
		now := time.Now()
		for _, job := range []struct {
			name string
			fn   func(context.Context, time.Time) (int64, error)
		}{
			{"sessions", db.DeleteExpiredSessions},
			{"email tokens", db.DeleteExpiredVerificationTokens},
			{"email outbox", db.DeleteOldOutbox},
		} {
			n, err := job.fn(ctx, now)
			switch {
			case ctx.Err() != nil:
				return
			case err != nil:
				log.Error("cleanup failed", "job", job.name, "err", err)
			case n > 0:
				log.Info("cleanup", "job", job.name, "deleted", n)
			}
		}
	}

	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
