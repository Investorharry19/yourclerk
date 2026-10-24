package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

// cleanupSessions deletes dead sessions once at startup and then every interval,
// until ctx is cancelled.
func cleanupSessions(ctx context.Context, log *slog.Logger, db *store.Store, every time.Duration) {
	run := func() {
		now := time.Now()
		n, err := db.DeleteExpiredSessions(ctx, now, now.Add(-auth.IdleTTL))
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.Error("session cleanup failed", "err", err)
		case n > 0:
			log.Info("session cleanup", "deleted", n)
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
