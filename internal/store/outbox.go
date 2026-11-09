package store

import (
	"context"
	"fmt"
	"time"
)

// OutboxItem is a queued email handed to the worker.
type OutboxItem struct {
	ID            string
	ApplicationID string
	Kind          string
	ToEmail       string
	Payload       []byte
	// Attempts includes the current one: 1 on the first try.
	Attempts int
}

// The worker's queries span all applications on purpose: the queue is
// platform infrastructure, not a request made on behalf of a tenant.

// ClaimOutbox leases up to limit due messages for lease and counts one attempt
// on each. FOR UPDATE SKIP LOCKED lets several workers run without ever taking
// the same row, and a worker that dies simply lets its lease lapse.
func (s *Store) ClaimOutbox(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]OutboxItem, error) {
	rows, err := s.Pool.Query(ctx,
		`-- cross-tenant: queue worker
		 UPDATE email_outbox SET attempts = attempts + 1, locked_until = $1::timestamptz + $3 * interval '1 second'
		 WHERE id IN (
		     SELECT id FROM email_outbox
		     WHERE status = 'pending' AND next_attempt_at <= $1
		       AND (locked_until IS NULL OR locked_until <= $1)
		     ORDER BY next_attempt_at
		     LIMIT $2
		     FOR UPDATE SKIP LOCKED)
		 RETURNING id::text, application_id::text, kind, to_email, payload, attempts`,
		now, limit, lease.Seconds())
	if err != nil {
		return nil, fmt.Errorf("claim outbox: %w", err)
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var it OutboxItem
		if err := rows.Scan(&it.ID, &it.ApplicationID, &it.Kind, &it.ToEmail, &it.Payload, &it.Attempts); err != nil {
			return nil, fmt.Errorf("scan outbox: %w", err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkOutboxSent records delivery and wipes the encrypted payload, so the
// one-time link does not stay in the database after it has been sent.
func (s *Store) MarkOutboxSent(ctx context.Context, id string, now time.Time) error {
	_, err := s.Pool.Exec(ctx,
		`-- cross-tenant: queue worker
		 UPDATE email_outbox SET status = 'sent', sent_at = $2, payload = ''::bytea, locked_until = NULL, last_error = ''
		 WHERE id::text = $1`, id, now)
	if err != nil {
		return fmt.Errorf("mark sent: %w", err)
	}
	return nil
}

// MarkOutboxFailed records a failed attempt. With retryAt the message is due
// again then; without it the message is dead (given up) and its payload wiped.
func (s *Store) MarkOutboxFailed(ctx context.Context, id, errMsg string, retryAt *time.Time, now time.Time) error {
	var err error
	if retryAt != nil {
		_, err = s.Pool.Exec(ctx,
			`-- cross-tenant: queue worker
			 UPDATE email_outbox SET next_attempt_at = $2, locked_until = NULL, last_error = $3
			 WHERE id::text = $1`, id, *retryAt, errMsg)
	} else {
		_, err = s.Pool.Exec(ctx,
			`-- cross-tenant: queue worker
			 UPDATE email_outbox SET status = 'dead', payload = ''::bytea, locked_until = NULL, last_error = $2
			 WHERE id::text = $1`, id, errMsg)
	}
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}

// DeleteOldOutbox removes sent messages after 7 days and dead ones after 30.
func (s *Store) DeleteOldOutbox(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`-- cross-tenant: maintenance
		 DELETE FROM email_outbox
		 WHERE (status = 'sent' AND sent_at    <= $1::timestamptz - interval '7 days')
		    OR (status = 'dead' AND created_at <= $1::timestamptz - interval '30 days')`, now)
	if err != nil {
		return 0, fmt.Errorf("delete old outbox: %w", err)
	}
	return tag.RowsAffected(), nil
}
