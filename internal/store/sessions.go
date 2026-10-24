package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Session struct {
	ID           string
	UserID       string
	UserAgent    string
	IP           string
	CreatedAt    time.Time
	LastActiveAt time.Time
	ExpiresAt    time.Time
}

const sessionColumns = "id::text, user_id::text, user_agent, ip, created_at, last_active_at, expires_at"

// All methods take the current time from the caller instead of calling now()
// in SQL, so expiry behaviour is easy to test.

// CreateSession stores a new session. tokenHash is the SHA-256 of the cookie
// token; the raw token is never stored.
func (s *Store) CreateSession(ctx context.Context, userID string, tokenHash []byte, userAgent, ip string, now, expiresAt time.Time) (Session, error) {
	var sess Session
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id, token_hash, user_agent, ip, created_at, last_active_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $5, $6)
		 RETURNING `+sessionColumns,
		userID, tokenHash, userAgent, ip, now, expiresAt,
	).Scan(&sess.ID, &sess.UserID, &sess.UserAgent, &sess.IP, &sess.CreatedAt, &sess.LastActiveAt, &sess.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return sess, nil
}

// GetLiveSession finds a session by token hash and returns it with its user.
// "Live" means not revoked, not past its absolute expiry, and active since idleCutoff.
// Anything else returns ErrNotFound, so callers cannot tell the reasons apart.
func (s *Store) GetLiveSession(ctx context.Context, tokenHash []byte, now, idleCutoff time.Time) (Session, User, error) {
	var (
		sess Session
		user User
	)
	err := s.Pool.QueryRow(ctx,
		`SELECT s.id::text, s.user_id::text, s.user_agent, s.ip, s.created_at, s.last_active_at, s.expires_at,
		        u.email, u.created_at, u.updated_at
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1
		   AND s.revoked_at IS NULL
		   AND s.expires_at > $2
		   AND s.last_active_at > $3`,
		tokenHash, now, idleCutoff,
	).Scan(&sess.ID, &sess.UserID, &sess.UserAgent, &sess.IP, &sess.CreatedAt, &sess.LastActiveAt, &sess.ExpiresAt,
		&user.Email, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, fmt.Errorf("get live session: %w", err)
	}
	user.ID = sess.UserID
	return sess, user, nil
}

// TouchSession records activity on a session.
func (s *Store) TouchSession(ctx context.Context, sessionID string, now time.Time) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE sessions SET last_active_at = $2 WHERE id::text = $1`, sessionID, now)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// ListLiveSessions returns a user's live sessions, newest first.
func (s *Store) ListLiveSessions(ctx context.Context, userID string, now, idleCutoff time.Time) ([]Session, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2 AND last_active_at > $3
		 ORDER BY created_at DESC`,
		userID, now, idleCutoff)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.UserAgent, &sess.IP, &sess.CreatedAt, &sess.LastActiveAt, &sess.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return out, nil
}

// RevokeSession revokes one of the given user's sessions. It reports false if
// no such live session belongs to that user, which also covers other users'
// sessions and malformed IDs. The id is compared as text so a malformed value
// is simply "not found" instead of a database error.
func (s *Store) RevokeSession(ctx context.Context, userID, sessionID string, now time.Time) (bool, error) {
	tag, err := s.Pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = $3
		 WHERE user_id = $1 AND id::text = $2 AND revoked_at IS NULL`,
		userID, sessionID, now)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteExpiredSessions removes sessions that can never be used again:
// past absolute expiry, idle too long, or revoked more than a day ago.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`DELETE FROM sessions
		 WHERE expires_at <= $1
		    OR last_active_at <= $2
		    OR (revoked_at IS NOT NULL AND revoked_at <= $1::timestamptz - interval '1 day')`,
		now, idleCutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
