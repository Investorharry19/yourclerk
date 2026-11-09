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

// CreateSession stores a new session for a user of this application. tokenHash
// is the SHA-256 of the cookie token; the raw token is never stored. The
// composite foreign key makes the database refuse a user from another application.
func (s *AppStore) CreateSession(ctx context.Context, userID string, tokenHash []byte, userAgent, ip string, now, expiresAt time.Time) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (application_id, user_id, token_hash, user_agent, ip, created_at, last_active_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
		 RETURNING `+sessionColumns,
		s.appID, userID, tokenHash, userAgent, ip, now, expiresAt,
	).Scan(&sess.ID, &sess.UserID, &sess.UserAgent, &sess.IP, &sess.CreatedAt, &sess.LastActiveAt, &sess.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return sess, nil
}

// GetLiveSession finds a session of this application by token hash and returns
// it with its user. "Live" means not revoked, not past its absolute expiry, and
// active since idleCutoff. Anything else, including a token that belongs to
// another application, returns ErrNotFound.
func (s *AppStore) GetLiveSession(ctx context.Context, tokenHash []byte, now, idleCutoff time.Time) (Session, User, error) {
	var (
		sess Session
		user User
	)
	err := s.pool.QueryRow(ctx,
		`SELECT s.id::text, s.user_id::text, s.user_agent, s.ip, s.created_at, s.last_active_at, s.expires_at,
		        u.email, u.created_at, u.updated_at, u.email_verified_at
		 FROM sessions s
		 JOIN users u ON u.application_id = s.application_id AND u.id = s.user_id
		 WHERE s.application_id = $1
		   AND s.token_hash = $2
		   AND s.revoked_at IS NULL
		   AND s.expires_at > $3
		   AND s.last_active_at > $4`,
		s.appID, tokenHash, now, idleCutoff,
	).Scan(&sess.ID, &sess.UserID, &sess.UserAgent, &sess.IP, &sess.CreatedAt, &sess.LastActiveAt, &sess.ExpiresAt,
		&user.Email, &user.CreatedAt, &user.UpdatedAt, &user.EmailVerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, fmt.Errorf("get live session: %w", err)
	}
	user.ID = sess.UserID
	return sess, user, nil
}

// TouchSession records activity on one of this application's sessions.
func (s *AppStore) TouchSession(ctx context.Context, sessionID string, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET last_active_at = $3 WHERE application_id = $1 AND id::text = $2`,
		s.appID, sessionID, now)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// ListLiveSessions returns a user's live sessions in this application, newest first.
func (s *AppStore) ListLiveSessions(ctx context.Context, userID string, now, idleCutoff time.Time) ([]Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE application_id = $1 AND user_id::text = $2
		   AND revoked_at IS NULL AND expires_at > $3 AND last_active_at > $4
		 ORDER BY created_at DESC`,
		s.appID, userID, now, idleCutoff)
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

// RevokeSession revokes one of the given user's sessions in this application.
// It reports false if no such live session exists, which also covers other
// users' sessions, other applications' sessions and malformed IDs (ids are
// compared as text so a malformed value is "not found", not a database error).
func (s *AppStore) RevokeSession(ctx context.Context, userID, sessionID string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = $4
		 WHERE application_id = $1 AND user_id::text = $2 AND id::text = $3 AND revoked_at IS NULL`,
		s.appID, userID, sessionID, now)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteExpiredSessions removes sessions, across all applications, that can
// never be used again: past absolute expiry, idle longer than their own
// application's idle timeout, or revoked more than a day ago. It is the one
// deliberate cross-tenant query: it is maintenance, not a request on behalf of a
// tenant, and each row is judged by its own application's settings.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`-- cross-tenant: maintenance
		 DELETE FROM sessions s USING applications a
		 WHERE a.id = s.application_id
		   AND (s.expires_at <= $1
		     OR s.last_active_at <= $1::timestamptz - a.session_idle_timeout_seconds * interval '1 second'
		     OR (s.revoked_at IS NOT NULL AND s.revoked_at <= $1::timestamptz - interval '1 day'))`,
		now)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
