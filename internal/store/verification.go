package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EmailPurpose says what a one-time email token is for.
type EmailPurpose string

const (
	PurposeVerify EmailPurpose = "verify"
	PurposeReset  EmailPurpose = "reset"
)

// OutboxMessage is a queued email. Payload is the encrypted message.
type OutboxMessage struct {
	Kind    EmailPurpose
	ToEmail string
	Payload []byte
}

// IssueEmailToken stores a one-time token and queues its email, in ONE
// transaction: either both exist or neither does, so a token is never created
// without a mail to deliver it and a mail never carries a token that was not saved.
//
// Any still-unused token of the same purpose for the user is superseded, so only
// the newest link works. If a token of this purpose was issued less than cooldown
// ago, nothing is done and false is returned: that stops an attacker (or a
// double click) from using the endpoint to flood someone's inbox.
func (s *AppStore) IssueEmailToken(ctx context.Context, userID string, purpose EmailPurpose, tokenHash []byte, now, expiresAt time.Time, cooldown time.Duration, msg OutboxMessage) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("issue email token: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if cooldown > 0 {
		var recent bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM verification_tokens
			                WHERE application_id = $1 AND user_id = $2 AND purpose = $3 AND created_at > $4)`,
			s.appID, userID, string(purpose), now.Add(-cooldown)).Scan(&recent); err != nil {
			return false, fmt.Errorf("check cooldown: %w", err)
		}
		if recent {
			return false, nil
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE verification_tokens SET used_at = $4
		 WHERE application_id = $1 AND user_id = $2 AND purpose = $3 AND used_at IS NULL`,
		s.appID, userID, string(purpose), now); err != nil {
		return false, fmt.Errorf("supersede old tokens: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO verification_tokens (application_id, user_id, purpose, token_hash, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		s.appID, userID, string(purpose), tokenHash, now, expiresAt); err != nil {
		return false, fmt.Errorf("insert token: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO email_outbox (application_id, kind, to_email, payload, next_attempt_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $5)`,
		s.appID, string(msg.Kind), msg.ToEmail, msg.Payload, now); err != nil {
		return false, fmt.Errorf("queue email: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("issue email token: %w", err)
	}
	return true, nil
}

// spendToken marks a live token of the given purpose as used and returns its
// user. "Live" means unused and unexpired, and it must belong to THIS application:
// a token issued by another application finds no row. Every failure mode (never
// existed, expired, already used, other application) is the same ErrNotFound.
func spendToken(ctx context.Context, tx pgx.Tx, appID string, tokenHash []byte, purpose EmailPurpose, now time.Time) (string, error) {
	var userID string
	err := tx.QueryRow(ctx,
		`UPDATE verification_tokens SET used_at = $4
		 WHERE application_id = $1 AND token_hash = $2 AND purpose = $3
		   AND used_at IS NULL AND expires_at > $4
		 RETURNING user_id::text`,
		appID, tokenHash, string(purpose), now).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("spend token: %w", err)
	}
	return userID, nil
}

// ConsumeVerifyToken spends a verification token and marks the user's email as
// verified, atomically. A second use of the same token fails.
func (s *AppStore) ConsumeVerifyToken(ctx context.Context, tokenHash []byte, now time.Time) (User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("verify email: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	userID, err := spendToken(ctx, tx, s.appID, tokenHash, PurposeVerify, now)
	if err != nil {
		return User{}, err
	}
	u, err := scanUser(tx.QueryRow(ctx,
		`UPDATE users SET email_verified_at = COALESCE(email_verified_at, $3), updated_at = $3
		 WHERE application_id = $1 AND id = $2 RETURNING `+userColumns, s.appID, userID, now))
	if err != nil {
		return User{}, fmt.Errorf("mark verified: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("verify email: %w", err)
	}
	return u, nil
}

// ResetPassword spends a reset token, sets the new password hash, and revokes
// every session of that user, all in one transaction: there is no moment where
// the password has changed but old sessions still work. The user also counts as
// email-verified afterwards, since they just proved control of the inbox.
func (s *AppStore) ResetPassword(ctx context.Context, tokenHash []byte, newPasswordHash string, now time.Time) (User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("reset password: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	userID, err := spendToken(ctx, tx, s.appID, tokenHash, PurposeReset, now)
	if err != nil {
		return User{}, err
	}
	u, err := scanUser(tx.QueryRow(ctx,
		`UPDATE users SET password_hash = $3, email_verified_at = COALESCE(email_verified_at, $4), updated_at = $4
		 WHERE application_id = $1 AND id = $2 RETURNING `+userColumns, s.appID, userID, newPasswordHash, now))
	if err != nil {
		return User{}, fmt.Errorf("set password: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET revoked_at = $3
		 WHERE application_id = $1 AND user_id = $2 AND revoked_at IS NULL`, s.appID, userID, now); err != nil {
		return User{}, fmt.Errorf("revoke sessions: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE verification_tokens SET used_at = $3
		 WHERE application_id = $1 AND user_id = $2 AND purpose = 'reset' AND used_at IS NULL`,
		s.appID, userID, now); err != nil {
		return User{}, fmt.Errorf("spend other reset tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("reset password: %w", err)
	}
	return u, nil
}

// DeleteExpiredVerificationTokens removes tokens that are a day past expiry or
// a day past use, across all applications (maintenance).
func (s *Store) DeleteExpiredVerificationTokens(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`-- cross-tenant: maintenance
		 DELETE FROM verification_tokens
		 WHERE expires_at <= $1::timestamptz - interval '1 day'
		    OR used_at    <= $1::timestamptz - interval '1 day'`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
