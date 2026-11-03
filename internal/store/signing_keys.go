package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

const signingKeyColumns = "kid, algorithm, public_key, private_key_encrypted, created_at, active_from, retired_at"

func scanSigningKey(row pgx.Row) (auth.SigningKey, error) {
	var k auth.SigningKey
	err := row.Scan(&k.KID, &k.Algorithm, &k.PublicKey, &k.PrivateKeyEncrypted, &k.CreatedAt, &k.ActiveFrom, &k.RetiredAt)
	return k, err
}

func (s *AppStore) CreateSigningKey(ctx context.Context, k auth.SigningKey) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO signing_keys (application_id, `+signingKeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		s.appID, k.KID, k.Algorithm, k.PublicKey, k.PrivateKeyEncrypted, k.CreatedAt, k.ActiveFrom, k.RetiredAt)
	if err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}
	return nil
}

// ActiveSigningKey returns the key that signs at time now: the application's
// newest key whose active_from has passed and that is not retired by now.
func (s *AppStore) ActiveSigningKey(ctx context.Context, now time.Time) (auth.SigningKey, error) {
	k, err := scanSigningKey(s.pool.QueryRow(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys
		 WHERE application_id = $1 AND active_from <= $2 AND (retired_at IS NULL OR retired_at > $2)
		 ORDER BY active_from DESC, created_at DESC LIMIT 1`, s.appID, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.SigningKey{}, auth.ErrNoSigningKey
	}
	if err != nil {
		return auth.SigningKey{}, fmt.Errorf("active signing key: %w", err)
	}
	return k, nil
}

// PublishedSigningKeys returns every key of this application that belongs in
// its JWKS: keys not retired, pending keys, and keys retired after
// retiredAfter. Newest first.
func (s *AppStore) PublishedSigningKeys(ctx context.Context, retiredAfter time.Time) ([]auth.SigningKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys
		 WHERE application_id = $1 AND (retired_at IS NULL OR retired_at > $2)
		 ORDER BY created_at DESC, active_from DESC`, s.appID, retiredAfter)
	if err != nil {
		return nil, fmt.Errorf("published signing keys: %w", err)
	}
	defer rows.Close()

	var out []auth.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("published signing keys: %w", err)
	}
	return out, nil
}

// RotateSigningKey schedules every not-yet-retired key of this application to
// retire at k.ActiveFrom and inserts k, in one transaction. The old key keeps
// signing until then and k is already published, so there is never a moment
// with no signing key and never a token signed with a key verifiers have not
// been able to fetch. Other applications' keys are untouched.
func (s *AppStore) RotateSigningKey(ctx context.Context, k auth.SigningKey) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rotate signing key: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET retired_at = $2 WHERE application_id = $1 AND retired_at IS NULL`,
		s.appID, k.ActiveFrom); err != nil {
		return fmt.Errorf("schedule retirement: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO signing_keys (application_id, `+signingKeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`,
		s.appID, k.KID, k.Algorithm, k.PublicKey, k.PrivateKeyEncrypted, k.CreatedAt, k.ActiveFrom); err != nil {
		return fmt.Errorf("insert signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rotate signing key: %w", err)
	}
	return nil
}
