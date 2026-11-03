package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

// Store implements auth.KeyStore.
var _ auth.KeyStore = (*Store)(nil)

const signingKeyColumns = "kid, algorithm, public_key, private_key_encrypted, created_at, active_from, retired_at"

func scanSigningKey(row pgx.Row) (auth.SigningKey, error) {
	var k auth.SigningKey
	err := row.Scan(&k.KID, &k.Algorithm, &k.PublicKey, &k.PrivateKeyEncrypted, &k.CreatedAt, &k.ActiveFrom, &k.RetiredAt)
	return k, err
}

func (s *Store) CreateSigningKey(ctx context.Context, k auth.SigningKey) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO signing_keys (`+signingKeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		k.KID, k.Algorithm, k.PublicKey, k.PrivateKeyEncrypted, k.CreatedAt, k.ActiveFrom, k.RetiredAt)
	if err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}
	return nil
}

// ActiveSigningKey returns the key that signs at time now: the newest key whose
// active_from has passed and that is not retired by now.
func (s *Store) ActiveSigningKey(ctx context.Context, now time.Time) (auth.SigningKey, error) {
	k, err := scanSigningKey(s.Pool.QueryRow(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys
		 WHERE active_from <= $1 AND (retired_at IS NULL OR retired_at > $1)
		 ORDER BY active_from DESC, created_at DESC LIMIT 1`, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.SigningKey{}, auth.ErrNoSigningKey
	}
	if err != nil {
		return auth.SigningKey{}, fmt.Errorf("active signing key: %w", err)
	}
	return k, nil
}

// PublishedSigningKeys returns every key that belongs in the JWKS: keys not
// retired, pending keys, and keys retired after retiredAfter. Newest first.
func (s *Store) PublishedSigningKeys(ctx context.Context, retiredAfter time.Time) ([]auth.SigningKey, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys
		 WHERE retired_at IS NULL OR retired_at > $1
		 ORDER BY created_at DESC`, retiredAfter)
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

// RotateSigningKey schedules every not-yet-retired key to retire at k.ActiveFrom
// and inserts k, in one transaction. The old key keeps signing until then and
// k is already published, so there is never a moment with no signing key and
// never a token signed with a key verifiers have not been able to fetch.
func (s *Store) RotateSigningKey(ctx context.Context, k auth.SigningKey) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rotate signing key: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `UPDATE signing_keys SET retired_at = $1 WHERE retired_at IS NULL`, k.ActiveFrom); err != nil {
		return fmt.Errorf("schedule retirement: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO signing_keys (`+signingKeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6, NULL)`,
		k.KID, k.Algorithm, k.PublicKey, k.PrivateKeyEncrypted, k.CreatedAt, k.ActiveFrom); err != nil {
		return fmt.Errorf("insert signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rotate signing key: %w", err)
	}
	return nil
}
