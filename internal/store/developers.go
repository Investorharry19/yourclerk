package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Developer struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// Developers is the dashboard-side account store: developers and their sign-in sessions.
type Developers interface {
	CreateDeveloper(ctx context.Context, email, passwordHash string) (Developer, error)
	GetDeveloperByEmail(ctx context.Context, email string) (Developer, error)
	CreateDeveloperSession(ctx context.Context, developerID string, tokenHash []byte, now, expiresAt time.Time) error
	GetLiveDeveloperSession(ctx context.Context, tokenHash []byte, now time.Time) (Developer, error)
	RevokeDeveloperSession(ctx context.Context, tokenHash []byte, now time.Time) error
}

const developerColumns = "id::text, email, password_hash, created_at"

func scanDeveloper(row pgx.Row) (Developer, error) {
	var d Developer
	err := row.Scan(&d.ID, &d.Email, &d.PasswordHash, &d.CreatedAt)
	return d, err
}

func (s *Store) CreateDeveloper(ctx context.Context, email, passwordHash string) (Developer, error) {
	d, err := scanDeveloper(s.Pool.QueryRow(ctx,
		`INSERT INTO developers (email, password_hash) VALUES ($1, $2) RETURNING `+developerColumns, email, passwordHash))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return Developer{}, ErrEmailTaken
		}
		return Developer{}, fmt.Errorf("create developer: %w", err)
	}
	return d, nil
}

func (s *Store) GetDeveloperByEmail(ctx context.Context, email string) (Developer, error) {
	d, err := scanDeveloper(s.Pool.QueryRow(ctx,
		`SELECT `+developerColumns+` FROM developers WHERE email = $1`, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return Developer{}, ErrNotFound
	}
	if err != nil {
		return Developer{}, fmt.Errorf("get developer: %w", err)
	}
	return d, nil
}

func (s *Store) CreateDeveloperSession(ctx context.Context, developerID string, tokenHash []byte, now, expiresAt time.Time) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO developer_sessions (developer_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		developerID, tokenHash, now, expiresAt)
	if err != nil {
		return fmt.Errorf("create developer session: %w", err)
	}
	return nil
}

func (s *Store) GetLiveDeveloperSession(ctx context.Context, tokenHash []byte, now time.Time) (Developer, error) {
	d, err := scanDeveloper(s.Pool.QueryRow(ctx,
		`SELECT d.id::text, d.email, d.password_hash, d.created_at
		 FROM developer_sessions ds JOIN developers d ON d.id = ds.developer_id
		 WHERE ds.token_hash = $1 AND ds.revoked_at IS NULL AND ds.expires_at > $2`, tokenHash, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return Developer{}, ErrNotFound
	}
	if err != nil {
		return Developer{}, fmt.Errorf("get developer session: %w", err)
	}
	return d, nil
}

func (s *Store) RevokeDeveloperSession(ctx context.Context, tokenHash []byte, now time.Time) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE developer_sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash, now)
	if err != nil {
		return fmt.Errorf("revoke developer session: %w", err)
	}
	return nil
}

var _ Developers = (*Store)(nil)
