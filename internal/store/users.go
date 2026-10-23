package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound   = errors.New("store: not found")
	ErrEmailTaken = errors.New("store: email already taken")
)

// pgUniqueViolation is Postgres error code 23505.
const pgUniqueViolation = "23505"

type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const userColumns = "id::text, email, password_hash, created_at, updated_at"

// CreateUser inserts a user. The email must already be normalised (lower case);
// the database rejects anything else. A duplicate email returns ErrEmailTaken.
func (s *Store) CreateUser(ctx context.Context, email, passwordHash string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING `+userColumns,
		email, passwordHash,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail looks a user up by normalised email. Returns ErrNotFound if absent.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}
