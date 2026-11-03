package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const userColumns = "id::text, email, password_hash, created_at, updated_at"

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// CreateUser inserts a user into this application. The email must already be
// normalised (lower case). A duplicate within the application returns
// ErrEmailTaken; the same email in another application is a different user.
func (s *AppStore) CreateUser(ctx context.Context, email, passwordHash string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx,
		`INSERT INTO users (application_id, email, password_hash) VALUES ($1, $2, $3) RETURNING `+userColumns,
		s.appID, email, passwordHash))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail looks a user up by normalised email within this application.
func (s *AppStore) GetUserByEmail(ctx context.Context, email string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE application_id = $1 AND email = $2`, s.appID, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetUserByID looks a user up by id within this application. A malformed id or
// an id belonging to another application is simply ErrNotFound.
func (s *AppStore) GetUserByID(ctx context.Context, userID string) (User, error) {
	if !uuidRE.MatchString(userID) {
		return User{}, ErrNotFound
	}
	u, err := scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE application_id = $1 AND id = $2`, s.appID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// ListUsers returns this application's users, newest first.
func (s *AppStore) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+userColumns+` FROM users WHERE application_id = $1
		 ORDER BY created_at DESC, id LIMIT $2 OFFSET $3`, s.appID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}
