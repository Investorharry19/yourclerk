package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplicationSettings are the per-application knobs a developer controls.
type ApplicationSettings struct {
	AllowedOrigins     []string
	SessionLifetime    time.Duration // absolute lifetime of a session
	SessionIdleTimeout time.Duration // sign-out after this long without activity
	SignupEnabled      bool
}

// Application is one tenant. The secret key is never part of it: only its hash
// is stored, and only the last four characters are kept for display.
type Application struct {
	ID             string
	DeveloperID    string
	Name           string
	PublishableKey string
	SecretKeyLast4 string
	Settings       ApplicationSettings
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewApplication carries the values to create one. SecretKeyHash is the hash
// of a secret key the caller generated and shows to the developer once.
type NewApplication struct {
	DeveloperID    string
	Name           string
	PublishableKey string
	SecretKeyHash  []byte
	SecretKeyLast4 string
}

// AppRegistry finds applications from the credential a request carries. It is
// how a request becomes tenant-bound; it is not itself tenant data.
type AppRegistry interface {
	ApplicationByPublishableKey(ctx context.Context, key string) (Application, error)
	ApplicationBySecretKeyHash(ctx context.Context, hash []byte) (Application, error)
	ApplicationByID(ctx context.Context, id string) (Application, error)
}

// DeveloperApps is what a signed-in developer may do with their own applications.
// Every method takes the developer id and refuses applications owned by others.
type DeveloperApps interface {
	CreateApplication(ctx context.Context, a NewApplication) (Application, error)
	ListApplications(ctx context.Context, developerID string) ([]Application, error)
	GetApplication(ctx context.Context, developerID, appID string) (Application, error)
	UpdateApplication(ctx context.Context, developerID, appID, name string, s ApplicationSettings) (Application, error)
	RollSecretKey(ctx context.Context, developerID, appID string, hash []byte, last4 string) (Application, error)
}

const applicationColumns = `id::text, developer_id::text, name, publishable_key, secret_key_last4,
	allowed_origins, session_lifetime_seconds, session_idle_timeout_seconds, signup_enabled, created_at, updated_at`

func scanApplication(row pgx.Row) (Application, error) {
	var (
		a             Application
		life, idle    int
		originsNonNil []string
	)
	err := row.Scan(&a.ID, &a.DeveloperID, &a.Name, &a.PublishableKey, &a.SecretKeyLast4,
		&originsNonNil, &life, &idle, &a.Settings.SignupEnabled, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return Application{}, err
	}
	a.Settings.AllowedOrigins = originsNonNil
	if a.Settings.AllowedOrigins == nil {
		a.Settings.AllowedOrigins = []string{}
	}
	a.Settings.SessionLifetime = time.Duration(life) * time.Second
	a.Settings.SessionIdleTimeout = time.Duration(idle) * time.Second
	return a, nil
}

func oneApp(row pgx.Row, what string) (Application, error) {
	a, err := scanApplication(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, ErrNotFound
	}
	if err != nil {
		return Application{}, fmt.Errorf("%s: %w", what, err)
	}
	return a, nil
}

func (s *Store) ApplicationByPublishableKey(ctx context.Context, key string) (Application, error) {
	return oneApp(s.Pool.QueryRow(ctx,
		`SELECT `+applicationColumns+` FROM applications WHERE publishable_key = $1`, key), "application by publishable key")
}

func (s *Store) ApplicationBySecretKeyHash(ctx context.Context, hash []byte) (Application, error) {
	return oneApp(s.Pool.QueryRow(ctx,
		`SELECT `+applicationColumns+` FROM applications WHERE secret_key_hash = $1`, hash), "application by secret key")
}

func (s *Store) ApplicationByID(ctx context.Context, id string) (Application, error) {
	if !uuidRE.MatchString(id) {
		return Application{}, ErrNotFound
	}
	return oneApp(s.Pool.QueryRow(ctx,
		`SELECT `+applicationColumns+` FROM applications WHERE id = $1`, id), "application by id")
}

func (s *Store) CreateApplication(ctx context.Context, a NewApplication) (Application, error) {
	return oneApp(s.Pool.QueryRow(ctx,
		`INSERT INTO applications (developer_id, name, publishable_key, secret_key_hash, secret_key_last4)
		 VALUES ($1, $2, $3, $4, $5) RETURNING `+applicationColumns,
		a.DeveloperID, a.Name, a.PublishableKey, a.SecretKeyHash, a.SecretKeyLast4), "create application")
}

func (s *Store) ListApplications(ctx context.Context, developerID string) ([]Application, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+applicationColumns+` FROM applications WHERE developer_id = $1 ORDER BY created_at, id`, developerID)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()
	out := []Application{}
	for rows.Next() {
		a, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetApplication(ctx context.Context, developerID, appID string) (Application, error) {
	if !uuidRE.MatchString(appID) {
		return Application{}, ErrNotFound
	}
	return oneApp(s.Pool.QueryRow(ctx,
		`SELECT `+applicationColumns+` FROM applications WHERE developer_id = $1 AND id = $2`, developerID, appID), "get application")
}

func (s *Store) UpdateApplication(ctx context.Context, developerID, appID, name string, st ApplicationSettings) (Application, error) {
	if !uuidRE.MatchString(appID) {
		return Application{}, ErrNotFound
	}
	origins := st.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	return oneApp(s.Pool.QueryRow(ctx,
		`UPDATE applications SET name = $3, allowed_origins = $4, session_lifetime_seconds = $5,
		        session_idle_timeout_seconds = $6, signup_enabled = $7, updated_at = now()
		 WHERE developer_id = $1 AND id = $2 RETURNING `+applicationColumns,
		developerID, appID, name, origins,
		int(st.SessionLifetime/time.Second), int(st.SessionIdleTimeout/time.Second), st.SignupEnabled), "update application")
}

// RollSecretKey replaces an application's secret key hash. The old key stops
// working immediately.
func (s *Store) RollSecretKey(ctx context.Context, developerID, appID string, hash []byte, last4 string) (Application, error) {
	if !uuidRE.MatchString(appID) {
		return Application{}, ErrNotFound
	}
	return oneApp(s.Pool.QueryRow(ctx,
		`UPDATE applications SET secret_key_hash = $3, secret_key_last4 = $4, updated_at = now()
		 WHERE developer_id = $1 AND id = $2 RETURNING `+applicationColumns,
		developerID, appID, hash, last4), "roll secret key")
}

var (
	_ AppRegistry   = (*Store)(nil)
	_ DeveloperApps = (*Store)(nil)
)
