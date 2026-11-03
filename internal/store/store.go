// Package store owns the Postgres connection pool and every database query.
//
// Tenant data (users, sessions, signing keys) is only reachable through an
// AppStore, a handle bound to one application id. There is no method that reads
// or writes those tables without an application, so forgetting the tenant filter
// is a compile error rather than a data leak; TestTenantQueriesAreScoped also
// scans the SQL to keep it that way.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

type Store struct {
	Pool *pgxpool.Pool
}

// New opens a connection pool and verifies it with a ping.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Ping checks that the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.Pool.Ping(ctx) }

func (s *Store) Close() { s.Pool.Close() }

// ForApp returns the handle for one application's data.
func (s *Store) ForApp(appID string) Tenant { return &AppStore{pool: s.Pool, appID: appID} }

// KeysFor returns the signing-key store of one application (auth.KeyStoreProvider).
func (s *Store) KeysFor(appID string) auth.KeyStore { return &AppStore{pool: s.Pool, appID: appID} }

var (
	_ auth.KeyStoreProvider = (*Store)(nil)
	_ Tenant                = (*AppStore)(nil)
	_ auth.KeyStore         = (*AppStore)(nil)
)

// AppStore is bound to one application. Every query it runs filters on that id.
type AppStore struct {
	pool  poolLike
	appID string
}

// Tenant is everything the HTTP layer may do with one application's data.
type Tenant interface {
	CreateUser(ctx context.Context, email, passwordHash string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, userID string) (User, error)
	ListUsers(ctx context.Context, limit, offset int) ([]User, error)

	CreateSession(ctx context.Context, userID string, tokenHash []byte, userAgent, ip string, now, expiresAt time.Time) (Session, error)
	GetLiveSession(ctx context.Context, tokenHash []byte, now, idleCutoff time.Time) (Session, User, error)
	TouchSession(ctx context.Context, sessionID string, now time.Time) error
	ListLiveSessions(ctx context.Context, userID string, now, idleCutoff time.Time) ([]Session, error)
	RevokeSession(ctx context.Context, userID, sessionID string, now time.Time) (bool, error)
}
