package http

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

// fakeWorld is an in-memory stand-in for the whole store: developers,
// applications and per-application tenants. It follows the same rules as the
// SQL (email unique per application, every tenant query scoped by application,
// same liveness rules for sessions), and TestRealStoreEndToEnd runs the same
// flows against Postgres to keep the two honest.
type fakeWorld struct {
	mu          sync.Mutex
	n           int
	devs        map[string]*store.Developer // by email
	devSessions map[string]*fakeDevSession  // by token hash
	apps        []*fakeApp
	tenants     map[string]*fakeTenant
}

type fakeDevSession struct {
	devID   string
	expires time.Time
	revoked bool
}

type fakeApp struct {
	store.Application
	skHash string
}

func newFakeWorld() *fakeWorld {
	return &fakeWorld{devs: map[string]*store.Developer{}, devSessions: map[string]*fakeDevSession{}, tenants: map[string]*fakeTenant{}}
}

func (w *fakeWorld) id(prefix string) string {
	w.n++
	return fmt.Sprintf("%s0000000-0000-4000-8000-%012d", prefix, w.n)
}

// --- store.Developers ---

func (w *fakeWorld) CreateDeveloper(_ context.Context, email, hash string) (store.Developer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.devs[email]; ok {
		return store.Developer{}, store.ErrEmailTaken
	}
	d := &store.Developer{ID: w.id("d"), Email: email, PasswordHash: hash, CreatedAt: time.Now()}
	w.devs[email] = d
	return *d, nil
}

func (w *fakeWorld) GetDeveloperByEmail(_ context.Context, email string) (store.Developer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if d, ok := w.devs[email]; ok {
		return *d, nil
	}
	return store.Developer{}, store.ErrNotFound
}

func (w *fakeWorld) CreateDeveloperSession(_ context.Context, devID string, hash []byte, _, exp time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.devSessions[string(hash)] = &fakeDevSession{devID: devID, expires: exp}
	return nil
}

func (w *fakeWorld) GetLiveDeveloperSession(_ context.Context, hash []byte, now time.Time) (store.Developer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.devSessions[string(hash)]
	if !ok || s.revoked || !s.expires.After(now) {
		return store.Developer{}, store.ErrNotFound
	}
	for _, d := range w.devs {
		if d.ID == s.devID {
			return *d, nil
		}
	}
	return store.Developer{}, store.ErrNotFound
}

func (w *fakeWorld) RevokeDeveloperSession(_ context.Context, hash []byte, _ time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.devSessions[string(hash)]; ok {
		s.revoked = true
	}
	return nil
}

// --- store.AppRegistry / store.DeveloperApps ---

func (w *fakeWorld) find(match func(*fakeApp) bool) (*fakeApp, bool) {
	for _, a := range w.apps {
		if match(a) {
			return a, true
		}
	}
	return nil, false
}

func (w *fakeWorld) ApplicationByPublishableKey(_ context.Context, key string) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a, ok := w.find(func(a *fakeApp) bool { return a.PublishableKey == key }); ok {
		return a.Application, nil
	}
	return store.Application{}, store.ErrNotFound
}

func (w *fakeWorld) ApplicationBySecretKeyHash(_ context.Context, hash []byte) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a, ok := w.find(func(a *fakeApp) bool { return a.skHash == string(hash) }); ok {
		return a.Application, nil
	}
	return store.Application{}, store.ErrNotFound
}

func (w *fakeWorld) ApplicationByID(_ context.Context, id string) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a, ok := w.find(func(a *fakeApp) bool { return a.ID == id }); ok {
		return a.Application, nil
	}
	return store.Application{}, store.ErrNotFound
}

func (w *fakeWorld) CreateApplication(_ context.Context, n store.NewApplication) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	a := &fakeApp{skHash: string(n.SecretKeyHash)}
	a.Application = store.Application{
		ID: w.id("a"), DeveloperID: n.DeveloperID, Name: n.Name, PublishableKey: n.PublishableKey,
		SecretKeyLast4: n.SecretKeyLast4, CreatedAt: time.Now(),
		Settings: store.ApplicationSettings{
			AllowedOrigins: []string{}, SessionLifetime: 30 * 24 * time.Hour,
			SessionIdleTimeout: 7 * 24 * time.Hour, SignupEnabled: true,
		},
	}
	w.apps = append(w.apps, a)
	return a.Application, nil
}

func (w *fakeWorld) ListApplications(_ context.Context, devID string) ([]store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []store.Application{}
	for _, a := range w.apps {
		if a.DeveloperID == devID {
			out = append(out, a.Application)
		}
	}
	return out, nil
}

func (w *fakeWorld) owned(devID, appID string) (*fakeApp, bool) {
	return w.find(func(a *fakeApp) bool { return a.ID == appID && a.DeveloperID == devID })
}

func (w *fakeWorld) GetApplication(_ context.Context, devID, appID string) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a, ok := w.owned(devID, appID); ok {
		return a.Application, nil
	}
	return store.Application{}, store.ErrNotFound
}

func (w *fakeWorld) UpdateApplication(_ context.Context, devID, appID, name string, st store.ApplicationSettings) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	a, ok := w.owned(devID, appID)
	if !ok {
		return store.Application{}, store.ErrNotFound
	}
	a.Name, a.Settings = name, st
	return a.Application, nil
}

func (w *fakeWorld) RollSecretKey(_ context.Context, devID, appID string, hash []byte, last4 string) (store.Application, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	a, ok := w.owned(devID, appID)
	if !ok {
		return store.Application{}, store.ErrNotFound
	}
	a.skHash, a.SecretKeyLast4 = string(hash), last4
	return a.Application, nil
}

// --- TenantProvider ---

func (w *fakeWorld) ForApp(appID string) store.Tenant {
	w.mu.Lock()
	defer w.mu.Unlock()
	t, ok := w.tenants[appID]
	if !ok {
		t = &fakeTenant{w: w}
		w.tenants[appID] = t
	}
	return t
}

// fakeTenant holds one application's users and sessions. There is no way to
// reach another application's data through it.
type fakeTenant struct {
	w        *fakeWorld
	mu       sync.Mutex
	users    []store.User
	sessions []*fakeSession
	touches  int
}

type fakeSession struct {
	store.Session
	hash    string
	revoked bool
}

func (t *fakeTenant) CreateUser(_ context.Context, email, hash string) (store.User, error) {
	t.w.mu.Lock()
	id := t.w.id("u")
	t.w.mu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, u := range t.users {
		if u.Email == email {
			return store.User{}, store.ErrEmailTaken
		}
	}
	u := store.User{ID: id, Email: email, PasswordHash: hash, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	t.users = append(t.users, u)
	return u, nil
}

func (t *fakeTenant) GetUserByEmail(_ context.Context, email string) (store.User, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, u := range t.users {
		if u.Email == email {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

func (t *fakeTenant) GetUserByID(_ context.Context, id string) (store.User, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, u := range t.users {
		if u.ID == id {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

func (t *fakeTenant) ListUsers(_ context.Context, limit, offset int) ([]store.User, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []store.User
	for i := len(t.users) - 1; i >= 0; i-- { // newest first
		out = append(out, t.users[i])
	}
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *fakeTenant) live(s *fakeSession, now, idleCutoff time.Time) bool {
	return !s.revoked && s.ExpiresAt.After(now) && s.LastActiveAt.After(idleCutoff)
}

func (t *fakeTenant) CreateSession(_ context.Context, userID string, hash []byte, ua, ip string, now, exp time.Time) (store.Session, error) {
	t.w.mu.Lock()
	id := t.w.id("s")
	t.w.mu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	known := false
	for _, u := range t.users {
		known = known || u.ID == userID
	}
	if !known { // the composite foreign key
		return store.Session{}, fmt.Errorf("fake: user %s is not in this application", userID)
	}
	s := store.Session{ID: id, UserID: userID, UserAgent: ua, IP: ip, CreatedAt: now, LastActiveAt: now, ExpiresAt: exp}
	t.sessions = append(t.sessions, &fakeSession{Session: s, hash: string(hash)})
	return s, nil
}

func (t *fakeTenant) GetLiveSession(ctx context.Context, hash []byte, now, idleCutoff time.Time) (store.Session, store.User, error) {
	t.mu.Lock()
	var found *fakeSession
	for _, s := range t.sessions {
		if s.hash == string(hash) && t.live(s, now, idleCutoff) {
			found = s
		}
	}
	var sess store.Session
	if found != nil {
		sess = found.Session
	}
	t.mu.Unlock()
	if found == nil {
		return store.Session{}, store.User{}, store.ErrNotFound
	}
	u, err := t.GetUserByID(ctx, sess.UserID)
	return sess, u, err
}

func (t *fakeTenant) TouchSession(_ context.Context, id string, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		if s.ID == id {
			s.LastActiveAt = now
			t.touches++
		}
	}
	return nil
}

func (t *fakeTenant) ListLiveSessions(_ context.Context, userID string, now, idleCutoff time.Time) ([]store.Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []store.Session
	for i := len(t.sessions) - 1; i >= 0; i-- {
		if s := t.sessions[i]; s.UserID == userID && t.live(s, now, idleCutoff) {
			out = append(out, s.Session)
		}
	}
	return out, nil
}

func (t *fakeTenant) RevokeSession(_ context.Context, userID, sessionID string, _ time.Time) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		if s.ID == sessionID && s.UserID == userID && !s.revoked {
			s.revoked = true
			return true, nil
		}
	}
	return false, nil
}

var (
	_ store.AppRegistry   = (*fakeWorld)(nil)
	_ store.DeveloperApps = (*fakeWorld)(nil)
	_ store.Developers    = (*fakeWorld)(nil)
	_ TenantProvider      = (*fakeWorld)(nil)
	_ store.Tenant        = (*fakeTenant)(nil)
	_ TokenIssuer         = (*auth.TokenService)(nil)
)
