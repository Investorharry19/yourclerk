package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Investorharry19/yourclerk/internal/store"
)

// fakeUsers is an in-memory UserStore that mimics the database's unique email rule.
type fakeUsers struct {
	mu    sync.Mutex
	users map[string]store.User
}

func newFakeUsers() *fakeUsers { return &fakeUsers{users: map[string]store.User{}} }

func (f *fakeUsers) CreateUser(_ context.Context, email, hash string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[email]; ok {
		return store.User{}, store.ErrEmailTaken
	}
	u := store.User{ID: "user-" + strconv.Itoa(len(f.users)+1), Email: email, PasswordHash: hash}
	f.users[email] = u
	return u, nil
}

func (f *fakeUsers) GetUserByEmail(_ context.Context, email string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[email]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func newUsersTestServer(users *fakeUsers) nethttp.Handler {
	return newSessionsServer(users, newFakeSessions(users), Options{})
}

func newSessionsServer(users *fakeUsers, sessions *fakeSessions, opts Options) nethttp.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(log, fakeDB{}, users, sessions, opts).Handler()
}

func post(h nethttp.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(nethttp.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func creds(email, pw string) string {
	b, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	return string(b)
}

func errorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body errorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad error json %q: %v", rr.Body.String(), err)
	}
	return body.Error.Code
}

func TestSignup(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"valid", creds("alice@example.com", "correct horse"), 201, ""},
		{"duplicate exact", creds("alice@example.com", "another password"), 409, "email_taken"},
		{"duplicate other case", creds("ALICE@Example.COM", "another password"), 409, "email_taken"},
		{"duplicate with spaces", creds("  alice@example.com ", "another password"), 409, "email_taken"},
		{"bad email", creds("not-an-email", "correct horse"), 422, "validation_error"},
		{"display name email", creds("Bob <bob@example.com>", "correct horse"), 422, "validation_error"},
		{"no dot in domain", creds("bob@localhost", "correct horse"), 422, "validation_error"},
		{"empty email", creds("", "correct horse"), 422, "validation_error"},
		{"short password", creds("bob@example.com", "short"), 422, "validation_error"},
		{"long password", creds("bob@example.com", strings.Repeat("a", 129)), 422, "validation_error"},
		{"not json", "hello", 400, "invalid_json"},
		{"unknown field", `{"email":"bob@example.com","password":"correct horse","admin":true}`, 400, "invalid_json"},
	}

	// Subtests share one server and run in order: the first creates alice.
	h := newUsersTestServer(newFakeUsers())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := post(h, "/v1/signup", tc.body)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantCode != "" {
				if got := errorCode(t, rr); got != tc.wantCode {
					t.Fatalf("code = %q, want %q", got, tc.wantCode)
				}
			}
		})
	}
}

func TestSignupStoresOnlyHashes(t *testing.T) {
	users := newFakeUsers()
	h := newUsersTestServer(users)

	const pw = "shared password 123"
	for _, email := range []string{"one@example.com", "two@example.com"} {
		rr := post(h, "/v1/signup", creds(email, pw))
		if rr.Code != 201 {
			t.Fatalf("signup %s: %d %s", email, rr.Code, rr.Body.String())
		}
		if bytes.Contains(rr.Body.Bytes(), []byte(pw)) || strings.Contains(rr.Body.String(), "argon2") {
			t.Fatalf("response leaks password or hash: %s", rr.Body.String())
		}
	}

	one, two := users.users["one@example.com"], users.users["two@example.com"]
	for _, u := range []store.User{one, two} {
		if !strings.HasPrefix(u.PasswordHash, "$argon2id$") || strings.Contains(u.PasswordHash, pw) {
			t.Fatalf("stored value is not an encoded hash: %q", u.PasswordHash)
		}
	}
	if one.PasswordHash == two.PasswordHash {
		t.Fatal("same password produced identical hashes")
	}
}

func TestLogin(t *testing.T) {
	h := newUsersTestServer(newFakeUsers())
	if rr := post(h, "/v1/signup", creds("alice@example.com", "correct horse")); rr.Code != 201 {
		t.Fatalf("setup signup: %d %s", rr.Code, rr.Body.String())
	}

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"correct", creds("alice@example.com", "correct horse"), 200, ""},
		{"email in other case", creds("Alice@Example.com", "correct horse"), 200, ""},
		{"wrong password", creds("alice@example.com", "wrong password"), 401, "invalid_credentials"},
		{"unknown user", creds("nobody@example.com", "correct horse"), 401, "invalid_credentials"},
		{"malformed email", creds("???", "correct horse"), 401, "invalid_credentials"},
		{"not json", "nope", 400, "invalid_json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := post(h, "/v1/login", tc.body)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantCode != "" {
				if got := errorCode(t, rr); got != tc.wantCode {
					t.Fatalf("code = %q, want %q", got, tc.wantCode)
				}
			}
		})
	}
}

func TestLoginErrorsAreIdentical(t *testing.T) {
	h := newUsersTestServer(newFakeUsers())
	post(h, "/v1/signup", creds("alice@example.com", "correct horse"))

	wrongPassword := post(h, "/v1/login", creds("alice@example.com", "wrong password"))
	unknownUser := post(h, "/v1/login", creds("nobody@example.com", "wrong password"))

	if wrongPassword.Code != unknownUser.Code {
		t.Fatalf("status differs: %d vs %d", wrongPassword.Code, unknownUser.Code)
	}
	if wrongPassword.Body.String() != unknownUser.Body.String() {
		t.Fatalf("body differs:\n%s\n%s", wrongPassword.Body.String(), unknownUser.Body.String())
	}
}
