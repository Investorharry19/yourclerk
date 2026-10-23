package http

import (
	"context"
	"encoding/json"
	"errors"
	nethttp "net/http"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/Investorharry19/yourclerk/internal/password"
	"github.com/Investorharry19/yourclerk/internal/store"
)

const (
	minPasswordLen = 8
	maxPasswordLen = 128
	maxEmailLen    = 254
	maxBodyBytes   = 1 << 20
)

// UserStore is the slice of the database the auth handlers need.
// *store.Store satisfies it; tests use an in-memory fake.
type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash string) (store.User, error)
	GetUserByEmail(ctx context.Context, email string) (store.User, error)
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func toUserResponse(u store.User) userResponse {
	return userResponse{ID: u.ID, Email: u.Email}
}

func decodeJSON(w nethttp.ResponseWriter, r *nethttp.Request, dst any) bool {
	r.Body = nethttp.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		WriteError(w, nethttp.StatusBadRequest, "invalid_json", "Request body must be valid JSON with only the expected fields")
		return false
	}
	return true
}

// normalizeEmail trims and lower-cases the address and checks its shape.
// It rejects display-name forms such as "Bob <bob@x.com>".
func normalizeEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" || len(e) > maxEmailLen {
		return "", false
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e {
		return "", false
	}
	at := strings.LastIndex(e, "@")
	if at < 1 || !strings.Contains(e[at+1:], ".") {
		return "", false
	}
	return e, true
}

func validatePassword(p string) string {
	n := utf8.RuneCountInString(p)
	switch {
	case n < minPasswordLen:
		return "Password must be at least 8 characters"
	case n > maxPasswordLen:
		return "Password must be at most 128 characters"
	}
	return ""
}

func (s *Server) handleSignup(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}

	email, ok := normalizeEmail(in.Email)
	if !ok {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", "Enter a valid email address")
		return
	}
	if msg := validatePassword(in.Password); msg != "" {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", msg)
		return
	}

	hash, err := password.Hash(in.Password)
	if err != nil {
		s.log.Error("signup: hash password", "err", err)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}

	user, err := s.users.CreateUser(r.Context(), email, hash)
	switch {
	case errors.Is(err, store.ErrEmailTaken):
		// Signup necessarily reveals that an email is registered. Stage 5
		// (email verification) is where this gets closed properly.
		WriteError(w, nethttp.StatusConflict, "email_taken", "An account with this email already exists")
		return
	case err != nil:
		s.log.Error("signup: create user", "err", err)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}

	WriteJSON(w, nethttp.StatusCreated, toUserResponse(user))
}

func (s *Server) handleLogin(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}

	var (
		user  store.User
		found bool
	)
	if email, ok := normalizeEmail(in.Email); ok {
		u, err := s.users.GetUserByEmail(r.Context(), email)
		switch {
		case err == nil:
			user, found = u, true
		case errors.Is(err, store.ErrNotFound):
			// fall through to the dummy verify below
		default:
			s.log.Error("login: get user", "err", err)
			WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
			return
		}
	}

	if !found {
		// Same CPU cost as a real check, same response as a wrong password.
		password.DummyVerify(in.Password)
		writeInvalidCredentials(w)
		return
	}

	match, err := password.Verify(in.Password, user.PasswordHash)
	if err != nil {
		s.log.Error("login: verify password", "err", err, "user_id", user.ID)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	if !match {
		writeInvalidCredentials(w)
		return
	}

	// Stage 1 only reports success. Stage 2 will create a session here.
	WriteJSON(w, nethttp.StatusOK, map[string]any{"user": toUserResponse(user)})
}

func writeInvalidCredentials(w nethttp.ResponseWriter) {
	WriteError(w, nethttp.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
}
