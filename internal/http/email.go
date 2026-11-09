package http

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	appmail "github.com/Investorharry19/yourclerk/internal/mail"
	"github.com/Investorharry19/yourclerk/internal/password"
	"github.com/Investorharry19/yourclerk/internal/store"
)

const (
	// VerifyTokenTTL and ResetTokenTTL: a verification link lives a day, a
	// password-reset link only an hour, because it is the more dangerous one.
	VerifyTokenTTL = 24 * time.Hour
	ResetTokenTTL  = time.Hour
	// EmailCooldown is the minimum gap between two emails of the same kind to the
	// same user, so these endpoints cannot be used to flood an inbox.
	EmailCooldown = time.Minute
)

// EmailDeps configures outgoing account emails.
type EmailDeps struct {
	// Sealer encrypts queued messages (they contain live one-time links).
	Sealer *auth.Sealer
	// WebURL is the base URL of the page that handles the links, for example
	// "https://app.example.com". The emails link to WebURL/verify-email and
	// WebURL/reset-password, with the token in the URL fragment.
	WebURL string
}

func (e *EmailDeps) normalized() *EmailDeps {
	if e == nil || e.Sealer == nil {
		return nil
	}
	c := *e
	c.WebURL = strings.TrimRight(c.WebURL, "/")
	return &c
}

func humanDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		if h := int(d / time.Hour); h == 1 {
			return "1 hour"
		} else {
			return fmt.Sprintf("%d hours", h)
		}
	}
	return fmt.Sprintf("%d minutes", int(d/time.Minute))
}

// queueEmail creates a one-time token for the user and queues the email that
// carries it, atomically. It returns false when the per-user cooldown applies
// (nothing was created). Sending happens later, in the worker.
func (s *Server) queueEmail(ctx context.Context, app store.Application, user store.User, purpose store.EmailPurpose, cooldown time.Duration) (bool, error) {
	token, hash, err := auth.NewOneTimeToken()
	if err != nil {
		return false, err
	}
	var (
		msg appmail.Message
		ttl time.Duration
	)
	switch purpose {
	case store.PurposeVerify:
		ttl = VerifyTokenTTL
		link := s.email.WebURL + "/verify-email#token=" + token
		msg = appmail.VerificationEmail(user.Email, app.Name, link, token, humanDuration(ttl))
	case store.PurposeReset:
		ttl = ResetTokenTTL
		link := s.email.WebURL + "/reset-password#token=" + token
		msg = appmail.PasswordResetEmail(user.Email, app.Name, link, token, humanDuration(ttl))
	default:
		return false, fmt.Errorf("unknown purpose %q", purpose)
	}
	payload, err := appmail.Seal(s.email.Sealer, app.ID, msg)
	if err != nil {
		return false, err
	}
	now := s.opts.Now()
	return s.tenants.ForApp(app.ID).IssueEmailToken(ctx, user.ID, purpose, hash, now, now.Add(ttl), cooldown,
		store.OutboxMessage{Kind: purpose, ToEmail: user.Email, Payload: payload})
}

func writeInvalidToken(w nethttp.ResponseWriter) {
	// One message for every failure: unknown, expired, already used, wrong
	// application or wrong purpose. The caller learns nothing about which.
	WriteError(w, nethttp.StatusBadRequest, "invalid_token", "This link is invalid or has expired")
}

type tokenBody struct {
	Token string `json:"token"`
}

// handleVerifyEmail spends a verification token and marks the email verified.
func (s *Server) handleVerifyEmail(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in tokenBody
	if !decodeJSON(w, r, &in) {
		return
	}
	if !auth.IsWellFormedToken(in.Token) {
		writeInvalidToken(w)
		return
	}
	user, err := s.tenant(r).ConsumeVerifyToken(r.Context(), auth.HashToken(in.Token), s.opts.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeInvalidToken(w)
		return
	}
	if err != nil {
		s.internalError(w, "verify email", err)
		return
	}
	WriteJSON(w, nethttp.StatusOK, map[string]any{"user": toUserResponse(user)})
}

// handleResendVerification sends another verification email to the signed-in user.
func (s *Server) handleResendVerification(w nethttp.ResponseWriter, r *nethttp.Request) {
	if s.email == nil {
		WriteError(w, nethttp.StatusServiceUnavailable, "unavailable", "Email is not configured")
		return
	}
	app, _ := ApplicationFromContext(r.Context())
	user, _ := UserFromContext(r.Context())
	if user.EmailVerified() {
		WriteError(w, nethttp.StatusConflict, "already_verified", "This email address is already verified")
		return
	}
	queued, err := s.queueEmail(r.Context(), app, user, store.PurposeVerify, EmailCooldown)
	if err != nil {
		s.internalError(w, "resend verification", err, "user_id", user.ID)
		return
	}
	if !queued {
		w.Header().Set("Retry-After", fmt.Sprint(int(EmailCooldown/time.Second)))
		WriteError(w, nethttp.StatusTooManyRequests, "rate_limited", "A verification email was sent a moment ago. Try again in a minute")
		return
	}
	WriteJSON(w, nethttp.StatusAccepted, map[string]string{"message": "Verification email sent"})
}

const forgotResponse = "If an account exists for that email, we have sent instructions to reset the password."

// handleForgotPassword starts a reset. It answers identically, with the same
// status and body, whether or not the email belongs to a user, whether or not
// the address is even well formed, and even if something goes wrong on our
// side: otherwise the endpoint would be a free way to find out who has an account.
func (s *Server) handleForgotPassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if s.email == nil {
		WriteError(w, nethttp.StatusServiceUnavailable, "unavailable", "Email is not configured")
		return
	}
	respond := func() {
		WriteJSON(w, nethttp.StatusAccepted, map[string]string{"message": forgotResponse})
	}

	email, ok := normalizeEmail(in.Email)
	if !ok {
		respond()
		return
	}
	app, _ := ApplicationFromContext(r.Context())
	user, err := s.tenant(r).GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		respond()
		return
	}
	if err != nil {
		s.log.Error("forgot password: lookup", "err", err, "application_id", app.ID)
		respond()
		return
	}
	// A cooldown hit is silent too. Errors are logged, never shown.
	if _, err := s.queueEmail(r.Context(), app, user, store.PurposeReset, EmailCooldown); err != nil {
		s.log.Error("forgot password: queue email", "err", err, "user_id", user.ID, "application_id", app.ID)
	}
	respond()
}

// handleResetPassword spends a reset token, sets the new password and signs the
// user out of every session, in one transaction.
func (s *Server) handleResetPassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !auth.IsWellFormedToken(in.Token) {
		writeInvalidToken(w)
		return
	}
	// Check the password before spending the token, so a too-short password
	// does not burn the user's only link.
	if msg := validatePassword(in.Password); msg != "" {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", msg)
		return
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		s.internalError(w, "reset password: hash", err)
		return
	}
	app, _ := ApplicationFromContext(r.Context())
	user, err := s.tenant(r).ResetPassword(r.Context(), auth.HashToken(in.Token), hash, s.opts.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeInvalidToken(w)
		return
	}
	if err != nil {
		s.internalError(w, "reset password", err)
		return
	}
	s.log.Info("password reset", "user_id", user.ID, "application_id", app.ID)
	s.clearSessionCookie(w, app) // this browser's session, if any, is gone as well
	w.WriteHeader(nethttp.StatusNoContent)
}
