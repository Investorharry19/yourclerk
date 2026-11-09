package http

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	appmail "github.com/Investorharry19/yourclerk/internal/mail"
)

const (
	pw1 = "original-password-1"
	pw2 = "brand-new-password-2"
)

// signedUp creates a user in the application and returns the verification token from the email.
func signedUp(t *testing.T, e *env, a *actor, appID, email string) string {
	t.Helper()
	if st := a.signup(email, pw1); st != 201 {
		t.Fatalf("signup: %d", st)
	}
	m := e.mails(appID, email)
	if len(m) == 0 {
		t.Fatal("no verification email queued")
	}
	return linkToken(t, m[len(m)-1])
}

func (a *actor) post(path, body string) (int, string) {
	st, resp, _ := a.call("POST", path, body)
	return st, resp
}

func TestSignupQueuesVerificationEmail(t *testing.T) {
	w := newTwoApps(t)
	if st := w.ua.signup("new@example.com", pw1); st != 201 {
		t.Fatalf("signup: %d", st)
	}
	mails := w.mails(w.a.ID, "new@example.com")
	if len(mails) != 1 {
		t.Fatalf("%d emails queued, want 1", len(mails))
	}
	m := mails[0]
	tok := linkToken(t, m)
	if m.Subject != "Confirm your email for App A" || !strings.Contains(m.Text, testWebURL+"/verify-email#token="+tok) ||
		!strings.Contains(m.HTML, testWebURL+"/verify-email#token="+tok) || !strings.Contains(m.Text, "24 hours") {
		t.Fatalf("email = %+v", m)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	// Only the right application has mail, and the user starts unverified.
	if n := len(w.mails(w.b.ID, "new@example.com")); n != 0 {
		t.Fatalf("application B has %d emails", n)
	}
	w.ua.login("new@example.com", pw1)
	_, body := w.ua.me()
	if decode[struct{ User userResponse }](t, body).User.EmailVerified {
		t.Fatal("user is verified before clicking the link")
	}
	// The raw token is not stored anywhere the fake can show: only its hash.
	for _, k := range w.world.ForApp(w.a.ID).(*fakeTenant).tokens {
		if k.hash == tok {
			t.Fatal("raw token stored")
		}
	}
}

func TestVerifyLinkWorksExactlyOnce(t *testing.T) {
	w := newTwoApps(t)
	tok := signedUp(t, w.env, w.ua, w.a.ID, "v@example.com")

	st, body := w.ua.post("/v1/verify-email", tokenBodyJSON(tok))
	if st != 200 || !decode[struct{ User userResponse }](t, body).User.EmailVerified {
		t.Fatalf("verify: %d %s", st, body)
	}
	// It is spent.
	st, body = w.ua.post("/v1/verify-email", tokenBodyJSON(tok))
	if st != 400 || errCode(t, body) != "invalid_token" {
		t.Fatalf("second use: %d %s", st, body)
	}
	// And the account really is verified, visible to the user and to the developer's backend.
	w.ua.login("v@example.com", pw1)
	if _, me := w.ua.me(); !decode[struct{ User userResponse }](t, me).User.EmailVerified {
		t.Fatal("/me does not show the verification")
	}
	_, list, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+w.a.SecretKey)
	if u := decode[struct{ Users []backendUser }](t, list).Users; len(u) != 1 || !u[0].EmailVerified {
		t.Fatalf("backend users = %+v", u)
	}
}

func TestVerifyLinkExpiresOnTime(t *testing.T) {
	w := newTwoApps(t)
	early := signedUp(t, w.env, w.ua, w.a.ID, "early@example.com")
	late := signedUp(t, w.env, w.ua, w.a.ID, "late@example.com")

	w.clock.Advance(VerifyTokenTTL - time.Second)
	if st, body := w.ua.post("/v1/verify-email", tokenBodyJSON(early)); st != 200 {
		t.Fatalf("one second before expiry: %d %s", st, body)
	}
	w.clock.Advance(time.Second)
	st, body := w.ua.post("/v1/verify-email", tokenBodyJSON(late))
	if st != 400 || errCode(t, body) != "invalid_token" {
		t.Fatalf("at expiry: %d %s", st, body)
	}
}

func TestEmailTokensDoNotCrossApplications(t *testing.T) {
	w := newTwoApps(t)
	const email = "shared@example.com"
	w.ub.signup(email, "password-in-B-1")
	verifyA := signedUp(t, w.env, w.ua, w.a.ID, email)

	// A's link, presented to application B (same email there): refused...
	st, body := w.ub.post("/v1/verify-email", tokenBodyJSON(verifyA))
	if st != 400 || errCode(t, body) != "invalid_token" {
		t.Fatalf("A's verify token accepted by B: %d %s", st, body)
	}
	if st, _ := w.ub.post("/v1/password/reset", resetBodyJSON(verifyA, pw2)); st != 400 {
		t.Fatalf("A's token accepted by B's reset: %d", st)
	}
	// ...and it was not burned by the attempt.
	if st, body := w.ua.post("/v1/verify-email", tokenBodyJSON(verifyA)); st != 200 {
		t.Fatalf("A's own link after B's failed attempt: %d %s", st, body)
	}

	// The same for a reset token.
	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	resetA := linkToken(t, w.mails(w.a.ID, email)[1])
	if st, _ := w.ub.post("/v1/password/reset", resetBodyJSON(resetA, pw2)); st != 400 {
		t.Fatalf("A's reset token accepted by B: %d", st)
	}
	if st := w.ub.login(email, "password-in-B-1"); st != 200 {
		t.Fatalf("B's password changed by A's token: %d", st)
	}
	if st, _ := w.ua.post("/v1/password/reset", resetBodyJSON(resetA, pw2)); st != 204 {
		t.Fatalf("A's reset token: %d", st)
	}
	if st := w.ub.login(email, "password-in-B-1"); st != 200 {
		t.Fatalf("B affected by A's reset: %d", st)
	}
}

func TestInvalidTokensAreAllRejectedTheSameWay(t *testing.T) {
	w := newTwoApps(t)
	verify := signedUp(t, w.env, w.ua, w.a.ID, "x@example.com")
	w.ua.post("/v1/password/forgot", `{"email":"x@example.com"}`)
	reset := linkToken(t, w.mails(w.a.ID, "x@example.com")[1])
	unknown, _, _ := auth.NewOneTimeToken()

	var first string
	for name, tok := range map[string]string{
		"unknown": unknown, "empty": "", "short": "abc", "padded": " " + verify, "sql": "' OR 1=1 --",
		"too long": strings.Repeat("a", 5000), "a reset token used as a verify token": reset,
	} {
		st, body := w.ua.post("/v1/verify-email", tokenBodyJSON(tok))
		if st != 400 || errCode(t, body) != "invalid_token" {
			t.Errorf("%s: %d %s", name, st, body)
		}
		if first == "" {
			first = body
		} else if body != first {
			t.Errorf("%s: response differs: %s", name, body)
		}
	}
	// A verify token is not a reset token.
	if st, _ := w.ua.post("/v1/password/reset", resetBodyJSON(verify, pw2)); st != 400 {
		t.Fatalf("verify token accepted as reset token: %d", st)
	}
	for _, body := range []string{"{", `{"token":1}`, `{"token":"x","extra":1}`} {
		if st, resp := w.ua.post("/v1/verify-email", body); st != 400 || errCode(t, resp) != "invalid_json" {
			t.Errorf("%s: %d %s", body, st, resp)
		}
	}
	// None of that burned the genuine tokens.
	if st, _ := w.ua.post("/v1/verify-email", tokenBodyJSON(verify)); st != 200 {
		t.Fatal("genuine verify token was burned by failed attempts")
	}
}

func TestResendVerification(t *testing.T) {
	w := newTwoApps(t)
	first := signedUp(t, w.env, w.ua, w.a.ID, "r@example.com")

	if st, _ := w.ua.post("/v1/verify-email/resend", ""); st != 401 {
		t.Fatalf("resend without a session: %d", st)
	}
	w.ua.login("r@example.com", pw1)

	// Signup just sent one, so an immediate resend is held back.
	st, body, hdr := w.ua.call("POST", "/v1/verify-email/resend", "")
	if st != 429 || errCode(t, body) != "rate_limited" || hdr.Get("Retry-After") != "60" {
		t.Fatalf("immediate resend: %d %s %v", st, body, hdr)
	}
	if n := len(w.mails(w.a.ID, "r@example.com")); n != 1 {
		t.Fatalf("%d emails after a refused resend", n)
	}

	w.clock.Advance(EmailCooldown + time.Second)
	if st, body := w.ua.post("/v1/verify-email/resend", ""); st != 202 {
		t.Fatalf("resend after cooldown: %d %s", st, body)
	}
	mails := w.mails(w.a.ID, "r@example.com")
	if len(mails) != 2 {
		t.Fatalf("%d emails, want 2", len(mails))
	}
	second := linkToken(t, mails[1])
	// Only the newest link works.
	if st, _ := w.ua.post("/v1/verify-email", tokenBodyJSON(first)); st != 400 {
		t.Fatalf("superseded link still works: %d", st)
	}
	if st, _ := w.ua.post("/v1/verify-email", tokenBodyJSON(second)); st != 200 {
		t.Fatalf("newest link: %d", st)
	}
	// Already verified: nothing to send.
	if st, body := w.ua.post("/v1/verify-email/resend", ""); st != 409 || errCode(t, body) != "already_verified" {
		t.Fatalf("resend when verified: %d %s", st, body)
	}
}

// The forgot-password response must not reveal whether an account exists.
func TestForgotPasswordResponseIsIdenticalForKnownAndUnknownEmails(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("known@example.com", pw1)
	w.ub.signup("only-in-b@example.com", pw1)

	type resp struct {
		st   int
		body string
		hdr  nethttp.Header
	}
	do := func(a *actor, email string) resp {
		st, body, hdr := a.call("POST", "/v1/password/forgot", `{"email":"`+email+`"}`)
		return resp{st, body, hdr}
	}
	known := do(w.ua, "known@example.com")
	cases := map[string]resp{
		"unknown email":              do(w.ua, "nobody@example.com"),
		"known, different case":      do(w.ua, "KNOWN@Example.com"),
		"cooldown (second request)":  do(w.ua, "known@example.com"),
		"exists only in application": do(w.ua, "only-in-b@example.com"),
		"malformed address":          do(w.ua, "not-an-email"),
		"empty address":              do(w.ua, ""),
	}
	if known.st != 202 || errCodeOrEmpty(known.body) != "" {
		t.Fatalf("known: %d %s", known.st, known.body)
	}
	for name, r := range cases {
		if r.st != known.st || r.body != known.body {
			t.Errorf("%s: %d %q differs from known %d %q", name, r.st, r.body, known.st, known.body)
		}
		for _, h := range []string{"Content-Type", "Cache-Control", "Set-Cookie"} {
			if r.hdr.Get(h) != known.hdr.Get(h) {
				t.Errorf("%s: header %s = %q vs %q", name, h, r.hdr.Get(h), known.hdr.Get(h))
			}
		}
	}

	// Only the real account got an email, once (the later requests hit the cooldown or matched nothing).
	if n := len(w.mails(w.a.ID, "known@example.com")); n != 2 { // verification + one reset
		t.Fatalf("known user has %d emails, want 2", n)
	}
	for _, addr := range []string{"nobody@example.com", "only-in-b@example.com"} {
		if n := len(w.mails(w.a.ID, addr)); n != 0 {
			t.Fatalf("%s got %d emails in application A", addr, n)
		}
	}
	// Requests the server cannot even parse are rejected the same way for everyone.
	if st, _, _ := w.ua.call("POST", "/v1/password/forgot", "{"); st != 400 {
		t.Fatalf("bad JSON: %d", st)
	}
}

func errCodeOrEmpty(body string) string {
	var b errorBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return ""
	}
	return b.Error.Code
}

func TestForgotPasswordIsUniformEvenWhenQueueingFails(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("known@example.com", pw1)
	st1, b1 := w.ua.post("/v1/password/forgot", `{"email":"nobody@example.com"}`)
	w.world.failIssue = errors.New("database unavailable")
	st2, b2 := w.ua.post("/v1/password/forgot", `{"email":"known@example.com"}`)
	if st1 != st2 || b1 != b2 || st2 != 202 {
		t.Fatalf("a server-side failure changed the response: %d %q vs %d %q", st1, b1, st2, b2)
	}
}

func TestPasswordResetEndToEnd(t *testing.T) {
	w := newTwoApps(t)
	const email = "reset@example.com"
	w.ua.signup(email, pw1)
	phone, laptop := w.env.actor(w.a.PublishableKey), w.env.actor(w.a.PublishableKey)
	for _, a := range []*actor{phone, laptop} {
		if st := a.login(email, pw1); st != 200 {
			t.Fatal("login")
		}
	}
	// A token minted before the reset; it will outlive the session by up to its 60 seconds.
	if st, _ := phone.me(); st != 200 {
		t.Fatal("phone session")
	}

	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	mails := w.mails(w.a.ID, email)
	m := mails[len(mails)-1]
	if !strings.HasPrefix(m.Subject, "Reset your App A password") || !strings.Contains(m.Text, testWebURL+"/reset-password#token=") ||
		!strings.Contains(m.Text, "1 hour") {
		t.Fatalf("reset email = %+v", m)
	}
	tok := linkToken(t, m)

	st, body := w.ua.post("/v1/password/reset", resetBodyJSON(tok, pw2))
	if st != 204 || body != "" {
		t.Fatalf("reset: %d %q", st, body)
	}

	// Every older session is dead.
	for name, a := range map[string]*actor{"phone": phone, "laptop": laptop} {
		if st, _ := a.me(); st != 401 {
			t.Errorf("%s session survived the reset: %d", name, st)
		}
	}
	// The old password is gone, the new one works, the link is spent.
	if st := w.ua.login(email, pw1); st != 401 {
		t.Fatalf("old password still works: %d", st)
	}
	if st := phone.login(email, pw2); st != 200 {
		t.Fatalf("new password: %d", st)
	}
	if st, resp := w.ua.post("/v1/password/reset", resetBodyJSON(tok, "yet-another-password")); st != 400 || errCode(t, resp) != "invalid_token" {
		t.Fatalf("link used twice: %d %s", st, resp)
	}
	if st := phone.login(email, "yet-another-password"); st == 200 {
		t.Fatal("second use changed the password")
	}
	// Proving control of the inbox also verifies the address.
	if _, me := phone.me(); !decode[struct{ User userResponse }](t, me).User.EmailVerified {
		t.Fatal("email not marked verified after a reset")
	}
}

func TestResetLinkExpiresAfterAnHour(t *testing.T) {
	w := newTwoApps(t)
	const email = "slow@example.com"
	w.ua.signup(email, pw1)
	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	tok := linkToken(t, w.mails(w.a.ID, email)[1])

	w.clock.Advance(ResetTokenTTL)
	st, body := w.ua.post("/v1/password/reset", resetBodyJSON(tok, pw2))
	if st != 400 || errCode(t, body) != "invalid_token" {
		t.Fatalf("expired reset link: %d %s", st, body)
	}
	if st := w.ua.login(email, pw1); st != 200 {
		t.Fatal("password changed by an expired link")
	}
}

func TestResetValidatesThePasswordBeforeSpendingTheLink(t *testing.T) {
	w := newTwoApps(t)
	const email = "typo@example.com"
	w.ua.signup(email, pw1)
	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	tok := linkToken(t, w.mails(w.a.ID, email)[1])

	if st, body := w.ua.post("/v1/password/reset", resetBodyJSON(tok, "short")); st != 422 || errCode(t, body) != "validation_error" {
		t.Fatalf("short password: %d %s", st, body)
	}
	if st, _ := w.ua.post("/v1/password/reset", resetBodyJSON(tok, pw2)); st != 204 {
		t.Fatal("a rejected password burned the link")
	}
}

func TestAskingForANewResetLinkReplacesTheOldOne(t *testing.T) {
	w := newTwoApps(t)
	const email = "twice@example.com"
	w.ua.signup(email, pw1)
	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	w.clock.Advance(EmailCooldown + time.Second)
	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	mails := w.mails(w.a.ID, email)
	if len(mails) != 3 { // verification, reset, reset
		t.Fatalf("%d emails", len(mails))
	}
	old, newest := linkToken(t, mails[1]), linkToken(t, mails[2])
	if st, _ := w.ua.post("/v1/password/reset", resetBodyJSON(old, pw2)); st != 400 {
		t.Fatalf("older reset link still works: %d", st)
	}
	if st, _ := w.ua.post("/v1/password/reset", resetBodyJSON(newest, pw2)); st != 204 {
		t.Fatalf("newest reset link: %d", st)
	}
}

func TestResetSignsOutOnlyTheSameUserInTheSameApplication(t *testing.T) {
	w := newTwoApps(t)
	const email = "alice@example.com"
	w.ua.signup(email, pw1)
	w.ua.signup("bob@example.com", pw1)
	w.ub.signup(email, pw1)
	bob, alice, aliceInB := w.env.actor(w.a.PublishableKey), w.env.actor(w.a.PublishableKey), w.ub
	bob.login("bob@example.com", pw1)
	alice.login(email, pw1)
	aliceInB.login(email, pw1)

	w.ua.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	w.ua.post("/v1/password/reset", resetBodyJSON(linkToken(t, w.mails(w.a.ID, email)[1]), pw2))

	if st, _ := alice.me(); st != 401 {
		t.Fatal("alice's session survived")
	}
	if st, _ := bob.me(); st != 200 {
		t.Fatal("another user was signed out")
	}
	if st, _ := aliceInB.me(); st != 200 {
		t.Fatal("the same email in another application was signed out")
	}
}

// Queueing trouble or a provider outage must never break signup.
func TestSignupSurvivesEmailFailures(t *testing.T) {
	w := newTwoApps(t)
	w.world.failIssue = errors.New("database hiccup")
	if st := w.ua.signup("resilient@example.com", pw1); st != 201 {
		t.Fatalf("signup failed because the email could not be queued: %d", st)
	}
	w.world.failIssue = nil
	if st := w.ua.login("resilient@example.com", pw1); st != 200 {
		t.Fatalf("login after a failed email: %d", st)
	}
	// The user can ask again.
	if st, _ := w.ua.post("/v1/verify-email/resend", ""); st != 202 {
		t.Fatalf("resend: %d", st)
	}
	if n := len(w.mails(w.a.ID, "resilient@example.com")); n != 1 {
		t.Fatalf("%d emails", n)
	}

	// And with email not configured at all, signup still works and the password endpoints say so.
	h := NewServer(Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: fakeDB{},
		Registry: w.world, Developers: w.world, Apps: w.world, Tenants: w.world, Options: Options{Now: w.clock.Now}}).Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	hdr := []string{publishableKeyHeader, w.a.PublishableKey}
	if st, _, _ := send(t, nethttp.DefaultClient, srv.URL+"/v1/signup", "POST", creds("quiet@example.com", pw1), hdr...); st != 201 {
		t.Fatalf("signup without email config: %d", st)
	}
	if st, _, _ := send(t, nethttp.DefaultClient, srv.URL+"/v1/password/forgot", "POST", `{"email":"quiet@example.com"}`, hdr...); st != 503 {
		t.Fatalf("forgot without email config: %d, want 503", st)
	}
}

func TestApplicationNameCannotInjectEmailHeaders(t *testing.T) {
	w := newTwoApps(t)
	if st, body := w.patch(w.a, `{"name":"Evil\r\nBcc: attacker@example.com"}`); st != 200 {
		t.Fatalf("rename: %d %s", st, body)
	}
	w.ua.signup("victim@example.com", pw1)
	m := w.mails(w.a.ID, "victim@example.com")[0]
	if strings.ContainsAny(m.Subject, "\r\n") {
		t.Fatalf("subject carries a line break: %q", m.Subject)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestQueuedEmailsAreEncrypted(t *testing.T) {
	w := newTwoApps(t)
	tok := signedUp(t, w.env, w.ua, w.a.ID, "enc@example.com")
	w.world.mu.Lock()
	defer w.world.mu.Unlock()
	for _, m := range w.world.outbox {
		if strings.Contains(string(m.payload), tok) || strings.Contains(string(m.payload), "enc@example.com") {
			t.Fatal("a queued payload holds the token or address in the clear")
		}
		// And it cannot be opened as another application's message.
		if _, err := appmail.Open(w.sealer, w.b.ID, m.payload); err == nil {
			t.Fatal("payload opened under another application")
		}
	}
}
