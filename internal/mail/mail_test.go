package mail

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	netmail "net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMessageValidate(t *testing.T) {
	ok := Message{To: "a@example.com", Subject: "hi", Text: "body"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]Message{
		"newline in subject": {To: "a@example.com", Subject: "hi\r\nBcc: evil@example.com", Text: "x"},
		"lf in subject":      {To: "a@example.com", Subject: "hi\nBcc: x", Text: "x"},
		"two recipients":     {To: "a@example.com, b@example.com", Subject: "s", Text: "x"},
		"display name":       {To: "Bob <b@example.com>", Subject: "s", Text: "x"},
		"newline in to":      {To: "a@example.com\r\nBcc: e@example.com", Subject: "s", Text: "x"},
		"empty to":           {Subject: "s", Text: "x"},
		"empty body":         {To: "a@example.com", Subject: "s"},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := validFrom("YourClerk <no-reply@example.com>"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "nope", "a@example.com\r\nBcc: x@y.com"} {
		if _, err := validFrom(bad); err == nil {
			t.Errorf("sender %q accepted", bad)
		}
	}
}

func TestTemplates(t *testing.T) {
	link := "https://app.example.com/verify-email#token=abc123"
	m := VerificationEmail("u@example.com", "My <b>App</b>\r\nBcc: x@y.z", link, "abc123", "24 hours")
	if strings.ContainsAny(m.Subject, "\r\n") || m.Subject != "Confirm your email for My <b>App</b>Bcc: x@y.z" {
		t.Fatalf("subject = %q", m.Subject)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{link, "abc123", "24 hours"} {
		if !strings.Contains(m.Text, want) || !strings.Contains(m.HTML, want) {
			t.Errorf("%q missing from text or html", want)
		}
	}
	if strings.Contains(m.HTML, "<b>App</b>") || !strings.Contains(m.HTML, "&lt;b&gt;App&lt;/b&gt;") {
		t.Fatalf("application name not HTML-escaped: %s", m.HTML)
	}
	if strings.Contains(m.Text, "&lt;") {
		t.Fatal("plain text body is HTML-escaped")
	}

	r := PasswordResetEmail("u@example.com", "App", link, "abc123", "1 hour")
	if !strings.Contains(r.Subject, "Reset") || !strings.Contains(r.Text, "signs you out everywhere") || !strings.Contains(r.HTML, link) {
		t.Fatalf("reset email: %+v", r)
	}
	// The token travels in the fragment, so it is never sent to a server or a Referer header.
	if strings.Contains(link, "?token") {
		t.Fatal("test link uses a query string")
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
	if Backoff(0) != 30*time.Second || Backoff(10_000) != time.Hour {
		t.Fatal("backoff bounds")
	}
}

func TestBuildMIME(t *testing.T) {
	m := Message{To: "u@example.com", Subject: "Café ✓ confirm", Text: "Hello café\nlink: https://x.test/#token=abc", HTML: "<p>Hello café</p>"}
	raw := buildMIME("YourClerk <no-reply@example.com>", m, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); subj != m.Subject {
		t.Fatalf("subject = %q", subj)
	}
	if strings.ContainsAny(msg.Header.Get("Subject"), "é✓") {
		t.Fatal("raw subject is not RFC 2047 encoded")
	}
	if msg.Header.Get("To") != "u@example.com" || msg.Header.Get("From") != "\"YourClerk\" <no-reply@example.com>" && msg.Header.Get("From") != "YourClerk <no-reply@example.com>" {
		t.Fatalf("headers: To=%q From=%q", msg.Header.Get("To"), msg.Header.Get("From"))
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var types, bodies []string
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p) // multipart.Reader already decodes quoted-printable
		types = append(types, p.Header.Get("Content-Type"))
		bodies = append(bodies, strings.ReplaceAll(string(b), "\r\n", "\n"))
	}
	if len(types) != 2 || !strings.HasPrefix(types[0], "text/plain") || !strings.HasPrefix(types[1], "text/html") {
		t.Fatalf("parts = %v", types)
	}
	if bodies[0] != m.Text+"\n" && bodies[0] != m.Text || !strings.Contains(bodies[1], "café") {
		t.Fatalf("bodies = %q", bodies)
	}
}

// --- SMTP against a tiny in-process server ---------------------------------

type fakeSMTP struct {
	ln       net.Listener
	mu       sync.Mutex
	from     string
	rcpts    []string
	data     string
	rejectTo bool
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r, w := bufio.NewReader(c), func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	w("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.TrimSpace(line[len("MAIL FROM:"):])
			f.mu.Unlock()
			w("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			if f.rejectTo {
				w("550 no such user")
				continue
			}
			f.mu.Lock()
			f.rcpts = append(f.rcpts, strings.TrimSpace(line[len("RCPT TO:"):]))
			f.mu.Unlock()
			w("250 ok")
		case cmd == "DATA":
			w("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			w("250 queued")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func TestSMTPMailerDelivers(t *testing.T) {
	f := newFakeSMTP(t)
	m := SMTPMailer{Addr: f.ln.Addr().String()}
	msg := Message{To: "u@example.com", Subject: "Hello", Text: "plain body", HTML: "<p>html body</p>"}
	if err := m.Send(context.Background(), "YourClerk <no-reply@example.com>", msg); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.from != "<no-reply@example.com>" || len(f.rcpts) != 1 || f.rcpts[0] != "<u@example.com>" {
		t.Fatalf("envelope: from=%q rcpts=%v", f.from, f.rcpts)
	}
	if !strings.Contains(f.data, "Subject: Hello") || !strings.Contains(f.data, "plain body") || !strings.Contains(f.data, "html body") {
		t.Fatalf("data = %s", f.data)
	}
}

func TestSMTPMailerErrors(t *testing.T) {
	f := newFakeSMTP(t)
	f.rejectTo = true
	ok := Message{To: "u@example.com", Subject: "s", Text: "x"}
	if err := (SMTPMailer{Addr: f.ln.Addr().String()}).Send(context.Background(), "a@example.com", ok); err == nil || !strings.Contains(err.Error(), "RCPT") {
		t.Fatalf("rejected recipient: %v", err)
	}
	// Nothing is listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if err := (SMTPMailer{Addr: addr}).Send(context.Background(), "a@example.com", ok); err == nil {
		t.Fatal("send to a closed port succeeded")
	}
	// Invalid input never reaches the network.
	g := newFakeSMTP(t)
	bad := Message{To: "u@example.com", Subject: "x\r\nBcc: e@example.com", Text: "x"}
	if err := (SMTPMailer{Addr: g.ln.Addr().String()}).Send(context.Background(), "a@example.com", bad); err == nil {
		t.Fatal("header injection accepted")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.data != "" || g.from != "" {
		t.Fatal("an invalid message reached the SMTP server")
	}
}

// --- Resend ---------------------------------------------------------------

func TestResendMailer(t *testing.T) {
	var gotAuth, gotCT, gotPath string
	var got map[string]any
	status := nethttp.StatusOK
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotAuth, gotCT, gotPath = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
		if status != 200 {
			_, _ = io.WriteString(w, `{"message":"invalid api key"}`)
		}
	}))
	defer srv.Close()

	m := ResendMailer{APIKey: "re_test", BaseURL: srv.URL + "/"}
	msg := Message{To: "u@example.com", Subject: "Hi", Text: "t", HTML: "<p>h</p>"}
	if err := m.Send(context.Background(), "YourClerk <no-reply@example.com>", msg); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer re_test" || gotCT != "application/json" || gotPath != "/emails" {
		t.Fatalf("request: %q %q %q", gotAuth, gotCT, gotPath)
	}
	if got["from"] != "YourClerk <no-reply@example.com>" || got["subject"] != "Hi" || got["text"] != "t" || got["html"] != "<p>h</p>" {
		t.Fatalf("body = %v", got)
	}
	if to, _ := got["to"].([]any); len(to) != 1 || to[0] != "u@example.com" {
		t.Fatalf("to = %v", got["to"])
	}

	status = nethttp.StatusUnauthorized
	if err := m.Send(context.Background(), "a@example.com", msg); err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("provider error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Send(ctx, "a@example.com", msg); err == nil {
		t.Fatal("cancelled context ignored")
	}
}

func TestLogMailer(t *testing.T) {
	var buf bytes.Buffer
	l := LogMailer{Log: slog.New(slog.NewTextHandler(&buf, nil))}
	if err := l.Send(context.Background(), "a@example.com", Message{To: "u@example.com", Subject: "S", Text: "the link"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "the link") || !strings.Contains(buf.String(), "u@example.com") {
		t.Fatalf("log = %s", buf.String())
	}
	if err := l.Send(context.Background(), "a@example.com", Message{To: "bad", Subject: "S", Text: "x"}); err == nil {
		t.Fatal("log mailer skipped validation")
	}
}
