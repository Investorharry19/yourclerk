// Package mail sends transactional email: a Mailer interface with three
// implementations (log, SMTP for Mailpit or a relay, and the Resend HTTP API),
// the message templates, and the background worker that drains the email outbox.
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

// Message is one email with a plain-text and an HTML body.
type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// Mailer delivers a message. A nil error means the provider accepted it.
// Implementations must honour ctx and must not retry: the worker does that.
type Mailer interface {
	Send(ctx context.Context, from string, m Message) error
}

// Validate rejects messages that could smuggle extra headers or recipients.
func (m Message) Validate() error {
	if strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("subject contains a line break")
	}
	addr, err := mail.ParseAddress(m.To)
	if err != nil || addr.Address != m.To || strings.ContainsAny(m.To, "\r\n,;") {
		return fmt.Errorf("invalid recipient %q", m.To)
	}
	if m.Text == "" && m.HTML == "" {
		return errors.New("empty message")
	}
	return nil
}

// validFrom checks the configured sender; it may be "Name <addr>" or "addr".
func validFrom(from string) (*mail.Address, error) {
	if strings.ContainsAny(from, "\r\n") {
		return nil, errors.New("sender contains a line break")
	}
	a, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("invalid sender %q: %w", from, err)
	}
	return a, nil
}

// Seal encrypts a message for the outbox. The application id is bound in, so a
// queued message cannot be replayed from another tenant's row.
func Seal(s *auth.Sealer, appID string, m Message) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return s.Seal(raw, appID)
}

// Open decrypts a message sealed with Seal.
func Open(s *auth.Sealer, appID string, blob []byte) (Message, error) {
	raw, err := s.Open(blob, appID)
	if err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return Message{}, err
	}
	return m, nil
}
