package mail

import (
	"context"
	"log/slog"
)

// LogMailer prints the message to the log instead of sending it. It is the
// development default: copy the link or token from the log. Never use it in
// production; it writes one-time links to your logs.
type LogMailer struct{ Log *slog.Logger }

func (l LogMailer) Send(_ context.Context, from string, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	l.Log.Info("email (log mailer, not sent)", "from", from, "to", m.To, "subject", m.Subject, "text", m.Text)
	return nil
}
