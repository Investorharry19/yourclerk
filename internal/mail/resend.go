package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ResendMailer sends through the Resend HTTP API (https://resend.com), the
// "real provider" implementation. Any provider with a JSON send endpoint works
// the same way; swapping one in means writing another small type like this one.
type ResendMailer struct {
	APIKey  string
	BaseURL string       // defaults to https://api.resend.com
	Client  *http.Client // defaults to a 15s timeout
}

func (r ResendMailer) Send(ctx context.Context, from string, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if _, err := validFrom(from); err != nil {
		return err
	}
	base := strings.TrimRight(r.BaseURL, "/")
	if base == "" {
		base = "https://api.resend.com"
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	body, err := json.Marshal(map[string]any{
		"from": from, "to": []string{m.To}, "subject": m.Subject, "text": m.Text, "html": m.HTML,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("resend: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("resend: status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
