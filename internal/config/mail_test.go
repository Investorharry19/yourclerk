package config

import "testing"

func TestMailConfig(t *testing.T) {
	const prodSecret = "0123456789abcdef0123456789abcdef"
	prod := func(extra map[string]string) map[string]string {
		m := map[string]string{"DATABASE_URL": "x", "APP_ENV": "production", "SECRET_KEY": prodSecret, "ISSUER": "https://auth.example.com",
			"MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name    string
		env     map[string]string
		driver  string
		webURL  string
		wantErr bool
	}{
		{"dev defaults to the log mailer", map[string]string{"DATABASE_URL": "x"}, "log", "http://localhost:3000", false},
		{"dev smtp (Mailpit)", map[string]string{"DATABASE_URL": "x", "MAIL_DRIVER": "smtp"}, "smtp", "http://localhost:3000", false},
		{"driver is case-insensitive", map[string]string{"DATABASE_URL": "x", "MAIL_DRIVER": "SMTP"}, "smtp", "http://localhost:3000", false},
		{"unknown driver", map[string]string{"DATABASE_URL": "x", "MAIL_DRIVER": "carrier-pigeon"}, "", "", true},
		{"resend needs a key", map[string]string{"DATABASE_URL": "x", "MAIL_DRIVER": "resend"}, "", "", true},
		{"resend with key", map[string]string{"DATABASE_URL": "x", "MAIL_DRIVER": "resend", "RESEND_API_KEY": "re_x"}, "resend", "http://localhost:3000", false},
		{"web url trailing slash", map[string]string{"DATABASE_URL": "x", "WEB_URL": "http://localhost:5173/"}, "log", "http://localhost:5173", false},
		{"web url without scheme", map[string]string{"DATABASE_URL": "x", "WEB_URL": "app.example.com"}, "", "", true},
		{"bad sender", map[string]string{"DATABASE_URL": "x", "MAIL_FROM": "not an address"}, "", "", true},
		{"sender with newline", map[string]string{"DATABASE_URL": "x", "MAIL_FROM": "a@example.com\r\nBcc: x@y.z"}, "", "", true},
		{"prod ok", prod(nil), "smtp", "https://app.example.com", false},
		{"prod resend ok", prod(map[string]string{"MAIL_DRIVER": "resend", "RESEND_API_KEY": "re_x"}), "resend", "https://app.example.com", false},
		{"prod requires a driver", prod(map[string]string{"MAIL_DRIVER": ""}), "", "", true},
		{"prod refuses the log mailer", prod(map[string]string{"MAIL_DRIVER": "log"}), "", "", true},
		{"prod web url must be https", prod(map[string]string{"WEB_URL": "http://app.example.com"}), "", "", true},
		{"prod needs a real sender", prod(map[string]string{"MAIL_FROM": ""}), "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := load(env(tc.env))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if cfg.MailDriver != tc.driver || cfg.WebURL != tc.webURL {
				t.Fatalf("driver=%q web=%q, want %q %q", cfg.MailDriver, cfg.WebURL, tc.driver, tc.webURL)
			}
		})
	}
}
