package config

import "testing"

func TestIssuerAndDocs(t *testing.T) {
	const prodSecret = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		env        map[string]string
		wantIssuer string
		wantDocs   bool
		wantErr    bool
	}{
		{"dev defaults", map[string]string{"DATABASE_URL": "x"}, "http://localhost:8080", true, false},
		{"dev custom port", map[string]string{"DATABASE_URL": "x", "PORT": "9000"}, "http://localhost:9000", true, false},
		{"trailing slash trimmed", map[string]string{"DATABASE_URL": "x", "ISSUER": "https://auth.example.com/"}, "https://auth.example.com", true, false},
		{"issuer without scheme", map[string]string{"DATABASE_URL": "x", "ISSUER": "auth.example.com"}, "", false, true},
		{"prod needs https", map[string]string{"DATABASE_URL": "x", "APP_ENV": "production", "MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com", "SECRET_KEY": prodSecret}, "", false, true},
		{"prod https ok, docs off", map[string]string{"DATABASE_URL": "x", "APP_ENV": "production", "MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com", "SECRET_KEY": prodSecret, "ISSUER": "https://auth.example.com"}, "https://auth.example.com", false, false},
		{"docs forced on in prod", map[string]string{"DATABASE_URL": "x", "APP_ENV": "production", "MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com", "SECRET_KEY": prodSecret, "ISSUER": "https://a.example.com", "ENABLE_DOCS": "true"}, "https://a.example.com", true, false},
		{"docs garbage", map[string]string{"DATABASE_URL": "x", "ENABLE_DOCS": "perhaps"}, "", false, true},
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
			if cfg.Issuer != tc.wantIssuer || cfg.EnableDocs != tc.wantDocs {
				t.Fatalf("issuer=%q docs=%v, want %q %v", cfg.Issuer, cfg.EnableDocs, tc.wantIssuer, tc.wantDocs)
			}
		})
	}
}
