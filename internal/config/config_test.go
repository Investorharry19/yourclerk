package config

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		port    int
	}{
		{"defaults", map[string]string{"DATABASE_URL": "postgres://x"}, false, 8080},
		{"custom port", map[string]string{"DATABASE_URL": "postgres://x", "PORT": "9000"}, false, 9000},
		{"missing db url", map[string]string{}, true, 0},
		{"bad port", map[string]string{"DATABASE_URL": "postgres://x", "PORT": "abc"}, true, 0},
		{"port out of range", map[string]string{"DATABASE_URL": "postgres://x", "PORT": "70000"}, true, 0},
		{"prod needs secret", map[string]string{"DATABASE_URL": "postgres://x", "APP_ENV": "production", "MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com", "ISSUER": "https://auth.example.com"}, true, 0},
		{"prod ok", map[string]string{"DATABASE_URL": "postgres://x", "APP_ENV": "production", "MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com", "SECRET_KEY": "0123456789abcdef0123456789abcdef", "ISSUER": "https://auth.example.com"}, false, 8080},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := load(env(tc.env))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && cfg.Port != tc.port {
				t.Fatalf("port = %d, want %d", cfg.Port, tc.port)
			}
		})
	}
}
