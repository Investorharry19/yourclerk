package config

import "testing"

func TestCookieSecure(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{"development default is off", map[string]string{"DATABASE_URL": "x"}, false, false},
		{"explicit development", map[string]string{"DATABASE_URL": "x", "APP_ENV": "development"}, false, false},
		{"staging default is on", map[string]string{"DATABASE_URL": "x", "APP_ENV": "staging"}, true, false},
		{"production default is on", map[string]string{"DATABASE_URL": "x", "APP_ENV": "production", "MAIL_DRIVER": "smtp", "MAIL_FROM": "App <no-reply@example.com>", "WEB_URL": "https://app.example.com", "SECRET_KEY": "0123456789abcdef0123456789abcdef", "ISSUER": "https://auth.example.com"}, true, false},
		{"override on in development", map[string]string{"DATABASE_URL": "x", "COOKIE_SECURE": "true"}, true, false},
		{"garbage", map[string]string{"DATABASE_URL": "x", "COOKIE_SECURE": "maybe"}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := load(env(tc.env))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && cfg.CookieSecure != tc.want {
				t.Fatalf("CookieSecure = %v, want %v", cfg.CookieSecure, tc.want)
			}
		})
	}
}
