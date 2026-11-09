// Package config loads application settings from environment variables
// (the twelve-factor approach).
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Env         string // development | production
	Port        int
	DatabaseURL string
	SMTPAddr    string
	SecretKey   string

	// CookieSecure sets the Secure flag on session cookies. It defaults to
	// true everywhere except APP_ENV=development, because browsers will not
	// send Secure cookies over plain http (curl and cookie jars included).
	CookieSecure bool

	// Issuer is the "iss" claim in access tokens and the base URL verifiers
	// use to find the JWKS. It must be the public URL of this service.
	Issuer string

	// EnableDocs serves Swagger UI at /docs and the spec at /openapi.json.
	// On by default in development only.
	EnableDocs bool

	// MailDriver picks how email is sent: "log" prints it to the server log
	// (development only), "smtp" talks to SMTP_ADDR (Mailpit locally, or a
	// provider's relay), "resend" uses the Resend HTTP API.
	MailDriver   string
	MailFrom     string // sender address, "Name <addr>" or "addr"
	SMTPUsername string
	SMTPPassword string
	ResendAPIKey string
	// WebURL is the front end that handles the links in emails:
	// WEB_URL/verify-email#token=... and WEB_URL/reset-password#token=...
	WebURL string
}

// Load reads configuration from the environment and validates it.
func Load() (Config, error) {
	return load(os.Getenv)
}

func load(get func(string) string) (Config, error) {
	cfg := Config{
		Env:         withDefault(get("APP_ENV"), "development"),
		DatabaseURL: get("DATABASE_URL"),
		SMTPAddr:    withDefault(get("SMTP_ADDR"), "localhost:1025"),
		SecretKey:   get("SECRET_KEY"),
	}

	port, err := strconv.Atoi(withDefault(get("PORT"), "8080"))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("PORT must be a number between 1 and 65535")
	}
	cfg.Port = port

	secure, err := strconv.ParseBool(withDefault(get("COOKIE_SECURE"), strconv.FormatBool(cfg.Env != "development")))
	if err != nil {
		return Config{}, errors.New("COOKIE_SECURE must be true or false")
	}
	cfg.CookieSecure = secure

	docs, err := strconv.ParseBool(withDefault(get("ENABLE_DOCS"), strconv.FormatBool(cfg.Env == "development")))
	if err != nil {
		return Config{}, errors.New("ENABLE_DOCS must be true or false")
	}
	cfg.EnableDocs = docs

	cfg.Issuer = strings.TrimRight(withDefault(get("ISSUER"), fmt.Sprintf("http://localhost:%d", port)), "/")
	if !strings.HasPrefix(cfg.Issuer, "http://") && !strings.HasPrefix(cfg.Issuer, "https://") {
		return Config{}, errors.New("ISSUER must start with http:// or https://")
	}
	if cfg.Env == "production" && !strings.HasPrefix(cfg.Issuer, "https://") {
		return Config{}, errors.New("ISSUER must use https:// in production")
	}

	if err := loadMail(&cfg, get); err != nil {
		return Config{}, err
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.Env == "production" && len(cfg.SecretKey) < 32 {
		return Config{}, errors.New("SECRET_KEY must be at least 32 characters in production")
	}
	return cfg, nil
}

func loadMail(cfg *Config, get func(string) string) error {
	cfg.MailDriver = strings.ToLower(withDefault(get("MAIL_DRIVER"), map[bool]string{true: "", false: "log"}[cfg.Env == "production"]))
	switch cfg.MailDriver {
	case "log", "smtp", "resend":
	case "":
		return errors.New("MAIL_DRIVER is required in production (smtp or resend)")
	default:
		return fmt.Errorf("MAIL_DRIVER must be log, smtp or resend (got %q)", cfg.MailDriver)
	}
	if cfg.Env == "production" && cfg.MailDriver == "log" {
		return errors.New("MAIL_DRIVER=log is for development only: it writes one-time links to the logs")
	}

	cfg.MailFrom = withDefault(get("MAIL_FROM"), "YourClerk <no-reply@localhost>")
	if a, err := mail.ParseAddress(cfg.MailFrom); err != nil || strings.ContainsAny(cfg.MailFrom, "\r\n") {
		return errors.New("MAIL_FROM must be an email address, optionally with a display name")
	} else if cfg.Env == "production" && strings.HasSuffix(a.Address, "@localhost") {
		return errors.New("MAIL_FROM must be a real sender address in production")
	}

	cfg.SMTPUsername, cfg.SMTPPassword = get("SMTP_USERNAME"), get("SMTP_PASSWORD")
	cfg.ResendAPIKey = get("RESEND_API_KEY")
	if cfg.MailDriver == "resend" && cfg.ResendAPIKey == "" {
		return errors.New("RESEND_API_KEY is required when MAIL_DRIVER=resend")
	}

	cfg.WebURL = strings.TrimRight(withDefault(get("WEB_URL"), "http://localhost:3000"), "/")
	if !strings.HasPrefix(cfg.WebURL, "http://") && !strings.HasPrefix(cfg.WebURL, "https://") {
		return errors.New("WEB_URL must start with http:// or https://")
	}
	if cfg.Env == "production" && !strings.HasPrefix(cfg.WebURL, "https://") {
		return errors.New("WEB_URL must use https:// in production")
	}
	return nil
}

func (c Config) IsProduction() bool { return c.Env == "production" }

func withDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
