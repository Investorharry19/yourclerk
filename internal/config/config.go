// Package config loads application settings from environment variables
// (the twelve-factor approach).
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
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

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.Env == "production" && len(cfg.SecretKey) < 32 {
		return Config{}, errors.New("SECRET_KEY must be at least 32 characters in production")
	}
	return cfg, nil
}

func (c Config) IsProduction() bool { return c.Env == "production" }

func withDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
