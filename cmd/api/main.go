package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/config"
	apphttp "github.com/Investorharry19/yourclerk/internal/http"
	appmail "github.com/Investorharry19/yourclerk/internal/mail"
	"github.com/Investorharry19/yourclerk/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var handler slog.Handler
	if cfg.IsProduction() {
		handler = slog.NewJSONHandler(os.Stdout, nil)
	} else {
		handler = slog.NewTextHandler(os.Stdout, nil)
	}
	log := slog.New(handler)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()

	// Signing keys are per application: created when an application is created
	// (or on its first token, for applications adopted by the Stage 4 migration).
	tokens, err := auth.NewTokenService(db, cfg.SecretKey, cfg.Issuer, auth.DefaultTokenTTL)
	if err != nil {
		return fmt.Errorf("token service: %w", err)
	}

	// Account emails: the API only queues them; this worker sends them, retrying
	// with backoff, so a mail outage never fails a signup or a reset request.
	sealer, err := auth.NewSealer(cfg.SecretKey)
	if err != nil {
		return fmt.Errorf("sealer: %w", err)
	}
	mailer := newMailer(cfg, log)
	go (&appmail.Worker{Outbox: db, Mailer: mailer, Sealer: sealer, From: cfg.MailFrom, Log: log}).Run(ctx)

	go cleanup(ctx, log, db, time.Hour)

	srv := &nethttp.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
		Handler: apphttp.NewServer(apphttp.Deps{
			Log: log, DB: db,
			Registry: db, Developers: db, Apps: db, Tenants: db, Tokens: tokens,
			Email:   &apphttp.EmailDeps{Sealer: sealer, WebURL: cfg.WebURL},
			Options: apphttp.Options{CookieSecure: cfg.CookieSecure, EnableDocs: cfg.EnableDocs},
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", srv.Addr, "env", cfg.Env, "issuer", cfg.Issuer, "mail_driver", cfg.MailDriver)
		if cfg.EnableDocs {
			log.Info("api docs enabled", "url", fmt.Sprintf("http://localhost:%d/docs", cfg.Port))
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// newMailer picks the Mailer named by MAIL_DRIVER.
func newMailer(cfg config.Config, log *slog.Logger) appmail.Mailer {
	switch cfg.MailDriver {
	case "smtp":
		return appmail.SMTPMailer{Addr: cfg.SMTPAddr, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword}
	case "resend":
		return appmail.ResendMailer{APIKey: cfg.ResendAPIKey}
	default:
		log.Warn("MAIL_DRIVER=log: emails are printed here, not sent (development only)")
		return appmail.LogMailer{Log: log}
	}
}
