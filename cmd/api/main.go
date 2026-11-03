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

	tokens, err := auth.NewTokenService(db, cfg.SecretKey, cfg.Issuer, auth.DefaultAudience, auth.DefaultTokenTTL)
	if err != nil {
		return fmt.Errorf("token service: %w", err)
	}
	if err := tokens.EnsureKey(ctx, time.Now()); err != nil {
		return fmt.Errorf("ensure signing key: %w", err)
	}

	go cleanupSessions(ctx, log, db, time.Hour)

	srv := &nethttp.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
		Handler: apphttp.NewServer(log, db, db, db, apphttp.Options{
			CookieSecure: cfg.CookieSecure,
			Tokens:       tokens,
			EnableDocs:   cfg.EnableDocs,
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", srv.Addr, "env", cfg.Env, "issuer", cfg.Issuer)
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
