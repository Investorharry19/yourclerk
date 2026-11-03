// Command keys manages JWT signing keys.
//
//	go run ./cmd/keys list <application-id>                 show an application's published keys
//	go run ./cmd/keys rotate [-delay 10m] <application-id>  publish a new key now; it starts signing after the delay
//
// Every application has its own signing keys; rotating one leaves the others alone.
// (Developers can also rotate from the API: POST /v1/platform/applications/{id}/signing-keys/rotate.)
//
// Rotation is two-phase so users never see a failed request: the new key is
// published in the JWKS immediately but signs nothing until the delay has passed,
// giving every verifier time to cache it. The old key keeps signing until then
// and stays in the JWKS for 24 hours afterwards, so its tokens keep verifying.
// Use "-delay 0" only in local development.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/config"
	"github.com/Investorharry19/yourclerk/internal/store"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "rotate" && os.Args[1] != "list") {
		fmt.Fprintln(os.Stderr, "usage: keys list <application-id> | keys rotate [-delay 10m] <application-id>")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	delay := fs.Duration("delay", auth.KeyActivationDelay, "how long the new key is published before it starts signing")
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "an application id is required (flags go before it)")
		os.Exit(2)
	}
	if err := run(os.Args[1], fs.Arg(0), *delay); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cmd, appID string, delay time.Duration) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	app, err := db.ApplicationByID(ctx, appID)
	if err != nil {
		return fmt.Errorf("application %q: %w", appID, err)
	}

	switch cmd {
	case "list":
		keys, err := db.KeysFor(app.ID).PublishedSigningKeys(ctx, time.Now().Add(-auth.KeyGrace))
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			fmt.Println("no published keys yet (one is created with the application, or on its first token)")
		}
		for _, k := range keys {
			now := time.Now()
			state := "signing"
			switch {
			case k.ActiveFrom.After(now):
				state = "pending, signs from " + k.ActiveFrom.Format(time.RFC3339)
			case k.RetiredAt != nil && !k.RetiredAt.After(now):
				state = "retired " + k.RetiredAt.Format(time.RFC3339)
			case k.RetiredAt != nil:
				state = "signing until " + k.RetiredAt.Format(time.RFC3339)
			}
			fmt.Printf("%s  %s  published %s  %s\n", k.KID, k.Algorithm, k.CreatedAt.Format(time.RFC3339), state)
		}
	case "rotate":
		ts, err := auth.NewTokenService(db, cfg.SecretKey, cfg.Issuer, auth.DefaultTokenTTL)
		if err != nil {
			return err
		}
		if err := ts.EnsureKey(ctx, app.ID, time.Now()); err != nil {
			return err
		}
		kid, activeFrom, err := ts.Rotate(ctx, app.ID, time.Now(), delay)
		if err != nil {
			return err
		}
		fmt.Printf("application %s (%s): published new key %s; it starts signing at %s\n", app.Name, app.ID, kid, activeFrom.Format(time.RFC3339))
	}
	return nil
}
