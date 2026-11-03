// Command demo is a tiny backend protected by the yourclerk Go SDK.
//
//	YOURCLERK_ISSUER=http://localhost:8080 go run ./examples/demo
//
// It has no shared secret with the yourclerk server and does not call it per
// request: it only downloads the public keys (JWKS) and caches them.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	yourclerk "github.com/Investorharry19/yourclerk-go"
)

func main() {
	issuer := getenv("YOURCLERK_ISSUER", "http://localhost:8080")
	addr := getenv("ADDR", ":9090")

	clerk, err := yourclerk.New(yourclerk.Config{
		Issuer: issuer,
		// The client only ever sees a generic 401; the reason is logged here.
		OnError: func(r *http.Request, err error) {
			log.Printf("rejected %s %s: %v", r.Method, r.URL.Path, err)
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"message": "public route: no token needed"})
	})
	mux.Handle("GET /private", clerk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := yourclerk.ClaimsFromContext(r.Context())
		writeJSON(w, map[string]any{
			"message":    "private route: your token is valid",
			"user_id":    claims.UserID(),
			"session_id": claims.SessionID,
			"expires_at": claims.ExpiresAt,
		})
	})))

	log.Printf("demo backend on %s, verifying tokens from %s", addr, issuer)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
