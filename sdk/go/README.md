# yourclerk-go

Verify yourclerk access tokens in your own Go backend. Standard library only.

```go
// Issuer is your application's issuer URL from the dashboard / API:
// "<service base URL>/apps/<application id>". Its id doubles as the token audience.
clerk, err := yourclerk.New(yourclerk.Config{Issuer: "https://auth.example.com/apps/0f6c1d2e-7a3b-4c5d-8e9f-a1b2c3d4e5f6"})
if err != nil { log.Fatal(err) }

mux := http.NewServeMux()
mux.Handle("GET /private", clerk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, _ := yourclerk.ClaimsFromContext(r.Context())
    fmt.Fprintf(w, "hello user %s", claims.UserID())
})))
```

Or verify by hand: `claims, err := clerk.VerifyToken(ctx, token)` and test the error with
`errors.Is(err, yourclerk.ErrTokenExpired)`.

## How it works

- Tokens are ES256 JWTs that live 60 seconds. Your frontend gets one from
  `POST /v1/sessions/{id}/token` and sends it as `Authorization: Bearer <token>`.
- **Each application has its own keys, issuer and audience.** A token minted for another application
  fails here three ways over: wrong issuer, wrong audience, and a signing key your JWKS does not list.
- The client downloads the issuer's public keys from `<issuer>/.well-known/jwks.json`, caches them
  (5 minutes by default) and checks every signature locally. **No shared secret, and no call
  to yourclerk on the request path.**
- It checks signature, `exp`, `nbf`, `iss` and `aud`. The algorithm in the token header is never
  trusted: only exact `ES256` is accepted, so `alg: none` and HS256 tricks fail.
- **Key rotation is invisible to users.** The server publishes a new key in the JWKS 10 minutes
  before it signs anything (longer than your 5-minute cache), and keeps a retired key listed for
  24 hours so tokens signed just before the switch keep working. As a safety net, a token naming
  a key you have not seen triggers one refetch, rate-limited to once per `MinRefreshInterval`
  (10s) so a flood of junk cannot hammer the issuer.
- If the issuer is unreachable when the cache goes stale, the old keys keep working.
- `RequireAuth` returns the same generic 401 whatever was wrong; the reason goes to `Config.OnError`.
  If no keys can be fetched at all it returns 503.

## Revocation

Tokens are not checked against the server, so a revoked session's last token can still pass for up
to 60 seconds. That is the trade-off of local verification. New tokens stop immediately.

## Try it

```
# terminal 1: the yourclerk API (from the repo root)      make run
# terminal 2: this demo backend                           make demo
```

Then get a token (see the main project's `/docs` page, or curl) and call the demo:

```
curl -s localhost:9090/private                                   # 401
curl -s localhost:9090/private -H "Authorization: Bearer $TOKEN" # 200
```
