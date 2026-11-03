Fixtures produced by the real server code (`internal/auth.TokenService`) so the SDK is
tested against tokens it did not sign itself.

Application A, id `0f6c1d2e-7a3b-4c5d-8e9f-a1b2c3d4e5f6`, issuer
`https://auth.example.com/apps/0f6c1d2e-7a3b-4c5d-8e9f-a1b2c3d4e5f6`, audience = the id:

- `server_jwks.json`: A's JWKS after one key rotation (two keys)
- `server_token_old_key.txt`: issued 2026-10-23T12:00:00Z with A's first key, valid 1h
- `server_token_new_key.txt`: issued 2026-10-23T12:02:00Z with A's rotated key, valid 1h

Application B, id `9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d`, same base URL:

- `server_jwks_other_app.json`: B's JWKS (one key)
- `server_token_other_app.txt`: a token issued by B at 2026-10-23T12:02:00Z

sub `user-fixture`, sid `sess-fixture`. Tokens are long expired in real time; the tests pin the clock.
Regenerate only if the token format changes.
