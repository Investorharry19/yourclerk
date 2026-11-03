Fixtures produced by the real server code (`internal/auth.TokenService`) so the SDK is
tested against tokens it did not sign itself:

- `server_jwks.json`: the JWKS after one key rotation (two keys)
- `server_token_old_key.txt`: issued 2026-10-23T12:00:00Z with the first key, valid 1h
- `server_token_new_key.txt`: issued 2026-10-23T12:02:00Z with the rotated key, valid 1h

issuer `https://auth.example.com`, audience `yourclerk`, sub `user-fixture`, sid `sess-fixture`.
Tokens are long expired in real time; the test pins the clock. Regenerate only if the token format changes.
