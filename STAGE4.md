# Stage 4: multi-tenancy

Your service is now a platform: developers create **applications**, and every end user belongs to one.

## Apply

```
tar -xf stage4.tar --strip-components=1   # run inside your project folder; it never touches go.mod / go.sum
make migrate-up               # applies 00005_multi_tenancy.sql
go mod tidy
make test                     # set TEST_DATABASE_URL to include the real-Postgres tests
make run                      # then open http://localhost:8080/docs
```

Users, sessions and signing keys from Stages 1-3 are adopted into an application called
"Legacy (migrated from stages 1-3)". Nobody can sign in as its developer. To keep using those
users, point it at your own developer: `UPDATE applications SET developer_id = '<your id>' WHERE name LIKE 'Legacy%';`
(its secret key is unknown; roll it from the API).

## Who uses what

| Caller | Credential | Endpoints |
|---|---|---|
| Developer (dashboard) | `Authorization: Bearer dvt_...` | `/v1/platform/...` |
| Developer's backend | `Authorization: Bearer sk_live_...` | `/v1/backend/...` |
| End users | `X-Publishable-Key: pk_live_...` + session cookie | `/v1/signup`, `/v1/login`, `/v1/me`, ... |

Tokens: issuer `<ISSUER>/apps/<application id>`, audience = application id, keys at
`<issuer>/.well-known/jwks.json`. Point the Go SDK at the issuer URL.

## Try it in Swagger (`/docs`)

1. `POST /v1/platform/signup`, `POST /v1/platform/login`; Authorize with the `token` (developerToken).
2. `POST /v1/platform/applications` twice. Copy each `publishable_key` and `secret_key` (shown once).
3. Authorize with app A's publishable and secret keys. `POST /v1/signup` + `/v1/login` as alice.
4. Switch to app B's publishable key; sign up the **same email** with a different password.
5. `GET /v1/backend/users` with each secret key: each sees only its own users.
6. Put the publishable key in the secret-key slot: 401.
7. `PATCH /v1/platform/applications/{id}` with `{"signup_enabled": false}`: signup in that app now 403s.

## You pass when

- [x] The same email exists in two applications with different passwords (`TestSameEmailInTwoApplicationsWithDifferentPasswords`)
- [x] A token from application A fails against application B (`TestTokenFromOneApplicationFailsAgainstAnother`, `TestServerTokensDoNotCrossApplications` in the SDK)
- [x] A leaked publishable key cannot call secret-key endpoints (`TestPublishableKeyCannotCallSecretKeyEndpoints`)
- [x] Every tenant query is scoped by `application_id` (only `AppStore` can reach those tables; `TestTenantQueriesAreScoped` scans the SQL)

## Known limits (on purpose, for later stages)

- `allowed_origins` is stored and validated but not enforced; CORS arrives in Stage 8.
- The application is looked up in the database on every request (no cache yet).
- Backend user listing uses limit/offset; cursors come in Stage 10.
- Developer sign-up is open and has no email verification or rate limiting (Stages 5 and 8).
- Applications are resolved by key only; custom domains come in Stage 11.
- Revoking a session still leaves its last access token valid for up to 60 seconds.
