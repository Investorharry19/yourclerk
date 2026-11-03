-- +goose Up
-- +goose StatementBegin
CREATE TABLE signing_keys (
    kid                   text PRIMARY KEY,
    algorithm             text NOT NULL,
    -- DER-encoded PKIX public key. Public by design: it is published in the JWKS.
    public_key            bytea NOT NULL,
    -- AES-256-GCM(nonce || ciphertext) of the PKCS#8 private key, keyed from SECRET_KEY.
    private_key_encrypted bytea NOT NULL,
    -- A key is published in the JWKS from created_at on...
    created_at            timestamptz NOT NULL DEFAULT now(),
    -- ...but only starts signing at active_from. A rotated-in key is published
    -- first so every verifier can cache it before any token needs it.
    active_from           timestamptz NOT NULL DEFAULT now(),
    -- When the key stops signing; NULL means not scheduled. A time in the future
    -- means it keeps signing until then (when its successor activates). After
    -- retirement it stays in the JWKS for a grace period so tokens signed just
    -- before the switch keep verifying.
    retired_at            timestamptz
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS signing_keys;
-- +goose StatementEnd
