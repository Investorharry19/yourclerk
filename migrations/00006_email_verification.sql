-- +goose Up
-- +goose StatementBegin

ALTER TABLE users ADD COLUMN email_verified_at timestamptz;

-- One-time tokens for verifying an email address and for resetting a password.
-- Only the SHA-256 of the token is stored; the raw token exists only in the
-- email. A token is spent by setting used_at, in the same transaction as the
-- change it authorises, so it works exactly once.
CREATE TABLE verification_tokens (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL,
    user_id        uuid NOT NULL,
    purpose        text NOT NULL CHECK (purpose IN ('verify', 'reset')),
    token_hash     bytea NOT NULL UNIQUE,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    -- A token belongs to a user of the same application; the database refuses a mix.
    FOREIGN KEY (application_id, user_id) REFERENCES users (application_id, id) ON DELETE CASCADE
);
CREATE INDEX verification_tokens_user_idx ON verification_tokens (application_id, user_id, purpose, created_at DESC);
CREATE INDEX verification_tokens_expires_idx ON verification_tokens (expires_at);

-- A database-backed outbound mail queue. Signup and "forgot password" only
-- insert a row (in the same transaction as the token); a background worker sends
-- it, retrying with backoff. A mail provider outage therefore never fails a request.
--
-- payload is the message (recipient, subject, bodies) encrypted with the server
-- secret, because it contains the raw one-time link. It is wiped once sent.
CREATE TABLE email_outbox (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('verify', 'reset')),
    to_email        text NOT NULL,
    payload         bytea NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'dead')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    -- A claimed row is leased until this time; if the worker dies, the lease
    -- lapses and the row is picked up again (at-least-once delivery).
    locked_until    timestamptz,
    last_error      text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE INDEX email_outbox_due_idx ON email_outbox (next_attempt_at) WHERE status = 'pending';
CREATE INDEX email_outbox_application_idx ON email_outbox (application_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_outbox;
DROP TABLE IF EXISTS verification_tokens;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
-- +goose StatementEnd
