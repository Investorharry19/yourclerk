-- +goose Up
-- +goose StatementBegin
CREATE TABLE sessions (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the session token. The raw token only ever exists in the
    -- user's cookie, so a leaked database cannot be replayed as live sessions.
    token_hash     bytea NOT NULL UNIQUE,
    user_agent     text NOT NULL DEFAULT '',
    ip             text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_active_at timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd
