-- +goose Up
-- +goose StatementBegin

-- Developers are the people who use the dashboard. They own applications.
CREATE TABLE developers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text NOT NULL UNIQUE CHECK (email = lower(email)),
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Developers sign in to the platform API with an opaque bearer token; only its hash is stored.
CREATE TABLE developer_sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id uuid NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);
CREATE INDEX developer_sessions_developer_id_idx ON developer_sessions (developer_id);

-- An application is one tenant: its own users, sessions, signing keys and settings.
CREATE TABLE applications (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id    uuid NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    -- Safe to expose in browsers, so stored as is. It only identifies the application.
    publishable_key text NOT NULL UNIQUE,
    -- SHA-256 of the secret key. The key itself is shown once at creation and never stored.
    secret_key_hash bytea NOT NULL UNIQUE,
    -- Last four characters of the secret key, so the dashboard can say which key is active.
    secret_key_last4 text NOT NULL CHECK (char_length(secret_key_last4) = 4),

    allowed_origins                text[]  NOT NULL DEFAULT '{}',
    session_lifetime_seconds       integer NOT NULL DEFAULT 2592000 CHECK (session_lifetime_seconds BETWEEN 3600 AND 31536000),
    session_idle_timeout_seconds   integer NOT NULL DEFAULT 604800  CHECK (session_idle_timeout_seconds BETWEEN 300 AND 31536000),
    signup_enabled                 boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (session_idle_timeout_seconds <= session_lifetime_seconds)
);
CREATE INDEX applications_developer_id_idx ON applications (developer_id);

-- Tenant columns. Added nullable first so existing rows can be adopted below.
ALTER TABLE users        ADD COLUMN application_id uuid REFERENCES applications(id) ON DELETE CASCADE;
ALTER TABLE sessions     ADD COLUMN application_id uuid REFERENCES applications(id) ON DELETE CASCADE;
ALTER TABLE signing_keys ADD COLUMN application_id uuid REFERENCES applications(id) ON DELETE CASCADE;

-- Signing keys are re-created automatically, now encrypted per application.
-- Tokens live 60 seconds, so dropping the old ones costs nothing.
DELETE FROM signing_keys;

-- Users created in earlier stages belong to no application. Rather than delete
-- them, adopt them into a "Legacy" application. Nobody can sign in as its
-- developer or knows its secret key; to keep using these users, point the
-- application at a real developer:
--   UPDATE applications SET developer_id = '<your developer id>' WHERE name LIKE 'Legacy%';
DO $$
DECLARE
    legacy_dev uuid;
    legacy_app uuid;
BEGIN
    IF EXISTS (SELECT 1 FROM users) THEN
        INSERT INTO developers (email, password_hash)
        VALUES ('legacy@yourclerk.invalid', '!cannot-log-in')
        RETURNING id INTO legacy_dev;

        INSERT INTO applications (developer_id, name, publishable_key, secret_key_hash, secret_key_last4)
        VALUES (
            legacy_dev,
            'Legacy (migrated from stages 1-3)',
            'pk_live_' || translate(encode(gen_random_bytes(18), 'base64'), '+/', '-_'),
            digest(gen_random_bytes(32), 'sha256'),
            'none'
        )
        RETURNING id INTO legacy_app;

        UPDATE users SET application_id = legacy_app;
        UPDATE sessions s SET application_id = u.application_id FROM users u WHERE u.id = s.user_id;
    END IF;
END
$$;

ALTER TABLE users        ALTER COLUMN application_id SET NOT NULL;
ALTER TABLE sessions     ALTER COLUMN application_id SET NOT NULL;
ALTER TABLE signing_keys ALTER COLUMN application_id SET NOT NULL;

-- An email is unique per application, not globally.
ALTER TABLE users DROP CONSTRAINT users_email_key;
ALTER TABLE users ADD CONSTRAINT users_app_email_key UNIQUE (application_id, email);

-- A session must belong to a user of the same application. The composite
-- foreign key makes the database itself refuse a cross-tenant session.
ALTER TABLE users ADD CONSTRAINT users_app_id_key UNIQUE (application_id, id);
ALTER TABLE sessions DROP CONSTRAINT sessions_user_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_app_user_fkey
    FOREIGN KEY (application_id, user_id) REFERENCES users (application_id, id) ON DELETE CASCADE;

CREATE INDEX sessions_application_id_idx ON sessions (application_id);
CREATE INDEX signing_keys_application_id_idx ON signing_keys (application_id, active_from DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- This fails on purpose if two applications now share an email address:
-- global uniqueness cannot be restored without deleting one of the users.
DROP INDEX IF EXISTS signing_keys_application_id_idx;
DROP INDEX IF EXISTS sessions_application_id_idx;

ALTER TABLE sessions DROP CONSTRAINT sessions_app_user_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE users DROP CONSTRAINT users_app_id_key;
ALTER TABLE users DROP CONSTRAINT users_app_email_key;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE signing_keys DROP COLUMN application_id;
ALTER TABLE sessions     DROP COLUMN application_id;
ALTER TABLE users        DROP COLUMN application_id;

DROP TABLE applications;
DROP TABLE developer_sessions;
DROP TABLE developers;
-- +goose StatementEnd
