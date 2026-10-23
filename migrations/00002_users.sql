-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Emails are normalised to lower case by the app; the CHECK makes the
    -- database refuse anything else, so "A@x.com" and "a@x.com" can never coexist.
    email         text NOT NULL UNIQUE CHECK (email = lower(email)),
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
