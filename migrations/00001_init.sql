-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE app_meta (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO app_meta (key, value) VALUES ('schema_origin', 'stage-0');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_meta;
-- +goose StatementEnd
