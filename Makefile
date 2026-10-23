-include .env
export

GOOSE := go run github.com/pressly/goose/v3/cmd/goose@v3.24.1
MIGRATE = $(GOOSE) -dir migrations postgres "$(DATABASE_URL)"

.PHONY: up down run test vet build migrate-up migrate-down migrate-status

up: ## start Postgres and Mailpit
	docker compose up -d --wait

down: ## stop containers
	docker compose down

run: ## run the API server
	go run ./cmd/api

build:
	go build -o bin/api ./cmd/api

vet:
	go vet ./...

test: ## run all tests (DB tests need TEST_DATABASE_URL)
	go test ./... -race -count=1

migrate-up:
	$(MIGRATE) up

migrate-down: ## roll back one migration
	$(MIGRATE) down

migrate-status:
	$(MIGRATE) status
