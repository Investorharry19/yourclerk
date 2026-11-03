-include .env
export

GOOSE := go run github.com/pressly/goose/v3/cmd/goose@v3.24.1
MIGRATE = $(GOOSE) -dir migrations postgres "$(DATABASE_URL)"

.PHONY: up down run test test-race test-sdk vet build migrate-up migrate-down migrate-status rotate-key list-keys demo

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
	go test ./... -count=1

test-race: ## needs cgo; works on Linux and in CI
	go test ./... -race -count=1

migrate-up:
	$(MIGRATE) up

migrate-down: ## roll back one migration
	$(MIGRATE) down

migrate-status:
	$(MIGRATE) status

rotate-key: ## publish a new JWT key now; it starts signing in 10 minutes (-delay 0 for dev)
	go run ./cmd/keys rotate

list-keys:
	go run ./cmd/keys list

test-sdk: ## test the Go SDK (a separate module)
	cd sdk/go && go vet ./... && go test ./... -count=1

demo: ## run the SDK demo app on :9090 (needs the API running)
	cd sdk/go && go run ./examples/demo
