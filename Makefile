# =============================================================================
#  Makefile — the single entry point for every task in this project.
#
#  Run `make` or `make help` to see everything available.
#
#  Why a Makefile and not a pile of shell scripts: it is self-documenting, it
#  is the one file a new developer opens to learn how to run your project, and
#  it is what CI calls too — so `make test` locally and `make test` in CI are
#  the same command, and cannot drift apart.
# =============================================================================

# Load .env so targets can build a database DSN. `-include` (with the leading
# dash) does not fail when the file is absent, which is correct in CI where
# configuration arrives as real environment variables.
-include .env
export

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
BINARY      := bin/api
MAIN        := ./cmd/api
MIGRATIONS  := migrations

# Stamp the binary with the git commit so a running process can tell you which
# code it is. `2>/dev/null || echo dev` keeps this working outside a git repo.
VERSION     := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS     := -X main.version=$(VERSION)

# goose speaks a URL; pgx and psql speak either. Built here so no target has to
# repeat it. Never echoed — every recipe using it is prefixed with @.
DB_DSN      := postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSLMODE)
TEST_DB_DSN := postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/backend_test?sslmode=$(DB_SSLMODE)

# Homebrew's postgresql@15 is keg-only, so its binaries are not symlinked into
# /opt/homebrew/bin. Make runs recipes with /bin/sh, which does not read your
# .zshrc, so we add the path here too.
export PATH := /opt/homebrew/opt/postgresql@15/bin:$(HOME)/go/bin:$(PATH)

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@echo "Usage: make <target>"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------
.PHONY: run
run: ## Run the API once (no reload)
	go run -ldflags "$(LDFLAGS)" $(MAIN)

.PHONY: dev
dev: ## Run the API with live reload (air)
	air

.PHONY: build
build: ## Compile a production binary into bin/
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS) -s -w" -o $(BINARY) $(MAIN)
	@echo "built $(BINARY) ($(VERSION))"
# CGO_ENABLED=0 produces a statically linked binary with no libc dependency,
# so it runs in a scratch container or on any Linux, regardless of glibc
# version. -s -w strip the symbol table and DWARF data: a smaller binary, at
# the cost of readable stack traces from a core dump.

.PHONY: clean
clean: ## Remove build artifacts and coverage output
	rm -rf bin tmp coverage.out coverage.html

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------
.PHONY: fmt
fmt: ## Format all code (gofumpt + import grouping)
	golangci-lint fmt ./...

.PHONY: lint
lint: ## Run the full linter suite
	golangci-lint run ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Sync go.mod/go.sum with the imports actually used
	go mod tidy

.PHONY: check
check: tidy vet lint test ## Everything CI runs. Run this before you push.

# ---------------------------------------------------------------------------
# API documentation
# ---------------------------------------------------------------------------
.PHONY: docs
docs: ## Regenerate the OpenAPI 3.1 spec from handler annotations
	@command -v swag >/dev/null || (echo "swag not installed. Run: go install github.com/swaggo/swag/v2/cmd/swag@latest" && exit 1)
	swag init --v3.1 -g cmd/api/main.go -o docs --parseInternal --outputTypes json,yaml
	@echo "Regenerated docs/swagger.json and docs/swagger.yaml. Commit them."
# --outputTypes json,yaml deliberately excludes docs.go. That file would
# register the spec in swag v2's global registry, while http-swagger/v2 reads
# swag v1's — two registries, and /docs/doc.json returns 500. We embed the
# JSON instead; see docs/embed.go.

.PHONY: docs-serve
docs-serve: ## Print where to read the docs while the server is running
	@echo "Start the server (make dev), then open:  http://localhost:$(SERVER_PORT)/docs"

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run unit tests (no database required)
	go test -race -count=1 ./...
# -race  enables the data race detector. Go makes concurrency easy, which makes
#        data races easy. It costs ~10x runtime; run it anyway.
# -count=1 disables the test result cache, so a passing test is actually re-run.

.PHONY: test-integration
test-integration: migrate-test-up ## Run integration tests against backend_test (requires a database)
	@TEST_DB_NAME=backend_test go test -race -count=1 -tags=integration -v ./tests/...

.PHONY: test-cover
test-cover: ## Run tests and open an HTML coverage report
	go test -race -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "open coverage.html"

.PHONY: bench
bench: ## Run benchmarks (e.g. to tune the bcrypt cost)
	go test -bench=. -benchmem -run=^$$ ./...

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
.PHONY: db-setup
db-setup: ## Create the app role and the dev/test databases
	@APP_DB_PASSWORD="$(DB_PASSWORD)" ./scripts/setup_db.sh

.PHONY: db-check-auth
db-check-auth: ## Show whether Postgres actually verifies passwords over TCP
	@echo "pg_hba rules currently in force:"
	@psql -d postgres -tAc "SELECT type, COALESCE(address,'(unix socket)'), auth_method FROM pg_hba_file_rules WHERE error IS NULL;" \
		| sed 's/^/  /'
	@echo ""
	@echo "Probing with a deliberately wrong password over TCP:"
	@PGPASSWORD=definitely-not-the-password psql -h $(DB_HOST) -U $(DB_USER) -d $(DB_NAME) -tAc "SELECT 1" >/dev/null 2>&1 \
		&& echo "  WARNING: a wrong password CONNECTED. Auth method is 'trust'; passwords are not checked." \
		|| echo "  OK: a wrong password was rejected. Passwords are enforced."

.PHONY: migrate-up
migrate-up: ## Apply all pending migrations
	@goose -dir $(MIGRATIONS) postgres "$(DB_DSN)" up

.PHONY: migrate-down
migrate-down: ## Roll back exactly one migration
	@goose -dir $(MIGRATIONS) postgres "$(DB_DSN)" down

.PHONY: migrate-status
migrate-status: ## Show which migrations have been applied
	@goose -dir $(MIGRATIONS) postgres "$(DB_DSN)" status

.PHONY: migrate-reset
migrate-reset: ## Roll back EVERY migration (destroys all data)
	@goose -dir $(MIGRATIONS) postgres "$(DB_DSN)" reset

.PHONY: migrate-create
migrate-create: ## Create a new migration: make migrate-create name=add_orders_table
	@test -n "$(name)" || (echo "usage: make migrate-create name=add_orders_table" && exit 1)
	@goose -dir $(MIGRATIONS) create $(name) sql

.PHONY: migrate-test-up
migrate-test-up: ## Apply migrations to the TEST database
	@goose -dir $(MIGRATIONS) postgres "$(TEST_DB_DSN)" up

.PHONY: psql
psql: ## Open a psql shell on the dev database
	@psql "$(DB_DSN)"
