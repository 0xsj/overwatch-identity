.PHONY: all build run test clean migrate sqlc proto docker help

# Variables
APP_NAME := overwatch-identity
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Go
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOGET := $(GOCMD) get

# Directories
CMD_DIR := ./cmd/server
BIN_DIR := ./bin
MIGRATIONS_DIR := ./migrations

# Database
DATABASE_URL ?= postgres://overwatch:overwatch@localhost:5450/overwatch_identity?sslmode=disable

# Default target
all: build

## Build

build: ## Build the binary
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(GO_LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) $(CMD_DIR)

build-linux: ## Build for Linux
	@echo "Building $(APP_NAME) for Linux..."
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(GO_LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 $(CMD_DIR)

## Run

run: ## Run the service
	@echo "Running $(APP_NAME)..."
	$(GOCMD) run $(CMD_DIR)

run-build: build ## Build and run
	@echo "Running $(APP_NAME)..."
	$(BIN_DIR)/$(APP_NAME)

## Test

test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

test-cover: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

test-short: ## Run short tests
	$(GOTEST) -v -short ./...

## Code Generation

sqlc: ## Generate sqlc code
	@echo "Generating sqlc..."
	sqlc generate

proto: ## Generate protobuf (run from overwatch-contracts)
	@echo "Protobuf generation should be run from overwatch-contracts"

## Database

migrate-up: ## Run all up migrations
	@echo "Running migrations..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down: ## Run all down migrations
	@echo "Rolling back migrations..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down

migrate-down-one: ## Roll back one migration
	@echo "Rolling back one migration..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-force: ## Force migration version (usage: make migrate-force V=1)
	@echo "Forcing migration version $(V)..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" force $(V)

migrate-version: ## Show current migration version
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version

migrate-create: ## Create new migration (usage: make migrate-create NAME=create_users)
	@echo "Creating migration $(NAME)..."
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(NAME)

## Dependencies

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download

deps-tidy: ## Tidy dependencies
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

deps-verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	$(GOMOD) verify

## Docker

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	docker run --rm --env-file .env --network host $(APP_NAME):latest

docker-push: ## Push Docker image (set REGISTRY)
	@echo "Pushing Docker image..."
	docker tag $(APP_NAME):$(VERSION) $(REGISTRY)/$(APP_NAME):$(VERSION)
	docker tag $(APP_NAME):latest $(REGISTRY)/$(APP_NAME):latest
	docker push $(REGISTRY)/$(APP_NAME):$(VERSION)
	docker push $(REGISTRY)/$(APP_NAME):latest

## Infrastructure

infra-up: ## Start infrastructure (postgres, redis, nats)
	@echo "Starting infrastructure..."
	docker compose -f ../overwatch-infra/docker/docker-compose.yml up -d

infra-down: ## Stop infrastructure
	@echo "Stopping infrastructure..."
	docker compose -f ../overwatch-infra/docker/docker-compose.yml down

infra-logs: ## Show infrastructure logs
	docker compose -f ../overwatch-infra/docker/docker-compose.yml logs -f

## Lint & Format

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run ./...

fmt: ## Format code
	@echo "Formatting code..."
	$(GOCMD) fmt ./...
	goimports -w .

## Clean

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

## Tools

tools: ## Install development tools
	@echo "Installing tools..."
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

## Help

help: ## Show this help
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'