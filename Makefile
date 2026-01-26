.PHONY: help build run test clean docker-build docker-up docker-down docker-logs setup

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	go build -o schat .

run: ## Run the application locally
	go run main.go

test: ## Run tests
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format code
	go fmt ./...

clean: ## Clean build artifacts
	rm -f schat ssh_host_key

setup: ## Run setup script
	./setup.sh

docker-build: ## Build docker image
	docker compose build

docker-up: ## Start services with docker compose
	docker compose up -d

docker-down: ## Stop services
	docker compose down

docker-logs: ## View docker logs
	docker compose logs -f

docker-restart: ## Restart services
	docker compose restart

docker-clean: ## Stop services and remove volumes
	docker compose down -v
