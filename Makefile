APP_NAME := device-cert-issuer
MAIN_PKG := ./cmd/device-cert-issuer
GOCACHE ?= $(CURDIR)/.gocache
GOLANGCI_LINT_CACHE ?= $(CURDIR)/.golangci-lint-cache
OAPI_CODEGEN_VERSION ?= v2.5.0
SQLC_VERSION ?= v1.30.0

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: help fmt lint test test-cover generate generate-openapi generate-sqlc build run clean

help:
	@grep -E '^[a-zA-Z_-]+:.*##' Makefile | awk 'BEGIN {FS = ":.*## "}; {printf "%-20s %s\n", $$1, $$2}'

fmt: ## format go code
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint: ## run linters
	GOCACHE=$(GOCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) golangci-lint run ./...

test: ## run unit tests
	GOCACHE=$(GOCACHE) go test ./...

test-cover: ## run tests with coverage
	GOCACHE=$(GOCACHE) go test -coverprofile=coverage.out ./...

generate: generate-openapi generate-sqlc ## generate all code

generate-openapi: ## generate openapi bindings
	GOCACHE=$(GOCACHE) go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) --config build/oapi-codegen.yaml api/openapi.yaml

generate-sqlc: ## generate sqlc code
	GOCACHE=$(GOCACHE) go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

build: ## build binary
	GOCACHE=$(GOCACHE) go build -o build/$(APP_NAME) $(MAIN_PKG)

run: ## run service
	GOCACHE=$(GOCACHE) go run $(MAIN_PKG)

clean: ## remove build outputs
	rm -f build/$(APP_NAME) coverage.out
	rm -rf $(GOCACHE) $(GOLANGCI_LINT_CACHE)
