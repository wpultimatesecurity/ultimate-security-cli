# Ultimate Security CLI (wpus)

BINARY_NAME   := wpus
MODULE        := github.com/wpultimatesecurity/ultimate-security-cli
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS       := -s -w \
                 -X $(MODULE)/internal/version.Version=$(VERSION) \
                 -X $(MODULE)/internal/version.GitCommit=$(COMMIT) \
                 -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

PLATFORMS     := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

DIST_DIR      := dist

.PHONY: build test test-race vet fmt fmt-check lint release-local clean help

build: ## Build wpus for the current platform
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/$(BINARY_NAME)

test: ## Run all tests
	go test ./...

test-race: ## Run all tests with the race detector
	go test -race ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format all code
	gofmt -w ./cmd ./internal

fmt-check: ## Verify formatting (CI mode)
	@out=$$(gofmt -l ./cmd ./internal); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

lint: fmt-check vet ## All lint checks

release-local: ## Build all release binaries into dist/
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "==> building $(BINARY_NAME)-$${os}-$${arch}"; \
		GOOS=$${os} GOARCH=$${arch} CGO_ENABLED=0 \
			go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST_DIR)/$(BINARY_NAME)-$${os}-$${arch} ./cmd/$(BINARY_NAME) || exit 1; \
	done
	@cd $(DIST_DIR) && shasum -a 256 $(BINARY_NAME)-* > checksums.txt && cd ..
	@echo "==> artifacts in $(DIST_DIR)/"

clean: ## Remove build artifacts
	rm -rf $(DIST_DIR) $(BINARY_NAME) coverage.*

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
