# Prooflog — build automation

BINARY  := prooflog
BIN_DIR := bin
PKG     := ./...

# Version metadata injected into internal/version via -ldflags -X. VERSION is a
# git describe (tag-or-commit), falling back to "dev" outside a git checkout.
# All three are overridable from the environment. BUILD_DATE uses the commit
# timestamp (not wall clock) so rebuilds from the same commit are byte-identical
# and auditors can rebuild-and-compare against the BinaryHash in evidence bundles.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd 2>/dev/null || echo unknown)
VPKG       := github.com/arhuman/prooflog/internal/version
LDFLAGS    := -ldflags "-X $(VPKG).Version=$(VERSION) -X $(VPKG).GitCommit=$(COMMIT) -X $(VPKG).BuildDate=$(BUILD_DATE)"

.PHONY: all audit build clean proto test tidy tools

all: build

build:
	CGO_ENABLED=0 go build -trimpath $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) ./cmd/prooflog

test:
	go test -race $(PKG)

tidy:
	go fmt $(PKG)
	go mod tidy

## audit: run quality control checks
audit:
	@which golangci-lint > /dev/null || $(MAKE) tools
	@which govulncheck > /dev/null || $(MAKE) tools
	go mod verify
	golangci-lint run $(PKG)
	govulncheck $(PKG)

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       proto/prooflog/v1/*.proto

clean:
	rm -rf $(BIN_DIR) coverage.out

## tools: install required Go development tools
tools:
	@echo "Installing Go tools..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3
	@go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	@echo "Tools installed in $(shell go env GOBIN || go env GOPATH)/bin"
