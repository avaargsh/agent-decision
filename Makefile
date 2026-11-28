# Local helpers for a checkout of this repository.
#
# GitHub Actions installs the Go version declared by go.mod
# (actions/setup-go with go-version-file: go.mod). These targets set
# GOTOOLCHAIN=local and use that installed toolchain. They do not download
# one. PostgreSQL integration tests skip when DATABASE_URL is unset, so
# `make test` does not start PostgreSQL.
#
# Main packages compiled by `make build`:
#   agent-decision, decision-catalog-attest, decision-role-audit.

.PHONY: help build test vet lint run clean require-go

# Recipes, and any Go command they invoke, stay on the installed toolchain.
override export GOTOOLCHAIN := local

# Keep build and clean inside the documented repository-local output directory.
override BIN_DIR := bin

PORT ?= 8080

.DEFAULT_GOAL := help

help:
	@echo "Targets (GOTOOLCHAIN=local; the installed Go only; no toolchain download):"
	@echo "  go.mod requires Go 1.22 or newer. CI installs that version from go.mod."
	@echo "  make help   - list targets (default)"
	@echo "  make build  - compile agent-decision, decision-catalog-attest, and decision-role-audit into $(BIN_DIR)/"
	@echo "  make test   - go test -race -count=1 ./... (PostgreSQL tests skip without DATABASE_URL)"
	@echo "  make vet    - go vet ./..."
	@echo "  make lint   - gofmt -l . must be empty; a gofmt error fails the target"
	@echo "  make run    - go run ./cmd/agent-decision --port \$$PORT (default $(PORT); 127.0.0.1 only)"
	@echo "  make clean  - delete $(BIN_DIR)/ only; does not clear the Go build cache"

require-go:
	@need=$$(sed -n 's/^go \([0-9][0-9]*\(\.[0-9][0-9]*\)*\).*/\1/p' go.mod | head -n 1); \
	if [ -z "$$need" ]; then \
		printf '%s\n' "error: could not read the required Go version from go.mod." >&2; \
		exit 1; \
	fi; \
	if ! command -v go >/dev/null 2>&1; then \
		printf '%s\n' "error: go is not installed or not on PATH. Install Go $$need or newer. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi; \
	if ! command -v gofmt >/dev/null 2>&1; then \
		printf '%s\n' "error: gofmt is not installed or not on PATH. It ships with the Go toolchain. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi; \
	raw=$$(go env GOVERSION 2>/dev/null || true); \
	have=$$(printf '%s\n' "$$raw" | sed -n 's/^go\([0-9][0-9]*\(\.[0-9][0-9]*\)*\)$$/\1/p' | head -n 1); \
	if [ -z "$$have" ]; then \
		printf '%s\n' "error: a stable local Go release is required; unexpected 'go env GOVERSION' (got: $${raw:-empty}). This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi; \
	version_at_least() { \
		have_v="$$1"; need_v="$$2"; \
		while [ -n "$$have_v" ] || [ -n "$$need_v" ]; do \
			h="$${have_v%%.*}"; n="$${need_v%%.*}"; \
			if [ "$$have_v" = "$$h" ]; then have_v=""; else have_v="$${have_v#*.}"; fi; \
			if [ "$$need_v" = "$$n" ]; then need_v=""; else need_v="$${need_v#*.}"; fi; \
			h="$${h%%[!0-9]*}"; n="$${n%%[!0-9]*}"; \
			h="$${h:-0}"; n="$${n:-0}"; \
			if [ "$$h" -gt "$$n" ]; then return 0; fi; \
			if [ "$$h" -lt "$$n" ]; then return 1; fi; \
		done; \
		return 0; \
	}; \
	if ! version_at_least "$$have" "$$need"; then \
		printf '%s\n' "error: local Go $$have is older than go.mod requires Go $$need. Install Go $$need or newer. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi

build: require-go
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/agent-decision ./cmd/agent-decision
	go build -o $(BIN_DIR)/decision-catalog-attest ./cmd/decision-catalog-attest
	go build -o $(BIN_DIR)/decision-role-audit ./cmd/decision-role-audit

test: require-go
	go test -race -count=1 ./...

vet: require-go
	go vet ./...

lint: require-go
	@unformatted=$$(gofmt -l .) || exit $$?; \
	if [ -n "$$unformatted" ]; then \
		printf 'Unformatted Go files:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi

run: require-go
	go run ./cmd/agent-decision --port "$(PORT)"

clean:
	rm -rf $(BIN_DIR)
