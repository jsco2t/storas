SHELL := /usr/bin/env bash

GO ?= go
DOCKER ?= docker

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod

BIN_DIR ?= bin
BINARY ?= storas
IMAGE ?= storas:dev
CONFIG_FILE ?= ./configs/config.yaml

GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './.cache/*')
MD_FILES := $(shell find . -type f -name '*.md' -not -path './.git/*' -not -path './.cache/*')

.PHONY: help lint lint-go lint-md build test test-integration test-compat test-compat-aws test-compat-rclone test-stress test-race-concurrency test-restore-integrity ci-check-tests verify mod-tidy run run-config dev clean build-container

STRESS_TEST_PACKAGES ?= ./internal/storage ./internal/api ./test/stress
STRESS_TEST_TAGS ?= stress
STRESS_TEST_REPEAT ?= 1
STRESS_TEST_TIMEOUT ?= 20m
STRESS_TEST_RUN ?=
STRESS_WORKLOAD_DURATION ?=

help:
	@echo "Common targets:"
	@echo "  make lint            - run Go and markdown linters"
	@echo "  make build           - build the service binary"
	@echo "  make test            - run all Go tests"
	@echo "  make test-integration- run integration test package(s)"
	@echo "  make test-compat     - run compatibility test package(s)"
	@echo "  make test-stress     - run opt-in stress/concurrency suites"
	@echo "  make test-race-concurrency - run stress/concurrency suites with -race"
	@echo "  make test-restore-integrity - run backup/restore integrity flow"
	@echo "  make verify          - lint + build + all test suites"
	@echo "  make mod-tidy        - tidy Go module dependencies"
	@echo "  make run             - build and run the service binary"
	@echo "  make run-config      - run service using CONFIG_FILE"
	@echo "  make dev             - run service with local sample config"
	@echo "  make build-container - build container image (requires Dockerfile)"
	@echo "  make clean           - remove local build outputs"

lint: lint-go lint-md

lint-go:
	@if [[ -n "$(GO_FILES)" ]]; then \
		unformatted="$$(gofmt -l $(GO_FILES))"; \
		if [[ -n "$$unformatted" ]]; then \
			echo "Go files need formatting:"; \
			echo "$$unformatted"; \
			exit 1; \
		fi; \
	fi
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) vet ./...

lint-md:
	@if [[ -n "$(MD_FILES)" ]]; then \
		npx --yes markdownlint-cli2 $(MD_FILES); \
	fi

build:
	@mkdir -p $(BIN_DIR)
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -o $(BIN_DIR)/$(BINARY) ./cmd/$(BINARY)

test:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

test-integration:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./test/...

test-compat:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./test/compat/...

test-compat-aws:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./test/compat/... -run TestAWSSDKCompatibilitySuite

test-compat-rclone:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./test/compat/... -run TestRcloneCompatibilitySuite

test-stress:
	@STRESS_WORKLOAD_DURATION=$(STRESS_WORKLOAD_DURATION) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test -tags $(STRESS_TEST_TAGS) -count=$(STRESS_TEST_REPEAT) -timeout $(STRESS_TEST_TIMEOUT) $(if $(STRESS_TEST_RUN),-run $(STRESS_TEST_RUN),) $(STRESS_TEST_PACKAGES)

test-race-concurrency:
	@STRESS_WORKLOAD_DURATION=$(STRESS_WORKLOAD_DURATION) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test -tags $(STRESS_TEST_TAGS) -race -count=$(STRESS_TEST_REPEAT) -timeout $(STRESS_TEST_TIMEOUT) $(if $(STRESS_TEST_RUN),-run $(STRESS_TEST_RUN),) $(STRESS_TEST_PACKAGES)

test-restore-integrity:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./test/integration/... -run TestIntegrationBackupRestoreFromFilesystemSnapshot

ci-check-tests:
	@./scripts/ci-check-test-updates.sh

verify: lint build test test-integration test-compat ci-check-tests

mod-tidy:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) mod tidy

run: build
	@./$(BIN_DIR)/$(BINARY)

run-config: build
	@./$(BIN_DIR)/$(BINARY) -config $(CONFIG_FILE)

dev: CONFIG_FILE=./configs/config.yaml
dev: run-config

build-container:
	@if [[ ! -f Dockerfile ]]; then \
		echo "Dockerfile not found. Add Dockerfile before running make build-container."; \
		exit 1; \
	fi
	@$(DOCKER) build -t $(IMAGE) .

clean:
	@rm -rf $(BIN_DIR)
