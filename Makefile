# Aegis-eBPF build entry point. Every target runs in Docker: the host only
# needs Docker with BuildKit (Docker Engine 23 or later). Run `make help`.

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REGISTRY ?= ghcr.io/sanabriadiosnel86-dotcom
DOCKER   ?= docker
REDOCLY  ?= redocly/cli:2.54.2
# Extra flags for docker build, such as --platform=linux/arm64 or --no-cache.
BUILD_FLAGS ?=

AGENT_IMAGE := $(REGISTRY)/aegis-agent:$(VERSION)
PROBE_IMAGE := $(REGISTRY)/aegis-probe:$(VERSION)
BUILD       := $(DOCKER) build $(BUILD_FLAGS) --build-arg VERSION=$(VERSION)
COMPOSE     := VERSION=$(VERSION) REGISTRY=$(REGISTRY) $(DOCKER) compose -f deploy/compose.yaml

.DEFAULT_GOAL := all

.PHONY: all
all: build images ## Compile both binaries and build both images

.PHONY: build
build: ## Compile aegis-agent and aegis-probe into ./bin
	$(BUILD) --target artifacts --output type=local,dest=bin .

.PHONY: images
images: image-agent image-probe ## Build the runtime images

.PHONY: image-agent
image-agent: ## Build the image of the control plane
	$(BUILD) --target aegis-agent --tag $(AGENT_IMAGE) .

.PHONY: image-probe
image-probe: ## Build the image of the eBPF probe
	$(BUILD) --target aegis-probe --tag $(PROBE_IMAGE) .

.PHONY: test
test: test-go test-rust lint-api ## Run every check

.PHONY: test-go
test-go: ## gofmt, go vet and the Go tests, OpenAPI contract tests included
	$(BUILD) --target go-test --output type=cacheonly .

.PHONY: test-rust
test-rust: ## rustfmt, clippy and the Rust tests
	$(BUILD) --target rust-test --output type=cacheonly .

.PHONY: lint-api
lint-api: ## Lint api/openapi.yaml with Redocly CLI
	$(DOCKER) run --rm --volume "$(CURDIR)/api:/spec:ro" --workdir /spec $(REDOCLY) lint openapi.yaml

.PHONY: up
up: images ## Run the agent and the probe on this Docker host
	$(COMPOSE) up

.PHONY: down
down: ## Stop what `make up` started
	$(COMPOSE) down

.PHONY: clean
clean: ## Remove the compiled binaries
	rm -rf bin

.PHONY: help
help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{ printf "  %-12s %s\n", $$1, $$2 }'
