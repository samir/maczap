# Development commands for maczap. Run `make` or `make help` for the list.

CARGO   ?= cargo
BIN     := target/debug/maczap
TARGETS := aarch64-apple-darwin x86_64-apple-darwin
# Arguments passed to `make run`, e.g. make run ARGS="scan Rectangle"
ARGS    ?= --help

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this list
	@cat ./banner.txt
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

## ---- Build ---------------------------------------------------------------

.PHONY: build
build: ## Build the debug binary
	$(CARGO) build --workspace

.PHONY: release
release: ## Build the optimized binary for this Mac
	$(CARGO) build --release -p maczap

.PHONY: run
run: build ## Run the debug binary: make run ARGS="scan Rectangle"
	$(BIN) $(ARGS)

.PHONY: install
install: ## Install maczap and its `mz` alias into ~/.cargo/bin
	$(CARGO) install --path crates/maczap --locked
	@bin="$${CARGO_INSTALL_ROOT:-$${CARGO_HOME:-$$HOME/.cargo}}/bin"; \
	ln -sf maczap "$$bin/mz" && echo "  Alias: $$bin/mz -> maczap"

## ---- Quality -------------------------------------------------------------

.PHONY: fmt
fmt: ## Format the code
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Check the formatting (as CI does)
	$(CARGO) fmt --all --check

.PHONY: lint
lint: ## Run clippy with warnings as errors (as CI does)
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: fix
fix: ## Apply clippy suggestions, then format
	$(CARGO) clippy --fix --allow-dirty --allow-no-vcs --workspace --all-targets
	$(CARGO) fmt --all

## ---- Tests ---------------------------------------------------------------

.PHONY: test
test: ## Run every test (unit, integration, contract, E2E)
	$(CARGO) test --workspace

.PHONY: test-core
test-core: ## Run the maczap-core tests only
	$(CARGO) test -p maczap-core

.PHONY: test-e2e
test-e2e: ## Run the end-to-end tests of the binary (sandboxed)
	$(CARGO) test -p maczap --test e2e

.PHONY: test-contract
test-contract: ## Run the contract tests against this Mac, incl. the one that launches Chess
	$(CARGO) test -p maczap-core --test mac_platform -- --include-ignored

.PHONY: smoke
smoke: build ## Real sudo round trip with a throw-away app (asks for your password)
	scripts/privileged-smoke.sh $(BIN)

.PHONY: ci
ci: fmt-check lint test ## Run the same checks as the CI workflow

## ---- Release -------------------------------------------------------------

.PHONY: dist-plan
dist-plan: ## Show what a release would publish
	dist plan

.PHONY: dist-build
dist-build: ## Build the release archives for Apple Silicon and Intel
	dist build --artifacts=local $(addprefix -t ,$(TARGETS))

.PHONY: dist-generate
dist-generate: ## Regenerate .github/workflows/release.yml after a dist config change
	dist generate

## ---- Housekeeping --------------------------------------------------------

.PHONY: doctor
doctor: build ## Check permissions and environment on this Mac
	$(BIN) doctor

.PHONY: clean
clean: ## Remove build outputs (target/ and the spike's target/)
	$(CARGO) clean
	$(CARGO) clean --manifest-path spikes/native-spike/Cargo.toml
