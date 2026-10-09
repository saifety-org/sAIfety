.DEFAULT_GOAL := build

# CI and local checks must use pinned modules, never a developer's go.work.
export GOWORK := off
export GOFLAGS := -mod=readonly
GOLANGCI_LINT_VERSION := v2.14.0
GOLANGCI_LINT ?= $(CURDIR)/bin/golangci-lint

.PHONY: fmt-check lint lint-install ci-test ci-build

fmt-check:
	bash scripts/check-format.sh

lint-install:
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: fmt-check vet
	@$(GOLANGCI_LINT) version | grep -F 'version $(GOLANGCI_LINT_VERSION:v%=%) ' >/dev/null || { echo 'Run make lint-install (requires $(GOLANGCI_LINT_VERSION))'; exit 1; }
	$(GOLANGCI_LINT) run --config .golangci.yml ./...
	$(GOLANGCI_LINT) run --config .golangci.yml --build-tags onnx ./...

# Builds:
#   build        ONNX-enabled build (-tags onnx, needs a C compiler).
#                Uses the embedded classifier unless configured otherwise.
#   build-lite   pure-Go build (no cgo, no native runtime, embedded classifier).
#
# Install:
#   install      go install into $(go env GOPATH)/bin (needs Go + that dir on PATH).
#   install-bin  copy the built binary into PREFIX/bin (default /usr/local/bin,
#                which is on PATH by default). Use sudo if PREFIX is system-owned,
#                or set PREFIX=$HOME/.local and add its bin to PATH.

PREFIX ?= /usr/local
VERSION := $(shell date +%Y-%m-%d-%H%M%S)
LDFLAGS := -X github.com/saifety-org/sAIfety/internal/cli.Version=$(VERSION)

.PHONY: build build-lite install install-lite install-bin install-bin-lite update reset-state test vet

build:
	go build -tags onnx -ldflags "$(LDFLAGS)" -o bin/saifety ./cmd/saifety

build-lite:
	go build -ldflags "$(LDFLAGS)" -o bin/saifety ./cmd/saifety

install:
	go install -tags onnx -ldflags "$(LDFLAGS)" ./cmd/saifety

install-lite:
	go install -ldflags "$(LDFLAGS)" ./cmd/saifety

install-bin: build
	@$(MAKE) --no-print-directory _copybin

install-bin-lite: build-lite
	@$(MAKE) --no-print-directory _copybin

# _copybin places bin/saifety into PREFIX/bin, with a clear hint if the
# destination needs elevated permissions.
_copybin:
	@mkdir -p "$(PREFIX)/bin" 2>/dev/null || true
	@if [ -w "$(PREFIX)/bin" ]; then \
		cp bin/saifety "$(PREFIX)/bin/saifety" && chmod 0755 "$(PREFIX)/bin/saifety" && \
		echo "installed $(PREFIX)/bin/saifety"; \
	else \
		echo "cannot write to $(PREFIX)/bin (needs permission)."; \
		echo "  run with sudo:      sudo make install-bin"; \
		echo "  or a user prefix:   PREFIX=$$HOME/.local make install-bin  (add ~/.local/bin to PATH)"; \
		exit 1; \
	fi

test:
	go test ./...

vet:
	go vet ./...

# verify: confirm the installed binary matches a fresh build (same checksum).
verify: build
	@echo "built:     $$(shasum -a256 bin/saifety | cut -d' ' -f1)"
	@echo "installed: $$(shasum -a256 $(PREFIX)/bin/saifety 2>/dev/null | cut -d' ' -f1)"
	@cmp -s bin/saifety $(PREFIX)/bin/saifety 2>/dev/null && echo "MATCH — установлен свежий" || echo "DIFFERENT — переустанови: sudo make install-bin"

# update: one command to rebuild, install globally, and verify. Needs sudo if
# PREFIX is system-owned (the default /usr/local). After it, restart Claude so
# the proxy relaunches with the new binary.
update: build _copybin
	@echo
	@echo "built:     $$(shasum -a256 bin/saifety | cut -d' ' -f1)"
	@echo "installed: $$(shasum -a256 $(PREFIX)/bin/saifety 2>/dev/null | cut -d' ' -f1)"
	@cmp -s bin/saifety $(PREFIX)/bin/saifety 2>/dev/null && echo "verify: MATCH" || echo "verify: DIFFERENT (install failed?)"
	@echo "version:   $$($(PREFIX)/bin/saifety version 2>/dev/null)"
	@echo
	@echo ">>> Перезапусти Claude полностью, чтобы прокси поднялся на новом бинарнике."
	@echo ">>> Если копились ложные блокировки — очисти состояние: make reset-state"

# reset-state: clear the proxy blocklist and tool pins (both accumulate stale
# false positives from older binaries). The new binary re-derives them.
reset-state:
	@state="$${XDG_STATE_HOME:-$$HOME/.local/state}/saifety"; 	for f in blocklist.json toolpins.json; do 		if [ -f "$$state/$$f" ]; then cp "$$state/$$f" "$$state/$$f.bak" && rm -f "$$state/$$f" && echo "сброшен $$state/$$f (бэкап .bak)"; fi; 	done; 	echo "готово; изменения применятся после перезапуска Claude"

ci-test:
	go test -race -count=1 -timeout=5m ./...
	go test -count=1 -timeout=5m -tags onnx ./...

ci-build:
	$(MAKE) build
	./bin/saifety version
	CGO_ENABLED=0 $(MAKE) build-lite
	./bin/saifety version
	bash scripts/build-release.sh
