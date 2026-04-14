PREFIX ?= /usr/local
BINARY = certui
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/diegovrocha/certui/internal/ui.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/certui

install: build
	@mkdir -p $(PREFIX)/bin
	@cp $(BINARY) $(PREFIX)/bin/$(BINARY)
	@chmod +x $(PREFIX)/bin/$(BINARY)
	@echo "✔ certui installed at $(PREFIX)/bin/$(BINARY)"

uninstall:
	@rm -f $(PREFIX)/bin/$(BINARY)
	@echo "✔ certui removed"

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)

test:
	go test ./... -count=1

vet:
	go vet ./...

check: vet test

# ─── Release targets ────────────────────────────────────
# Runs scripts/bump.sh to tag a new version and push to GitHub.
# GitHub Actions + GoReleaser then publish binaries automatically.
release-patch:
	@./scripts/bump.sh patch

release-minor:
	@./scripts/bump.sh minor

release-major:
	@./scripts/bump.sh major

# Usage: make release VERSION=1.5.0
release:
	@[ -n "$(VERSION)" ] || { echo "Usage: make release VERSION=X.Y.Z"; exit 1; }
	@./scripts/bump.sh $(VERSION)

.PHONY: build install uninstall run clean test vet check \
	release release-patch release-minor release-major
