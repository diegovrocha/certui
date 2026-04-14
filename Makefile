PREFIX ?= /usr/local
BINARY = certui

build:
	go build -o $(BINARY) ./cmd/certui

install: build
	@mkdir -p $(PREFIX)/bin
	@cp $(BINARY) $(PREFIX)/bin/$(BINARY)
	@chmod +x $(PREFIX)/bin/$(BINARY)
	@echo "✔ certui instalado em $(PREFIX)/bin/$(BINARY)"

uninstall:
	@rm -f $(PREFIX)/bin/$(BINARY)
	@echo "✔ certui removido"

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)

test:
	go test ./... -count=1

.PHONY: build install uninstall run clean test
