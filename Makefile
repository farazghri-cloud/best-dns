BIN     := bin/bestdns
VERSION := $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
LDFLAGS := -s -w -X main.version=$(if $(VERSION),$(VERSION),dev)

.PHONY: build test vet lint clean release run

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/bestdns
	@echo "built $(BIN)"

test:
	go test ./...

vet:
	go vet ./...

run: build
	./$(BIN) server -data ./data/state.json -dns :5353 -panel :8080 -proxy-ports 8443

clean:
	rm -rf bin dist

release:
	@mkdir -p dist
	@set -e; \
	for target in amd64 arm64 armv7; do \
		case $$target in \
			amd64) goarch=amd64; goarm="" ;; \
			arm64) goarch=arm64; goarm="" ;; \
			armv7) goarch=arm;   goarm=7  ;; \
		esac; \
		echo "-> linux/$$target"; \
		GOOS=linux GOARCH=$$goarch GOARM=$$goarm CGO_ENABLED=0 \
			go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bestdns ./cmd/bestdns; \
		tar -czf dist/best-dns-linux-$$target.tar.gz -C dist bestdns; \
		( cd dist && sha256sum best-dns-linux-$$target.tar.gz > best-dns-linux-$$target.tar.gz.sha256 ); \
		rm -f dist/bestdns; \
	done; \
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" \
		-o dist/best-dns-windows-amd64.exe ./cmd/bestdns
	@ls -la dist
