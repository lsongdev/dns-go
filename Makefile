# dns-go build targets. Binaries are static (CGO_ENABLED=0) and the web panel
# is embedded, so each archive is self-contained.
#
#   make                  build for this machine into dist/dns-go
#   make test             vet + race tests
#   make release          every platform below, archives + SHA256SUMS
#   make release PLATFORMS="linux/arm64 linux/mipsle"
#   make linux/arm/v7     one platform (directory in dist/, no archive)
#
# Platform syntax: os/arch[/variant]. Variants: arm v5|v6|v7 (GOARM),
# mips/mipsle softfloat|hardfloat (GOMIPS; default softfloat, as most
# routers lack an FPU), amd64 v1..v4 (GOAMD64).
# SQLite storage is not available on MIPS (the pure-Go driver does not
# support it); those builds use the config-file storage.

BINARY    := dns-go
PKG       := ./cmd/dns-go
DIST      := dist
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO        ?= go
GOFLAGS   ?= -trimpath
LDFLAGS   ?= -s -w -X main.version=$(VERSION)
TAGS      ?=

PLATFORMS ?= \
	linux/amd64 linux/arm64 linux/arm/v7 linux/arm/v6 linux/386 \
	linux/riscv64 linux/loong64 linux/mipsle linux/mips \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64 \
	freebsd/amd64 freebsd/arm64

EXTRA_FILES := README.md config.yaml config.authoritative.yaml

.PHONY: all build test vet race smoke e2e release checksums clean $(PLATFORMS)

all: build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags '$(TAGS)' -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) $(PKG)

vet:
	$(GO) vet ./...
	$(GO) vet -tags nosqlite ./...

test: vet
	$(GO) test -race ./...

smoke:
	./scripts/smoke.sh

# Needs a throwaway server with an unauthenticated API on BASE.
BASE ?= http://127.0.0.1:8080
e2e:
	node scripts/panel-e2e.mjs $(BASE) $(DIST)/panel-e2e

# One platform: dist/dns-go-<version>-<os>-<arch>[<variant>]/
$(PLATFORMS):
	@os=$(word 1,$(subst /, ,$@)); arch=$(word 2,$(subst /, ,$@)); variant=$(word 3,$(subst /, ,$@)); \
	goarm=; gomips=; goamd64=; \
	case $$arch in \
	  arm) goarm=$${variant#v}; goarm=$${goarm:-7} ;; \
	  mips|mipsle) gomips=$${variant:-softfloat} ;; \
	  amd64) goamd64=$${variant:-v1} ;; \
	esac; \
	ext=; [ "$$os" = windows ] && ext=.exe; \
	name=$(BINARY)-$(VERSION)-$$os-$$arch$$variant; \
	echo "build $$name"; \
	rm -rf $(DIST)/$$name; mkdir -p $(DIST)/$$name; \
	GOOS=$$os GOARCH=$$arch GOARM=$$goarm GOMIPS=$$gomips GOAMD64=$$goamd64 CGO_ENABLED=0 \
	  $(GO) build $(GOFLAGS) -tags '$(TAGS)' -ldflags '$(LDFLAGS)' -o $(DIST)/$$name/$(BINARY)$$ext $(PKG); \
	cp $(EXTRA_FILES) $(DIST)/$$name/; \
	if [ "$$os" = linux ]; then cp contrib/systemd/dns-go.service $(DIST)/$$name/; fi

# Every platform, archived: .zip for Windows, .tar.gz elsewhere.
release: clean $(PLATFORMS)
	@cd $(DIST) && for dir in $(BINARY)-$(VERSION)-*/; do \
	  dir=$${dir%/}; \
	  case $$dir in \
	    *-windows-*) zip -qr $$dir.zip $$dir ;; \
	    *) tar -czf $$dir.tar.gz $$dir ;; \
	  esac; \
	  rm -rf $$dir; \
	done
	@$(MAKE) --no-print-directory checksums

checksums:
	@cd $(DIST) && { command -v sha256sum >/dev/null && sha256sum *.tar.gz *.zip || shasum -a 256 *.tar.gz *.zip; } > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

clean:
	rm -rf $(DIST)
