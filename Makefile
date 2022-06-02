# Some nice defines for the "make install" target
PREFIX ?= /usr
BINDIR ?= ${PREFIX}/bin

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GOFILES ?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")

RUNTIME_IMAGE ?= gcr.io/distroless/static
# Set version variables for LDFLAGS
GIT_TAG ?= dirty-tag
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

SRCS = $(shell find . -iname "*.go")

PKG ?= sigs.k8s.io/release-utils/version
LDFLAGS=-buildid= -X $(PKG).gitVersion=$(GIT_VERSION) \
        -X $(PKG).gitCommit=$(GIT_HASH) \
        -X $(PKG).gitTreeState=$(GIT_TREESTATE) \
        -X $(PKG).buildDate=$(BUILD_DATE)

KO_DOCKER_REPO ?= ghcr.io/chainguard-dev/apko
DIGEST ?=


KOCACHE_PATH=/tmp/ko

define create_kocache_path
  mkdir -p $(KOCACHE_PATH)
endef

##########
# default
##########

default: help

##########
# ko build
##########

.PHONY: ko
ko: ## Build images using ko
	$(create_kocache_path)
	$(eval DIGEST := $(shell LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		chainguard.dev/apko))
	@echo Image Digest $(DIGEST)

.PHONY: ko-local
ko-local:  ## Build images locally using ko
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		chainguard.dev/apko

.PHONY: ko-apply
ko-apply:  ## Build the image and apply the manifests
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" \
	KOCACHE=$(KOCACHE_PATH) ko apply --base-import-paths \
		--recursive --filename config/

.PHONY: ko-apply
ko-resolve:  ## Build the image generate the Task YAML
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" \
	KOCACHE=$(KOCACHE_PATH) ko resolve --base-import-paths \
		--recursive --filename config/ > task.yaml

##########
# Build
##########

.PHONY: apko
apko: $(SRCS) ## Builds apko
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./

.PHONY: install
install: $(SRCS) apko ## Builds and moves apko into BINDIR (default /usr/bin)
	install -Dm755 apko ${DESTDIR}${BINDIR}/apko

#####################
# lint / test section
#####################

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

.PHONY: golangci-lint
golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.44.2 ;\

.PHONY: fmt
fmt: ## Format all go files
	@ $(MAKE) --no-print-directory log-$@
	goimports -w $(GOFILES)

.PHONY: checkfmt
checkfmt: SHELL := /usr/bin/env bash
checkfmt: ## Check formatting of all go files
	@ $(MAKE) --no-print-directory log-$@
	$(shell test -z "$(shell gofmt -l $(GOFILES) | tee /dev/stderr)")
	$(shell test -z "$(shell goimports -l $(GOFILES) | tee /dev/stderr)")

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

.PHONY: lint
lint: checkfmt golangci-lint ## Run linters and checks like golangci-lint
	$(GOLANGCI_LINT_BIN) run -n

.PHONY: test
test: ## Run go test
	go test ./...

.PHONY: clean
clean: ## Clean the workspace
	rm -rf apko
	rm -rf bin/
	rm -rf dist/

#######################
# Release / goreleaser
#######################

.PHONY: snapshot
snapshot: ## Run Goreleaser in snapshot mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --rm-dist --snapshot --skip-sign --skip-publish

.PHONY: release
release: ## Run Goreleaser in release mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --rm-dist


#######################
# Sign images
#######################
.PHONY: sign-image
sign-image: ko ## Sign images built using ko
	cosign sign $(DIGEST)

##################
# help
##################

help: ## Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort
