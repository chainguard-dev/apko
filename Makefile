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

# Set version variables for LDFLAGS
IMAGE_TAG ?= latest
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

DIGEST ?=

PROJECT_BIN := $(shell pwd)/bin

##########
# default
##########

default: help

.PHONY: help
help: ## Display help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n	make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "	\033[36m%-22s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development:

.PHONY: generate
generate: ## Generates jsonschema for apko types.
	go generate ./...

GOLANGCI_LINT_BIN := $(PROJECT_BIN)/golangci-lint
GOLANGCI_LINT_VERSION := v2.6.1

$(GOLANGCI_LINT_BIN):
	@echo "Installing golangci-lint@$(GOLANGCI_LINT_VERSION) to $(PROJECT_BIN)…"
	@GOBIN=$(PROJECT_BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOBIN)/goimports:
	@echo "Installing goimports to $(GOBIN)…"
	@go install golang.org/x/tools/cmd/goimports@latest

.PHONY: fmt
fmt: $(GOBIN)/goimports ## Format all go files
	@$(MAKE) --no-print-directory log-$@
	@$< -l $(GOFILES)

.PHONY: checkfmt
checkfmt: SHELL := /usr/bin/env bash
checkfmt: $(GOBIN)/goimports ## Check formatting of all go files
	@$(MAKE) --no-print-directory log-$@
	@test -z "$$(gofmt -l $(GOFILES))" || { echo "Files need formatting"; exit 1; }
	@test -z "$$($< -l $(GOFILES))" || { echo "Linting issues found"; exit 1; }

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
lint: checkfmt $(GOLANGCI_LINT_BIN) ## Run linters and checks like golangci-lint
	@$(MAKE) --no-print-directory log-$@
	@$(GOLANGCI_LINT_BIN) run -n

.PHONY: test
test: ## Run go test
	go test ./... -race

.PHONY: clean
clean: ## Clean the workspace
	rm -rf apko
	rm -rf bin/
	rm -rf dist/

##@ Compile:

.PHONY: apko
apko: $(SRCS) ## Builds apko
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./

.PHONY: install
install: $(SRCS) ## Builds and moves apko into BINDIR (default /usr/bin)
	install -Dm755 apko ${DESTDIR}${BINDIR}/apko

##@ ko-build:

DOCKER_HOST ?= $(shell docker context inspect --format '{{.Endpoints.docker.Host}}')

KO_BIN := $(PROJECT_BIN)/ko
KO_VERSION := v0.18.0
KO_DOCKER_REPO ?= chainguard.dev/apko
KOCACHE := $(PROJECT_BIN)/kocache
KO_TAGS := --tags $(IMAGE_TAG) --tags $(GIT_VERSION) --tags $(GIT_HASH)

$(KO_BIN):
	@echo "Installing ko@$(KO_VERSION) to $(PROJECT_BIN)…"
	@GOBIN=$(PROJECT_BIN) go install github.com/google/ko@$(KO_VERSION)

$(KOCACHE):
	@mkdir -p $@

.PHONY: ko
ko: $(KO_BIN) $(KOCACHE) ## Build images using ko
	@$(MAKE) --no-print-directory log-$@
	@$(eval DIGEST := $(shell LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KO_DOCKER_REPO=$(KO_DOCKER_REPO) \
	KOCACHE=$(KOCACHE) \
	$< build --bare --platform=all $(KO_TAGS)))
	@echo Image Digest $(DIGEST)

.PHONY: ko-local
ko-local: $(KO_BIN) $(KOCACHE) ## Build images locally using ko
	@$(MAKE) --no-print-directory log-$@
	@DOCKER_HOST=$(DOCKER_HOST) \
	KO_DOCKER_REPO=$(KO_DOCKER_REPO) \
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	$< build --bare --local $(KO_TAGS)

.PHONY: ko-apply
ko-apply: $(KO_BIN) $(KOCACHE) ## Build the image and apply the manifests
	@$(MAKE) --no-print-directory log-$@
	@KO_DOCKER_REPO=$(KO_DOCKER_REPO) \
	KOCACHE=$(KOCACHE) \
	LDFLAGS="$(LDFLAGS)" \
	$< apply --base-import-paths \
		--recursive --filename config/

.PHONY: ko-resolve
ko-resolve: $(KO_BIN) $(KOCACHE) ## Build the image generate the Task YAML
	@$(MAKE) --no-print-directory log-$@
	@KO_DOCKER_REPO=$(KO_DOCKER_REPO) \
	KOCACHE=$(KOCACHE) \
	LDFLAGS="$(LDFLAGS)" \
	$< resolve --base-import-paths \
		--recursive --filename config/ > task.yaml

##@ Release:

.PHONY: snapshot
snapshot: ## Run Goreleaser in snapshot mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --clean --snapshot --skip=sign,publish

.PHONY: release
release: ## Run Goreleaser in release mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --clean

COSIGN_VERSION := v3.0.2

$(PROJECT_BIN)/cosign:
	@echo "Installing cosign to $(PROJECT_BIN)…"
	@GOBIN=$(PROJECT_BIN) go install github.com/sigstore/cosign/v3/cmd/cosign@$(COSIGN_VERSION)

.PHONY: sign-image
sign-image: $(PROJECT_BIN)/cosign ko ## Sign images built using ko
	@$(MAKE) --no-print-directory log-$@
	@echo "Signing $(DIGEST)…"
	@$< sign -y $(DIGEST)

##@ CI:

.PHONY: ci
ci: ## Run all CI tests
	./hack/ci-tests.sh
