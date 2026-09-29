SHELL := /bin/sh

GO ?= go
FLOW_BIN ?= .flow/bin/flow
GO_BUILD_FLAGS := -trimpath -buildvcs=false
GO_LDFLAGS := -s -w -buildid=
GO_DEV_ENV := GOENV=off GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
GO_OFFLINE_ENV := GOENV=off GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor

.PHONY: build test static vendor vendor-check offline-build component-static optional-component-static check check-core demo

build:
	@install -d -m 0700 "$(dir $(FLOW_BIN))"
	$(GO_DEV_ENV) CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -ldflags '$(GO_LDFLAGS)' -o "$(FLOW_BIN)" ./cmd/flow

test:
	$(GO_DEV_ENV) CGO_ENABLED=0 $(GO) test -trimpath ./...
	$(GO_DEV_ENV) CGO_ENABLED=1 $(GO) test -race -trimpath ./...

static: build
	$(GO_DEV_ENV) CGO_ENABLED=0 $(GO) vet -trimpath ./...
	$(GO_DEV_ENV) FLOW_BIN="$(abspath $(FLOW_BIN))" ./tests/static-security.sh

# dependency preparation for the unchanged offline release builder is explicit.
vendor:
	$(GO_DEV_ENV) $(GO) mod vendor

vendor-check:
	@test -f vendor/modules.txt || { printf '%s\n' 'Missing root vendor tree. Run make vendor with dependency access before an offline build.' >&2; exit 1; }
	$(GO_OFFLINE_ENV) $(GO) list -mod=vendor ./... >/dev/null

offline-build: vendor-check
	@install -d -m 0700 "$(dir $(FLOW_BIN))"
	$(GO_OFFLINE_ENV) CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -ldflags '$(GO_LDFLAGS)' -o "$(FLOW_BIN)" ./cmd/flow

# local legacy component checks are separate from the go-core publication gate.
component-static:
	./ssh/tests/static-checks.sh
	./vpn/tests/static-checks.sh
	./pbp/tests/static-checks.sh
	./serving/tests/provision-static-checks.sh
	./serving/tests/mfa-static-checks.sh
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v -s serving/tests -p 'test_toolkit_auth.py'
	./serving/tests/release-set-checks.sh
	./serving/tests/release-flow.sh

optional-component-static:
	@test -x examstation/tests/static-checks.sh && test -x examstation/tests/test-sshd-policy.sh || { printf '%s\n' 'Examstation integration is in development; its source and checks are not shipped. See docs/DEVELOPMENT.md.' >&2; exit 1; }
	./examstation/tests/static-checks.sh
	./examstation/tests/test-sshd-policy.sh

# publication gate for the shipped go core, also used by CI.
check-core: build test static

check: check-core

# Small local walkthrough; deliberately separate from the complete core gate.
demo:
	GO="$(GO)" ./scripts/portfolio-demo.sh
