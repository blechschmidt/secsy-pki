# ---------------------------------------------------------------------------
# secsy-pki — supply-chain / release Makefile (Task 48)
#
# Build, SBOM, sign, provenance and verification targets for the container
# image (Task 19) and the Go binaries. Everything here is idempotent and safe
# to re-run: SBOMs land in dist/ and are regenerated, signing/attestation are
# additive registry operations, and verification is read-only.
#
# The heavy tools (cosign, syft) are looked up on PATH; the Go-native tools
# (cyclonedx-gomod, govulncheck) are pinned and run via `go run` so no global
# install is required. `make tools` installs everything for local use.
#
# Quick start:
#   make govulncheck                 # gating vulnerability scan of the Go deps
#   make sbom                        # CycloneDX SBOMs -> dist/
#   make image IMAGE=... VERSION=... # build the container image
#   make sign  IMAGE=... VERSION=... # cosign sign + SBOM attest (keyless OIDC)
#   make verify IMAGE=... VERSION=...# cosign verify + verify-attestation
# ---------------------------------------------------------------------------

SHELL := /bin/bash

# --- Image coordinates -----------------------------------------------------
# Override on the command line or via the environment, e.g.
#   make sign IMAGE=ghcr.io/acme/secsy-pki VERSION=1.2.3
REGISTRY   ?= ghcr.io
OWNER      ?= blechschmidt
IMAGE      ?= $(REGISTRY)/$(OWNER)/secsy-pki

# VERSION defaults to `git describe` (tag-aware), falling back to a short SHA.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE_REF  ?= $(IMAGE):$(VERSION)

# When an image has been pushed we prefer to operate on the immutable digest.
# Populate IMAGE_DIGEST (sha256:...) to sign/verify a specific manifest;
# otherwise the by-tag reference is used and resolved at call time.
IMAGE_DIGEST ?=
ifeq ($(strip $(IMAGE_DIGEST)),)
COSIGN_TARGET ?= $(IMAGE_REF)
else
COSIGN_TARGET ?= $(IMAGE)@$(IMAGE_DIGEST)
endif

# --- Output ----------------------------------------------------------------
DIST            := dist
SBOM_GOMOD      := $(DIST)/sbom-gomod.cdx.json
SBOM_IMAGE      := $(DIST)/sbom-image.cdx.json
PROVENANCE      := $(DIST)/provenance.slsa.json

# --- Pinned Go-native tools (run via `go run`, no global install needed) ----
CYCLONEDX_GOMOD_VERSION ?= v1.9.0
GOVULNCHECK_VERSION     ?= latest
CYCLONEDX_GOMOD := go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)
GOVULNCHECK     := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

# --- External binaries (looked up on PATH; `make tools` installs them) ------
COSIGN ?= cosign
SYFT   ?= syft

# --- cosign signing configuration ------------------------------------------
# Keyless (Fulcio/Rekor OIDC) is the default and needs no secrets in a GitHub
# Actions runner with `id-token: write`. For key-based signing set COSIGN_KEY
# (a cosign.key path or a KMS/k8s/env reference) and COSIGN_PASSWORD; the
# targets switch to `--key` automatically.
COSIGN_KEY      ?=

# Keyless verification identity. Defaults accept any GitHub Actions workflow in
# this repo; tighten for production consumers (see docs/supply-chain.md). These
# must be defined before COSIGN_VERIFY_FLAGS references them below.
COSIGN_CERT_IDENTITY_REGEXP     ?= ^https://github.com/$(OWNER)/secsy-pki/
COSIGN_CERT_OIDC_ISSUER_REGEXP  ?= ^https://token.actions.githubusercontent.com$$

# `=` (recursive) so command-line overrides of the identity/key vars are honored
# at use time regardless of definition order.
ifeq ($(strip $(COSIGN_KEY)),)
COSIGN_SIGN_FLAGS    = --yes
COSIGN_VERIFY_FLAGS  = --certificate-identity-regexp '$(COSIGN_CERT_IDENTITY_REGEXP)' --certificate-oidc-issuer-regexp '$(COSIGN_CERT_OIDC_ISSUER_REGEXP)'
else
COSIGN_SIGN_FLAGS    = --key $(COSIGN_KEY) --yes
COSIGN_VERIFY_FLAGS  = --key $(COSIGN_KEY)
endif

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n",$$1,$$2}'
	@echo
	@echo "  IMAGE=$(IMAGE)  VERSION=$(VERSION)"

$(DIST):
	@mkdir -p $(DIST)

# ---------------------------------------------------------------------------
# Vulnerability scanning (gating)
# ---------------------------------------------------------------------------
.PHONY: govulncheck
govulncheck: ## Gating vulnerability scan of the Go dependency tree
	@echo "==> govulncheck (source mode, -tags sqlite)"
	cd server && GOTOOLCHAIN=auto $(GOVULNCHECK) -tags sqlite ./...

# ---------------------------------------------------------------------------
# gRPC / protobuf code generation (Task 56)
# ---------------------------------------------------------------------------
.PHONY: proto
proto: ## Regenerate gRPC/protobuf Go code from proto/pki/v1/pki.proto
	@echo "==> generating gRPC/protobuf Go code"
	scripts/gen-proto.sh

# ---------------------------------------------------------------------------
# SBOM generation (CycloneDX)
# ---------------------------------------------------------------------------
.PHONY: sbom
sbom: sbom-gomod sbom-image ## Generate all SBOMs into dist/

.PHONY: sbom-gomod
sbom-gomod: | $(DIST) ## CycloneDX SBOM of the Go modules
	@echo "==> Go-module SBOM -> $(SBOM_GOMOD)"
	cd server && GOTOOLCHAIN=auto $(CYCLONEDX_GOMOD) mod -json -licenses \
	  -output "$(CURDIR)/$(SBOM_GOMOD)" .
	@echo "    components: $$(grep -o '\"bom-ref\"' $(SBOM_GOMOD) | wc -l)"

.PHONY: sbom-image
sbom-image: | $(DIST) ## CycloneDX SBOM of the container image (needs syft + built image)
	@if ! command -v $(SYFT) >/dev/null 2>&1; then \
	  echo "!! syft not found on PATH; run 'make tools' or install syft. Skipping image SBOM." >&2; \
	  exit 0; \
	fi
	@echo "==> Image SBOM -> $(SBOM_IMAGE)  ($(COSIGN_TARGET))"
	$(SYFT) scan "$(COSIGN_TARGET)" -o cyclonedx-json="$(SBOM_IMAGE)"

# ---------------------------------------------------------------------------
# Image build
# ---------------------------------------------------------------------------
.PHONY: image
image: ## Build the container image (docker buildx)
	@echo "==> docker build $(IMAGE_REF)"
	docker build -t $(IMAGE_REF) --build-arg VERSION=$(VERSION) .

# ---------------------------------------------------------------------------
# Signing + attestation (cosign)
# ---------------------------------------------------------------------------
.PHONY: sign
sign: sign-image attest-sbom ## Sign the image and attach the SBOM attestation

.PHONY: sign-image
sign-image: _need-cosign ## cosign sign the image
	@echo "==> cosign sign $(COSIGN_TARGET)"
	$(COSIGN) sign $(COSIGN_SIGN_FLAGS) $(COSIGN_TARGET)

.PHONY: attest-sbom
attest-sbom: _need-cosign sbom-image ## Attach the CycloneDX image SBOM as a cosign attestation
	@if [ ! -f "$(SBOM_IMAGE)" ]; then \
	  echo "!! $(SBOM_IMAGE) missing (syft unavailable?); cannot attest SBOM." >&2; exit 1; \
	fi
	@echo "==> cosign attest (cyclonedx) $(COSIGN_TARGET)"
	$(COSIGN) attest $(COSIGN_SIGN_FLAGS) --type cyclonedx --predicate "$(SBOM_IMAGE)" $(COSIGN_TARGET)

.PHONY: attest-provenance
attest-provenance: _need-cosign ## Attach a SLSA provenance attestation from $(PROVENANCE)
	@if [ ! -f "$(PROVENANCE)" ]; then \
	  echo "!! $(PROVENANCE) missing. In CI this is produced by the slsa-github-generator job." >&2; exit 1; \
	fi
	@echo "==> cosign attest (slsaprovenance) $(COSIGN_TARGET)"
	$(COSIGN) attest $(COSIGN_SIGN_FLAGS) --type slsaprovenance --predicate "$(PROVENANCE)" $(COSIGN_TARGET)

# ---------------------------------------------------------------------------
# Verification (read-only; the same commands consumers run)
# ---------------------------------------------------------------------------
.PHONY: verify
verify: verify-image verify-sbom ## Verify signature + SBOM attestation

.PHONY: verify-image
verify-image: _need-cosign ## cosign verify the image signature
	@echo "==> cosign verify $(COSIGN_TARGET)"
	$(COSIGN) verify $(COSIGN_VERIFY_FLAGS) $(COSIGN_TARGET) >/dev/null
	@echo "    signature OK"

.PHONY: verify-sbom
verify-sbom: _need-cosign ## cosign verify-attestation for the SBOM
	@echo "==> cosign verify-attestation (cyclonedx) $(COSIGN_TARGET)"
	$(COSIGN) verify-attestation $(COSIGN_VERIFY_FLAGS) --type cyclonedx $(COSIGN_TARGET) >/dev/null
	@echo "    SBOM attestation OK"

.PHONY: verify-provenance
verify-provenance: _need-cosign ## cosign verify-attestation for the SLSA provenance
	@echo "==> cosign verify-attestation (slsaprovenance) $(COSIGN_TARGET)"
	$(COSIGN) verify-attestation $(COSIGN_VERIFY_FLAGS) --type slsaprovenance $(COSIGN_TARGET) >/dev/null
	@echo "    provenance attestation OK"

# ---------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------
.PHONY: tools
tools: ## Install cosign + syft locally (Go-native tools run via `go run`)
	go install github.com/sigstore/cosign/v2/cmd/cosign@latest
	go install github.com/anchore/syft/cmd/syft@latest
	@echo "cosign + syft installed to $$(go env GOPATH)/bin"

.PHONY: _need-cosign
_need-cosign:
	@command -v $(COSIGN) >/dev/null 2>&1 || { \
	  echo "!! cosign not found on PATH. Run 'make tools' or see https://docs.sigstore.dev/cosign/installation" >&2; \
	  exit 1; }

.PHONY: clean
clean: ## Remove generated SBOM/provenance artifacts
	rm -rf $(DIST)
