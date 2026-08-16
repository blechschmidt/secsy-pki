# Supply-chain security: SBOM, signed images & SLSA provenance

secsy-pki hardens the release pipeline for the container image and binaries
(built in [Kubernetes deployment](../deployment/kubernetes.md)) so that consumers can prove,
before they run it, **what** they are running and **where it came from**:

- a **Software Bill of Materials (SBOM)** — CycloneDX — for both the Go modules
  and the container image, so every dependency is enumerable and scannable;
- a **cosign signature** on the image (keyless / Sigstore OIDC by default, or a
  configurable key), so tampered or unofficial images are rejected;
- a **cosign SBOM attestation**, binding the SBOM to the exact image digest;
- a **SLSA build-provenance attestation** (SLSA Build L3) attached to the image,
  produced by the official
  [`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator),
  so the build is traceable to the source commit and workflow;
- a **`govulncheck` gate** in CI that fails the build on any *reachable*
  vulnerability in the Go dependency tree.

Everything is driven from the repo [`Makefile`](../../Makefile) and two GitHub
Actions workflows, so what CI does and what you run locally cannot drift.

- Build/sign/verify targets: [`Makefile`](../../Makefile)
- Release pipeline (tags): [`.github/workflows/release.yaml`](../../.github/workflows/release.yaml)
- Continuous gate + SBOM: [`.github/workflows/supply-chain.yaml`](../../.github/workflows/supply-chain.yaml)

---

## 1. What is produced on a release

Pushing a `v*` tag (e.g. `v1.2.3`) runs `release.yaml`, which publishes to GHCR:

| Artifact | Type | How it is attached |
|----------|------|--------------------|
| `ghcr.io/<owner>/secsy-pki:<tag>` (+ `:latest`) | OCI image | pushed by digest |
| Image signature | cosign `.sig` | `cosign sign` (keyless or key) |
| Image SBOM | CycloneDX attestation | `cosign attest --type cyclonedx` |
| Go-module SBOM | CycloneDX file | GitHub Release asset + workflow artifact |
| SLSA provenance | in-toto SLSA v0.2 attestation | `slsa-github-generator`, attached to the image |

The pipeline **verifies all of this itself** (the `verify` job) before the run
is considered green — the same commands a consumer runs, below.

---

## 2. Consumer verification (the important part)

Install [cosign](https://docs.sigstore.dev/cosign/installation) and, for
provenance, [slsa-verifier](https://github.com/slsa-framework/slsa-verifier).
Replace `<owner>` and the tag as appropriate. **Always verify by digest** in
automation — resolve the tag to a digest first:

```bash
IMAGE=ghcr.io/<owner>/secsy-pki
TAG=v1.2.3
DIGEST=$(cosign triangulate --type digest "$IMAGE:$TAG" 2>/dev/null \
         || crane digest "$IMAGE:$TAG")
REF="$IMAGE@$DIGEST"
```

### 2a. Verify the signature (keyless / Sigstore)

Keyless signatures are bound to the GitHub Actions workflow identity that
produced them, so pin **both** the identity and the OIDC issuer — this is what
stops an attacker's signature from a different repo being accepted:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/<owner>/secsy-pki/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$REF"
```

### 2b. Verify the SBOM attestation and read the SBOM

```bash
# Verify the attestation signature + identity, then extract the CycloneDX doc:
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/<owner>/secsy-pki/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$REF" \
  | jq -r '.payload | @base64d | fromjson | .predicate' > sbom.cdx.json

# Now scan it with any CycloneDX-aware tool, e.g. grype:
grype sbom:sbom.cdx.json
```

### 2c. Verify the SLSA build provenance

The provenance is signed by the SLSA generator's own workflow identity; use
`slsa-verifier`, which knows how to check it and pins the source repo:

```bash
slsa-verifier verify-image "$REF" \
  --source-uri "github.com/<owner>/secsy-pki" \
  --source-tag "$TAG" \
  --print-provenance | jq .
```

You can also read the raw provenance attestation with cosign (identity is the
generator's reusable workflow, not this repo):

```bash
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "^https://github.com/slsa-framework/slsa-github-generator/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$REF" | jq -r '.payload | @base64d | fromjson | .predicate'
```

### 2d. Enforce it in the cluster

Verification is only worth something if unsigned images are actually rejected.
Enforce the policy at admission with
[sigstore-policy-controller](https://docs.sigstore.dev/policy-controller/overview/)
or [Kyverno](https://kyverno.io/policies/?policytypes=verifyImages). Minimal
Kyverno example (keyless, pinned identity):

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-secsy-pki-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences: ["ghcr.io/<owner>/secsy-pki*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/<owner>/secsy-pki/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

---

## 3. Producing the artifacts locally (`make`)

The Makefile exposes the same steps CI uses. It needs `docker`, `cosign` and
`syft` on `PATH` (`make tools` installs cosign + syft); the Go-native tools
(`cyclonedx-gomod`, `govulncheck`) are pinned and run via `go run`.

```bash
make help                              # list targets + current IMAGE/VERSION

make govulncheck                       # gating vulnerability scan of the Go deps
make sbom      IMAGE=… VERSION=…       # dist/sbom-gomod.cdx.json + sbom-image.cdx.json
make image     IMAGE=… VERSION=…       # docker build
make sign      IMAGE=… VERSION=… \     # cosign sign + SBOM attest
               IMAGE_DIGEST=sha256:…
make verify    IMAGE=… VERSION=… \     # cosign verify + verify-attestation
               IMAGE_DIGEST=sha256:…
```

**Keyless vs. key-based signing.** By default the targets sign keyless
(Fulcio/Rekor OIDC), which is what you want in GitHub Actions. To sign with a
configurable key set `COSIGN_KEY` (and `COSIGN_PASSWORD`):

```bash
cosign generate-key-pair                       # -> cosign.key / cosign.pub
make sign   IMAGE=$IMAGE VERSION=$TAG IMAGE_DIGEST=$DIGEST \
            COSIGN_KEY=cosign.key
make verify IMAGE=$IMAGE VERSION=$TAG IMAGE_DIGEST=$DIGEST \
            COSIGN_VERIFY_FLAGS="--key cosign.pub"
```

`COSIGN_KEY` accepts anything cosign does, including KMS references
(`awskms://…`, `azurekms://…`, `hashivault://…`) and `k8s://…` secrets — so the
signing key itself can live in the same HSM/KMS backend used for CA keys
(see [Cloud KMS backend](../hsm/cloud-kms.md)).

---

## 4. The `govulncheck` gate

`make govulncheck` runs `govulncheck` in source/call-graph mode over the whole
server module (`-tags sqlite`). Unlike a naïve dependency diff it only fails on
vulnerabilities that are actually **reachable** from the code, keeping the gate
low-noise. It runs:

- on **every push/PR** to `enterprise` (`supply-chain.yaml`), and
- as a **pre-publish gate** on every release (`release.yaml`) — no signed image
  is produced if a reachable vulnerability is present.

Because standard-library vulnerabilities are reported against the Go toolchain
version, the toolchain is pinned to a **patched** release via the `toolchain`
directive in [`server/go.mod`](../../server/go.mod). When `govulncheck` flags a new
stdlib CVE, bump that directive to the fixed patch release; for module CVEs,
`go get` the fixed dependency version.

### The optional `zlint` backend

The industry-standard `github.com/zmap/zlint` pre-issuance lint backend (see
[certlint.md](../issuance/certlint.md)) is compiled in **only under the `zlint` build tag**.
Its modules (`zmap/zlint`, `zmap/zcrypto`, and two transitive deps) appear in
`go.mod` — `go mod tidy` records any import reachable under *any* build tag — but
they are **not linked into, or reachable from, the default/FIPS/supply-chain
builds**. Consequently the default `make govulncheck` (`-tags sqlite`) neither
analyzes nor is affected by them. To scan the zlint dependency tree, run the
reachability check *with* the tag:

```bash
make govulncheck-zlint          # cd server && govulncheck -tags 'sqlite zlint' ./...
```

Pipelines that ship a `-tags zlint` build should add this scan. The module SBOM
(`cyclonedx-gomod mod`) lists the zmap modules because they are in the module
graph; a per-binary SBOM of a default build does not.

---

## 5. How it fits together in CI

```
tag v* ──▶ release.yaml
             ├─ govulncheck (gate; nothing published on failure)
             ├─ build-sign:  build+push image ─▶ make sbom ─▶ make sign (cosign)
             │                                              └─ SBOMs ─▶ Release assets
             ├─ provenance:  slsa-github-generator ─▶ SLSA attestation on the image
             └─ verify:      cosign verify + verify-attestation + slsa-verifier

push/PR ──▶ supply-chain.yaml
             ├─ govulncheck (gate)
             └─ sbom (Go-module CycloneDX SBOM artifact)
```

See the [operator runbook](../operations/runbook.md) for the incident procedure when
verification fails in the field, and [Kubernetes deployment](../deployment/kubernetes.md) for
where the image is consumed.
