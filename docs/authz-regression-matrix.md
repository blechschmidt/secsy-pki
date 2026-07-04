# Authorization & tenant-isolation regression matrix

secsy-pki exposes ~116 REST routes plus a gRPC `PKIService`. Every one is an
access-control surface. To stop a new route from silently shipping without an
RBAC/tenant decision — the classic OWASP *broken/ missing function-level
authorization* and *broken object-level authorization* failure — the codebase
carries a **table-driven authorization regression matrix** that is checked in
CI on every change.

- REST: `server/internal/handlers/authz_matrix_test.go`
- gRPC: `server/internal/grpcapi/authz_matrix_test.go`

Both are `//go:build sqlite` (they run under the same tag as the rest of the
handler suite; no HSM required — a software key provider backs them).

## What it guarantees

For **every** route/RPC the matrix drives the real router + auth middleware with
four principals and asserts the four contract points:

| # | Principal | Expectation |
|---|-----------|-------------|
| (a) | unauthenticated | `401` (REST) / `Unauthenticated` (gRPC) on protected routes |
| (b) | authenticated but lacking the capability | `403`/`404`, **never** `2xx` |
| (c) | a tenant-scoped principal touching **another** tenant's resource | `403`/`404`, no cross-tenant data in the body |
| (d) | a correctly-capable principal | **not** denied (not `401`/`403`) |

Principals are minted through the *real* middleware via a mock OIDC verifier plus
the production role resolvers, so the test exercises the genuine authentication →
authorization path, not a shortcut. `admin` is allow-all, so a tenant-`a` admin is
the universal *capable* witness for tenant-scoped routes, and a role-less
authenticated principal (`"none"`) is the universal *denied* witness.

## The forcing function

`TestAuthzMatrixCoversRegisteredRoutes` parses `RegisterRoutes` in
`handlers.go` with `go/ast` and **fails the build if any registered
`mux.Handle`/`mux.HandleFunc` route has no matrix entry** (and if any matrix
entry is stale). `TestGRPCAuthzMatrixCoversMethods` does the same for every
`PKIService` method via `pkiv1.PKIService_ServiceDesc.Methods`.

**Consequence:** you cannot add a route without declaring its access-control
intent. A new `mux.Handle(...)` turns the suite red until you add a row.

## Adding a route — what to do

Add exactly one row to `authzMatrix()` (REST) or `grpcAuthzMatrix()` (gRPC),
using the constructor that matches the handler's gate:

| Constructor | Gate the handler uses | Capable witness |
|-------------|-----------------------|-----------------|
| `caRd` / `caRdBody` | `authorizeCARead` (read + tenant member) | tenant-`a` auditor; cross-tenant → `404` |
| `rdG` | `canRead` (any assigned role) | tenant-`a` auditor |
| `platRd` | `a.can(audit:read)` (platform role) | platform auditor (a *tenant* auditor is denied) |
| `iss` | `canIssueOn` (per-CA issue) | tenant-`a` admin; cross-tenant → `403` |
| `caMg` / `caMgBody` | `canInTenant(ca:manage)` | tenant-`a` admin |
| `platAdm` | `isPlatformAdmin` / root-only | root |
| `memRd` | tenant-member read (non-member → `404`) | tenant-`a` admin |
| `tokMg` / `tokMgScoped` | `canInTenant(token:manage)` | tenant-`a` admin |
| `secretR` | `canInTenant(secret:*)`, tenant from `X-Secsy-Tenant` | tenant-`a` admin |
| `signR` | `canInTenant(artifact:sign)` | tenant-`a` admin |
| `aprRd` / `aprGet` / `aprDec` | approval `read`/`approve` | tenant-`a` auditor / admin |
| `rbacMg` | `a.can(rbac:manage)` (platform) | platform admin |
| `cfgCA` | root or per-CA `CONFIGURE_CA` | root |
| `hsmMg` | `a.can(hsm:manage)` (platform) | root |
| `platIss` | `a.can(cert:issue)` (platform) | root |

Two explicit allowlists exist for the endpoints that are **intentionally** open:

- `pub(...)` — unauthenticated by design: CRL, delta/shard CRL, OCSP, the AIA
  chain / cross-sign chains, SSH CA public key + KRL, the SVID trust bundle,
  health, and the OpenAPI/Redoc docs. (ACME, EST, SCEP, CMP, TSA, `/healthz`,
  `/readyz` and the ACME directory are mounted on a separate router and are the
  public protocol surface; they are not registered in `handlers.go`.)
- `authed(...)` — requires authentication but no capability, by design:
  `/api/me`, `/api/profiles`, `/api/secret/info`, `/api/hsm/info`,
  `/api/keys/{id}/my-restrictions` (each returns the caller's own view or
  non-sensitive service metadata).

If a genuinely new capability class appears, add a constructor next to the
others rather than hand-rolling an `rc{...}` literal, so the table stays
declarative.

## What the matrix caught

Building the matrix uncovered one real cross-tenant gap: `CRLStatus`
(`GET /api/ca/{id}/crl/status`) gated only on `canRead` — any role-holder in
*any* tenant — and skipped the tenant-membership check that every other
CA-scoped read performs. A tenant-B auditor could read tenant-A's CRL freshness
and revocation counts. Fixed by routing it through the shared `authorizeCARead`
guard (which enforces membership and answers `404` for non-members), closing the
leak and bringing it in line with the rest of the CA inventory.

## Keeping it green

- Run locally: `go test -tags sqlite ./internal/handlers/ ./internal/grpcapi/`.
- If `TestAuthzMatrixCoversRegisteredRoutes` fails with *"route X has no
  authorization-matrix entry"*, add the row — do **not** delete the assertion.
- If a `(b)`/`(c)` assertion fails with a `2xx`, you have found a missing
  authorization or tenant check in the handler. Fix the handler, not the test.
