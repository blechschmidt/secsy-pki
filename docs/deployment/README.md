# Deployment & scaling

*Getting it running, and running more than one of it.*

How to package, persist and scale a deployment: the container image and Helm
chart, the two persistence engines, what changes when you run more than one
replica, and how the server obtains its own serving certificate.

| Guide | Covers |
|-------|--------|
| [**Kubernetes deployment**](kubernetes.md) | Multi-stage container image, Helm chart (HSM/PKCS#11 module mount, PIN via Secret, TLS, RBAC/policy config, `/healthz`+`/readyz` probes), cert-manager ACME issuer for HSM-backed workload certs, and a kind/SoftHSM smoke test |
| [**Persistence backends (SQLite & PostgreSQL)**](persistence.md) | The `Store` abstraction and its two engines; selecting a backend and pooling; the invariants preserved across both (audit-chain tamper-evidence, serial/CRL monotonicity); `secsy-ca db migrate` to lift a file store into PostgreSQL; and running multiple replicas for HA |
| [**Multi-replica coordination & HA**](high-availability.md) | Running `replicas > 1` safely: PostgreSQL advisory-lock leader election with lease renewal gating every singleton background job (expiry monitor/auto-renewal, CA rotation, OCSP pre-signing, CRL publishing, audit anchoring, SIEM export, discovery), idempotent leadership handover, `secsy_leader_*` metrics + `/readyz` leadership detail, and the Helm `replicaCount > 1` preconditions |
| [**Self-managed serving-TLS certificate**](serving-cert.md) | Dogfooding the HTTPS listener certificate from an internal CA instead of a static `tls_cert`/`tls_key` pair (`server.tls.self_issue`): the serving key generated in and used through the key provider (never on disk; non-extractable on a PKCS#11 HSM), hitless background auto-rotation through the shared `GetCertificate` Holder (also the OCSP-staple hook), the fraction-based renewal schedule, the `serving-tls` marker that excludes it from the monitor/inventory, `secsy_serving_cert_*` metrics, and the `doctor serving.self_issued` check |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
