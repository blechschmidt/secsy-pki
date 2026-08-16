# Signing & timestamping services

*Using the HSM to sign things that are not certificates.*

The same key provider that backs the CA also backs a code/artifact signing
service, an RFC 3161 time-stamping authority, the trusted time source that
guards it, and the long-term preservation machinery that keeps old signatures
verifiable after their algorithms age out.

| Guide | Covers |
|-------|--------|
| [**Artifact / code signing**](artifact-signing.md) | HSM-backed CMS/PKCS#7 detached signatures over release artifacts: provisioning code-signing keys under the lint-gated `code-signing` profile (`secsy-ca signing-key`), `/api/sign` + `/api/sign/verify` (signer role, tenant-scoped, rate-limited, `artifact.sign` audit), `secsy-ca sign`/`verify-signature` with file & digest input, embedded RFC 3161 countersignatures with timestamp-time chain validation, key-ceremony notes for signing keys, and `openssl cms`/`openssl ts` interop |
| [**Time-stamping authority (RFC 3161)**](timestamping.md) | HSM-backed trusted time-stamp tokens: provisioning the TSA key/cert (`secsy-ca tsa-key`), the `/tsa` endpoint, policy/accuracy/ordering config, nonce & hash validation, audit + metrics, and `openssl ts -verify` interop |
| [**Trusted external time source (NTS / Roughtime)**](trusted-time.md) | Fail-closed drift detection guarding the TSA and audit anchoring against a compromised/drifted host clock: the `time.source` block (`system` default, authenticated NTP/NTS per RFC 8915, or Roughtime), cross-checking the host clock before signing and refusing (`timeNotAvailable` / no anchor) when the offset exceeds `max_drift`, the reachability policy (`fail_closed`/`fail_open`) + `min_sources` quorum + cached `refresh_interval`, `secsy_time_drift_seconds`/`secsy_time_check_failures_total` metrics, the `SecsyPKITrustedTimeCheckFailing` alert, the `time.trusted` doctor check, and the `time.check` audit event |
| [**Long-term preservation — Evidence Records (RFC 4998)**](evidence-records.md) | Renewable archive-timestamp Evidence Records over the audit chain and signed artifacts so proofs survive hash/signature-algorithm obsolescence: a Merkle/data-group hash tree, HSM-backed `ArchiveTimeStamp`s from the internal TSA, time-stamp renewal (before cert expiry) + hash-tree renewal (on FIPS-driven algorithm deprecation), a leader-elected `ers.schedule` job with a durable cursor, `secsy-ca ers generate/renew/verify/export`, `POST /api/ers/verify`, `ers.*` audit/metrics, and the `ers.freshness` doctor check |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
