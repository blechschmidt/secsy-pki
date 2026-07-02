# Persistence backends (SQLite & PostgreSQL)

secsy-pki keeps all of its shared state — the certificate-authority definitions,
the issued-certificate inventory, the revocation store and CRL/serial counters,
ACME account/order/authorization/challenge state, the tamper-evident audit
`event_log`, RBAC, and secret-operation audit records — behind a single storage
abstraction, the `database.Store` interface. Two engines implement it:

| Backend | Driver | Use case |
|---------|--------|----------|
| **SQLite** (embedded, file-backed) | `sqlite` | Default. A single self-contained file; ideal for a single node, dev, and CI. Pinned to one connection with WAL journaling. |
| **PostgreSQL** | `postgres` | Shared database for **multi-replica high availability**. Every replica runs a bounded connection pool against the same PostgreSQL cluster. |

Both engines are driven by the same Go code (`server/internal/database`); the
driver is chosen at startup. Queries are written portably — placeholders are
rebound (`?` → `$N`) and DDL is dialect-aware (`BLOB`↔`BYTEA`,
`AUTOINCREMENT`↔`SERIAL`, `INTEGER`↔`BOOLEAN`) — so behavior is identical across
backends. The schema is created/upgraded automatically on startup (idempotent
`CREATE TABLE IF NOT EXISTS` plus additive `ALTER TABLE` migrations).

## Selecting a backend

In `config.yaml`:

```yaml
database:
  driver: "sqlite"            # or "postgres"
  dsn: "secsy-pki.db"         # SQLite file path, or a PostgreSQL DSN
  # Connection-pool tuning — PostgreSQL only; ignored for SQLite.
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_lifetime_seconds: 1800
  conn_max_idle_time_seconds: 300
```

A PostgreSQL DSN looks like:

```
postgres://secsy:secret@db.internal:5432/secsy_pki?sslmode=require
```

Because the DSN carries credentials, it can also be supplied from the
environment (a Kubernetes Secret, Vault, etc.) and will override the file:

| Variable | Overrides |
|----------|-----------|
| `SECSY_DATABASE_DRIVER` | `database.driver` |
| `SECSY_DATABASE_DSN` | `database.dsn` |
| `SECSY_DATABASE_MAX_OPEN_CONNS` | `database.max_open_conns` |
| `SECSY_DATABASE_MAX_IDLE_CONNS` | `database.max_idle_conns` |

### Connection pooling

The pool applies to PostgreSQL only (SQLite is single-connection by
construction). Defaults are conservative — 10 open / 5 idle connections, a
30-minute connection lifetime, and a 5-minute idle timeout — and are sized so a
fleet of replicas does not exhaust the server's `max_connections`. Size
`max_open_conns` roughly as *(PostgreSQL `max_connections` − headroom) ÷ replica
count*. `conn_max_lifetime` recycles connections so a load balancer or failover
in front of the cluster cannot leave a replica pinned to a dead backend.

## Invariants preserved on both backends

The correctness guarantees the PKI relies on hold identically on SQLite and
PostgreSQL, and are covered by the cross-backend integration tests:

- **Tamper-evident audit chain.** `event_log` rows are hash-chained (each row's
  hash covers the previous row's hash). Appends are serialized (a mutex plus a
  single transaction that reads the current tail and inserts the next row), so
  the chain stays gap-free and correctly linked even under concurrent writers on
  PostgreSQL, where multiple replicas write to the same table.
- **Monotonic serials and CRL numbers.** Serial allocation and CRL-number
  allocation are transactional counter increments, so no certificate serial or
  CRL number is ever reused — the property that makes a multi-writer CA safe.

## Migrating an existing SQLite store into PostgreSQL

Use `secsy-ca db migrate` to lift a single-node file store into a shared
PostgreSQL database before switching replicas over:

```bash
# Stop writers (or run during a maintenance window) so the source is quiescent.
secsy-ca db migrate \
  -from-driver sqlite   -from-dsn ./secsy-pki.db \
  -to-driver   postgres -to-dsn   'postgres://secsy:secret@db:5432/secsy_pki?sslmode=require'
```

`-from-dsn` defaults to the configured database when its driver matches, so on a
running node you often need only `-to-dsn`.

The migration:

1. **Verifies the source audit chain first** and refuses to run if it is broken,
   so tampering cannot be laundered into the new store.
2. **Refuses a non-empty destination** (checks the authority and audit tables) so
   a re-run cannot double-insert.
3. **Copies every table** in foreign-key-safe order. `event_log` rows are copied
   verbatim (sequence numbers, `prev_hash`, `hash`), so the chain is
   byte-identical on the destination. The serial and CRL-number counters are
   copied verbatim, so allocation resumes exactly where the source left off with
   no reuse.
4. **Resets PostgreSQL identity sequences** past the largest copied id, so
   subsequent natural inserts do not collide with migrated rows.
5. **Re-verifies the audit chain on the destination** before reporting success,
   and prints a per-table row-count report.

After a successful migration, point `config.database` (or the
`SECSY_DATABASE_*` env vars) at PostgreSQL and start the replicas.

## Running multiple replicas (HA)

1. Provision PostgreSQL and create an empty database.
2. Migrate the existing store (above), or start fresh — the schema is created
   automatically on first start.
3. Configure every replica with the same PostgreSQL DSN.
4. Scale out. The audit-chain serialization and transactional counters make
   concurrent issuance, revocation, and ACME progress safe across replicas.

> **Note:** HSM/PKCS#11 key material is *not* stored in the database — it stays
> in the HSM. The database holds only metadata, public certificates, and audit
> records. Each replica must have access to the same key provider (HSM token or
> shared software keystore).

### Kubernetes

The Helm chart has a first-class `externalDatabase` block that wires all of the
above — enabling it injects `SECSY_DATABASE_DRIVER`/`SECSY_DATABASE_DSN` from a
Secret (never the ConfigMap) and lets you raise `replicaCount`. See the
[Kubernetes guide](kubernetes.md#external-postgresql-for-ha).

## Testing

- SQLite unit/integration tests build with `-tags sqlite` (CGO):
  `go test -tags sqlite ./internal/database/...`
- The cross-backend tests (including the SQLite→PostgreSQL migration) also run
  against a real PostgreSQL when `SECSY_TEST_PG_DSN` is set. Bring one up with
  the throwaway compose file:

  ```bash
  docker compose -f server/docker-compose.postgres.yaml up -d
  export SECSY_TEST_PG_DSN='postgres://secsy:secsy@localhost:5433/secsy_pki?sslmode=disable'
  (cd server && go test -tags sqlite ./internal/database/...)
  docker compose -f server/docker-compose.postgres.yaml down -v
  ```
