package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// migrationTables lists every persisted table in a dependency-safe order:
// parents precede children so that foreign-key constraints hold as rows are
// inserted one table at a time. Copying in this order lets the migration run
// against a PostgreSQL account with ordinary privileges — it does not depend on
// disabling triggers or deferring constraints.
//
// If a table is ever added to the schema, it must be added here (in FK order) so
// the file→Postgres migration remains complete; MigrateStore cross-checks the
// live schema against this list and fails loudly on any omission.
var migrationTables = []string{
	// Tenants are the top-level isolation boundary; cas and restriction_sets
	// reference them, so they must be copied first to satisfy the FK.
	"tenants",
	// Per-tenant daily usage counters (Task 61) reference tenants.
	"tenant_usage",
	// Authorities and the subjects/policy that reference them.
	"cas",
	"restriction_sets",
	"ssh_restriction_details",
	"x509_restriction_details",
	"groups_",
	"group_members",
	"permissions",
	// Per-CA counters and issuance/revocation records.
	"ca_serial_counters",
	"ca_crl_counters",
	"ca_scoped_crl_counters",
	"ca_published_crls",
	"issued_certificates",
	"revoked_certificates",
	// Released certificateHold records (Task 82) retained for delta-CRL
	// removeFromCRL generation; references cas, so copied after it.
	"released_holds",
	// CT SCT inclusion-proof verification state (Task 93); references cas, so
	// copied after it.
	"sct_inclusion",
	// Cross-signing relationships reference tenants and cas (issuer/subject), so
	// they are copied after both.
	"cross_signs",
	// Audit and export state. audit_anchors holds the RFC 3161 head attestations
	// (Task 64); copying them verbatim keeps truncation evidence intact across a
	// store migration.
	"audit_log",
	"access_log",
	"hsm_audit_entries",
	"event_log",
	"siem_export_cursor",
	"audit_anchors",
	// ACME state (account → order → authorization → challenge).
	"acme_accounts",
	"acme_orders",
	"acme_authorizations",
	"acme_challenges",
	// Shared anti-replay nonce state (Task 97): the consumed-set and the
	// server-wide signing secret. Both are standalone (no foreign keys). The
	// consumed-set is ephemeral (rows expire within the nonce TTL), so copying it
	// is harmless; the secret is copied so nonces minted before a store migration
	// still verify after it.
	"acme_nonces",
	"acme_nonce_secret",
	// Operator WebAuthn credentials (standalone; no foreign keys).
	"webauthn_credentials",
	// Discovered external certificates (Task 54). Tenant-scoped; references
	// tenants, so copied after it.
	"discovered_certificates",
	// SSH certificate authority state (Task 57). Both reference cas (and
	// ssh_certificates references tenants), so they are copied after those.
	"ssh_certificates",
	"ssh_revocations",
	// Secret-layer KEK rotation state (Task 63). kek_versions is standalone;
	// stored_secrets references tenants, so it is copied after them, and the
	// value-history rows (Task 73) reference stored_secrets, so they come last.
	"kek_versions",
	"stored_secrets",
	"stored_secret_versions",
	// Post-quantum hybrid ML-KEM key material (Task 137). Keyed by KEK family;
	// standalone (no foreign keys). Copied with the rest of the secret layer so a
	// store migration preserves the sealed decapsulation key (existing hybrid
	// envelopes stay openable after the migration).
	"pqc_hybrid_keys",
	// Keyed-HMAC MAC keys for the crypto service (Task 138). Keyed by KEK
	// family/version; standalone (no foreign keys). Copied with the rest of the
	// secret layer so a store migration preserves the sealed MAC seed (existing
	// HMAC tokens still verify after the migration).
	"mac_keys",
	// Named HSM-backed asymmetric signing keys for the crypto service (Task 153).
	// Keyed by id, unique per (tenant, name); standalone (no foreign keys). Holds
	// only metadata plus the exported public key — no private material — so a store
	// migration preserves the ability to verify and to address the HSM key.
	"signing_keys",
	// Format-preserving-encryption / tokenization seed (Task 144). One row per KEK
	// family; standalone (no foreign keys). Copied with the rest of the secret
	// layer so a store migration preserves the sealed FPE seed (existing tokens
	// still decode after the migration).
	"fpe_seeds",
	// Four-eyes approval workflow (Task 81). pending_approvals references
	// tenants, so it is copied after them; the per-approver decisions reference
	// pending_approvals, so they come last.
	"pending_approvals",
	"approval_decisions",
	// Native scoped API tokens / service accounts (Task 86). References tenants,
	// so copied after them; no children of its own.
	"api_tokens",
	// Durable outbound webhook subscriptions and their delivery queue (Task 116).
	// webhook_subscriptions references tenants, so it is copied after them; the
	// delivery rows reference webhook_subscriptions, so they come after that; the
	// fan-out cursor is standalone.
	"webhook_subscriptions",
	"webhook_deliveries",
	"webhook_fanout_cursor",
	// Operator-managed compromised-key blocklist (Task 120). Deployment-global; no
	// foreign keys, so it can be copied at any point.
	"blocked_keys",
}

// tableCopyOrder pins the read order for tables whose rows have intra-table
// ordering requirements (self-referential foreign keys). Tables absent from the
// map are copied in the engine's natural order.
var tableCopyOrder = map[string]string{
	"cas": "created_at",
}

// TableReport records the number of rows copied from one table.
type TableReport struct {
	Table string
	Rows  int64
}

// MigrationReport summarizes a completed store migration.
type MigrationReport struct {
	Tables     []TableReport
	TotalRows  int64
	ChainValid bool
	ChainCount int
	SourceDrv  string
	DestDrv    string
}

// MigrateStore copies the entire contents of src into dst, table by table, in a
// foreign-key-safe order. It is the engine behind `secsy-ca db migrate`, whose
// purpose is to lift an existing single-node SQLite ("file") store into a shared
// PostgreSQL database for multi-replica HA.
//
// Invariants preserved:
//   - The tamper-evident audit chain: event_log rows (seq, prev_hash, hash) are
//     copied verbatim, so the chain hashes are byte-identical on the destination;
//     MigrateStore re-verifies the chain on dst before returning.
//   - Monotonic counters: ca_serial_counters and the CRL-number counters are
//     copied verbatim, so serial/CRL-number allocation continues without reuse.
//   - SERIAL identity: after copying, PostgreSQL identity sequences are advanced
//     past the largest copied id (see resetSequences) so subsequent inserts do
//     not collide with migrated rows.
//
// dst must be freshly migrated (schema present) and empty; MigrateStore refuses
// to run against a destination that already holds authority or event data, to
// avoid duplicate-key corruption.
func MigrateStore(ctx context.Context, src, dst *DB) (*MigrationReport, error) {
	if src == nil || dst == nil {
		return nil, fmt.Errorf("migrate: src and dst must both be non-nil")
	}

	if err := verifyTableCoverage(dst); err != nil {
		return nil, err
	}
	if err := ensureDestinationEmpty(dst); err != nil {
		return nil, err
	}

	// The source chain must be intact before we trust it as the authority of
	// record; migrating a broken chain would silently launder tampering.
	if res, err := src.VerifyEventChain(); err != nil {
		return nil, fmt.Errorf("migrate: verifying source audit chain: %w", err)
	} else if !res.Valid {
		return nil, fmt.Errorf("migrate: source audit chain is invalid (broken at seq %d); refusing to migrate", res.BrokenAtSeq)
	}

	report := &MigrationReport{SourceDrv: src.driver, DestDrv: dst.driver}

	// The copy runs on a single dedicated connection so any session-level settings
	// (FK bypass, when permitted) apply consistently. It is scoped to this closure
	// and released before the post-copy verification below: under SQLite the pool
	// has exactly one connection, so holding it while calling back into the pool
	// (VerifyEventChain) would deadlock.
	if err := func() error {
		conn, err := dst.conn.Conn(ctx)
		if err != nil {
			return fmt.Errorf("acquiring destination connection: %w", err)
		}
		defer func() { _ = conn.Close() }()

		// Best-effort: on PostgreSQL run as a superuser this bypasses FK triggers so
		// ordering mistakes cannot wedge the copy. It is not required — the ordered
		// table list already satisfies the constraints — so a failure (ordinary role)
		// is ignored and the ordered inserts carry the load.
		if dst.isPostgres() {
			_, _ = conn.ExecContext(ctx, "SET session_replication_role = replica")
			defer func() { _, _ = conn.ExecContext(ctx, "SET session_replication_role = origin") }()
		}

		destTypes := map[string]map[string]string{}
		if dst.isPostgres() {
			destTypes, err = loadColumnTypes(ctx, conn)
			if err != nil {
				return fmt.Errorf("reading destination column types: %w", err)
			}
		}

		for _, table := range migrationTables {
			n, err := copyTable(ctx, src, dst, conn, table, destTypes[table])
			if err != nil {
				return fmt.Errorf("copying %s: %w", table, err)
			}
			report.Tables = append(report.Tables, TableReport{Table: table, Rows: n})
			report.TotalRows += n
		}

		if dst.isPostgres() {
			if err := resetSequences(ctx, conn); err != nil {
				return fmt.Errorf("resetting identity sequences: %w", err)
			}
		}
		return nil
	}(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Re-verify on the destination: this proves the audit chain survived the copy
	// intact (row order, hashes, gap-free sequence) end to end.
	res, err := dst.VerifyEventChain()
	if err != nil {
		return nil, fmt.Errorf("migrate: verifying destination audit chain: %w", err)
	}
	if !res.Valid {
		return nil, fmt.Errorf("migrate: destination audit chain invalid after copy (broken at seq %d)", res.BrokenAtSeq)
	}
	report.ChainValid = res.Valid
	report.ChainCount = res.Count
	return report, nil
}

// copyTable streams every row of one table from src to dst. Column names are
// discovered from the source result set, so the copy is schema-driven and needs
// no per-table field lists. Values are normalized to the destination column
// types (see normalizeValue) to bridge the SQLite/PostgreSQL representation gap
// for booleans, byte strings, and text.
func copyTable(ctx context.Context, src, dst *DB, dstConn *sql.Conn, table string, colTypes map[string]string) (int64, error) {
	query := "SELECT * FROM " + table
	// The cas table self-references (parent_id → cas.id), so a child row must not
	// be inserted before its parent. Ordering by creation time places roots before
	// the intermediates issued under them, keeping the FK satisfied even when the
	// destination role cannot bypass constraint triggers.
	if order := tableCopyOrder[table]; order != "" {
		query += " ORDER BY " + order
	}
	rows, err := src.conn.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("reading source: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}

	placeholders := make([]string, len(cols))
	for i := range placeholders {
		placeholders[i] = "?"
	}
	// migrate() seeds idempotent baseline rows (the built-in restriction sets)
	// into every fresh database, so those identical rows already exist on the
	// destination. A conflict-tolerant insert skips them rather than aborting the
	// copy; all genuine data rows (guarded empty by ensureDestinationEmpty) insert
	// normally, and RowsAffected reflects the true number of rows added.
	insertSQL := dst.insertOrIgnore(table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))

	var count int64
	for rows.Next() {
		raw := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return count, fmt.Errorf("scanning row %d: %w", count, err)
		}

		args := make([]interface{}, len(cols))
		for i, v := range raw {
			args[i] = normalizeValue(v, colTypes[cols[i]])
		}
		res, err := dstConn.ExecContext(ctx, insertSQL, args...)
		if err != nil {
			return count, fmt.Errorf("inserting row %d: %w", count, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			count += n
		} else {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	return count, nil
}

// normalizeValue coerces a value read from the source engine into a form the
// destination column accepts. SQLite is dynamically typed and the driver returns
// TEXT as []byte, BOOLEAN as int64, and BLOB as []byte; PostgreSQL's typed
// columns reject some of those directly:
//   - a bytea destination needs a []byte, so a text-encoded value is re-wrapped;
//   - a boolean destination needs a bool, so 0/1 and "t"/"f" are converted;
//   - every other destination (text, timestamp, numeric) is happiest with a Go
//     string, so a []byte is decoded to string (PostgreSQL then parses it).
//
// When destType is empty (destination is SQLite, or the column type is unknown)
// the value passes through unchanged, since SQLite accepts the source form.
func normalizeValue(v interface{}, destType string) interface{} {
	if v == nil {
		return nil
	}
	switch destType {
	case "bytea":
		if s, ok := v.(string); ok {
			return []byte(s)
		}
		return v // already []byte
	case "boolean":
		switch b := v.(type) {
		case bool:
			return b
		case int64:
			return b != 0
		case []byte:
			return parseBool(string(b))
		case string:
			return parseBool(b)
		default:
			return v
		}
	default:
		// text / timestamp / numeric families: prefer string over raw bytes.
		if b, ok := v.([]byte); ok {
			return string(b)
		}
		return v
	}
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes", "y":
		return true
	default:
		return false
	}
}

// loadColumnTypes returns table → column → data_type for the public schema, used
// to drive value normalization. It is PostgreSQL-specific (information_schema).
func loadColumnTypes(ctx context.Context, conn *sql.Conn) (map[string]map[string]string, error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT table_name, column_name, data_type
		   FROM information_schema.columns
		  WHERE table_schema = 'public'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]map[string]string{}
	for rows.Next() {
		var table, col, typ string
		if err := rows.Scan(&table, &col, &typ); err != nil {
			return nil, err
		}
		if out[table] == nil {
			out[table] = map[string]string{}
		}
		out[table][col] = strings.ToLower(typ)
	}
	return out, rows.Err()
}

// resetSequences advances every SERIAL/identity sequence in the public schema so
// its next value is greater than the largest id already present. Because the
// migration inserts explicit id/seq values (to preserve audit sequence numbers
// and cross-table references), the identity generators would otherwise still be
// at 1 and collide with migrated rows on the next natural insert.
func resetSequences(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx,
		`SELECT table_name, column_name
		   FROM information_schema.columns
		  WHERE table_schema = 'public'
		    AND column_default LIKE 'nextval(%'`)
	if err != nil {
		return err
	}
	type serialCol struct{ table, col string }
	var serials []serialCol
	for rows.Next() {
		var sc serialCol
		if err := rows.Scan(&sc.table, &sc.col); err != nil {
			rows.Close()
			return err
		}
		serials = append(serials, sc)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, sc := range serials {
		// setval to max(id); is_called=false when the table is empty so the first
		// natural insert still returns 1. GREATEST guards the empty case.
		q := fmt.Sprintf(
			`SELECT setval(
			   pg_get_serial_sequence('%s', '%s'),
			   GREATEST((SELECT COALESCE(MAX(%s), 0) FROM %s), 1),
			   (SELECT COUNT(*) FROM %s) > 0
			 )`, sc.table, sc.col, sc.col, sc.table, sc.table)
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("setval %s.%s: %w", sc.table, sc.col, err)
		}
	}
	return nil
}

// verifyTableCoverage cross-checks migrationTables against the live schema of
// dst so a schema addition cannot silently be left out of the migration. It is a
// no-op for SQLite destinations (migration targets PostgreSQL), where the check
// would require a different catalog query.
func verifyTableCoverage(dst *DB) error {
	if !dst.isPostgres() {
		return nil
	}
	rows, err := dst.conn.Query(
		`SELECT table_name FROM information_schema.tables
		  WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		return err
	}
	defer rows.Close()

	known := map[string]bool{}
	for _, t := range migrationTables {
		known[t] = true
	}
	var missing []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return err
		}
		// schema_migrations-style bookkeeping tables, if any, are not data tables.
		if !known[t] {
			missing = append(missing, t)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("migrate: schema table(s) %v are not covered by the migration; update migrationTables", missing)
	}
	return nil
}

// MissingTables reports which tables from the canonical schema list
// (migrationTables — the single source of truth for the persisted schema) are
// absent from the live store, in the canonical order. It is the read-only
// pending-migration probe used by `secsy-ca doctor`: a non-empty result means
// the store predates the current schema (or was never initialized) and the
// missing tables will be created the next time the store is opened with New.
func (db *DB) MissingTables() ([]string, error) {
	var rows *sql.Rows
	var err error
	if db.isPostgres() {
		rows, err = db.conn.Query(
			`SELECT table_name FROM information_schema.tables
			  WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	} else {
		rows, err = db.conn.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	}
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}
	defer rows.Close()

	live := map[string]bool{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		live[t] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var missing []string
	for _, t := range migrationTables {
		if !live[t] {
			missing = append(missing, t)
		}
	}
	return missing, nil
}

// ensureDestinationEmpty refuses to migrate into a store that already holds
// authority or audit data, so a re-run cannot double-insert and violate unique
// or primary-key constraints (which would leave a half-copied database).
func ensureDestinationEmpty(dst *DB) error {
	for _, table := range []string{"cas", "issued_certificates", "event_log", "acme_accounts"} {
		var n int64
		if err := dst.conn.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			return fmt.Errorf("migrate: checking destination %s: %w", table, err)
		}
		if n > 0 {
			return fmt.Errorf("migrate: destination is not empty (%s has %d rows); refusing to overwrite", table, n)
		}
	}
	return nil
}
