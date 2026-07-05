package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
)

type DB struct {
	conn   *sql.DB
	driver string

	// eventMu serializes appends to the tamper-evident event_log so the read of
	// the previous entry's hash and the insert of the next entry are atomic with
	// respect to each other, keeping the hash chain consistent under concurrency.
	// It also guards eventHook so installing the hook races neither with an
	// in-flight append nor with its invocation.
	eventMu sync.Mutex
	// eventHook, when non-nil, is invoked with each event AFTER it has been sealed
	// and durably committed, from within the eventMu critical section so callbacks
	// observe events in the same monotonic sequence they were chained in. It backs
	// the operator live audit-event SSE feed (internal/eventstream): AppendEvent is
	// the single audit-append chokepoint, so hooking it fans every event out
	// identically no matter which layer (HTTP handler, background job, or protocol
	// server) appended it. The hook must never block — the feed's Publisher is
	// explicitly non-blocking — or it would stall the audit hot path.
	eventHook func(audit.Event)
}

// PoolOptions tunes the underlying database/sql connection pool. Zero values
// select driver-appropriate defaults (see New), so callers may leave any field
// unset. The pool is only meaningful for networked backends such as PostgreSQL,
// where multiple server replicas each maintain a bounded pool against the shared
// database; SQLite is single-connection by construction and ignores these knobs.
type PoolOptions struct {
	// MaxOpenConns bounds the total number of open connections to the database.
	MaxOpenConns int
	// MaxIdleConns bounds the number of idle connections retained in the pool.
	MaxIdleConns int
	// ConnMaxLifetime is the maximum age of a connection before it is recycled.
	// Recycling protects against server-side idle timeouts and load-balancer
	// connection draining in front of a replicated PostgreSQL cluster.
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime is the maximum time a connection may sit idle before it is
	// closed, releasing backend resources during quiet periods.
	ConnMaxIdleTime time.Duration
}

func New(driver, dsn string) (*DB, error) {
	return NewWithOptions(driver, dsn, PoolOptions{})
}

// NewWithOptions opens a database with an explicit connection-pool configuration.
// It is the constructor used by the servers so operators can size the PostgreSQL
// pool for their replica count and backend limits; New wraps it with defaults.
func NewWithOptions(driver, dsn string, opts PoolOptions) (*DB, error) {
	return open(driver, dsn, opts, true)
}

// OpenExisting opens an already-provisioned store WITHOUT applying schema
// migrations or seeding baseline rows, so read-only tooling (`secsy-ca doctor`)
// can inspect a store exactly as it stands. Unlike New it also refuses to
// create a missing SQLite file (sql.Open would silently create an empty one)
// and leaves the journal mode untouched. Use MissingTables to report whether
// the schema is complete; a store opened this way may predate newer tables, so
// reads against those tables will fail until the server (or `secsy-ca`) next
// opens the store normally and migrates it.
func OpenExisting(driver, dsn string) (*DB, error) {
	if driver == "sqlite" || driver == "sqlite3" {
		if path := sqliteFilePath(dsn); path != "" {
			if _, err := os.Stat(path); err != nil {
				return nil, fmt.Errorf("sqlite database %q does not exist (refusing to create it): %w", path, err)
			}
		}
	}
	return open(driver, dsn, PoolOptions{}, false)
}

// sqliteFilePath extracts the on-disk path from a SQLite DSN, returning "" for
// in-memory databases (where there is no file whose existence could be
// required).
func sqliteFilePath(dsn string) string {
	path := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == ":memory:" || strings.Contains(dsn, "mode=memory") {
		return ""
	}
	return path
}

func open(driver, dsn string, opts PoolOptions, runMigrations bool) (*DB, error) {
	driverName := driver
	if driverName == "sqlite" {
		driverName = "sqlite3"
	}
	conn, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if driver == "sqlite" || driver == "sqlite3" {
		// SQLite is an embedded, file-backed store; concurrent writers corrupt the
		// hash-chained event log, so it is pinned to a single connection and relies
		// on WAL mode for read concurrency. Pool options do not apply.
		conn.SetMaxOpenConns(1)
		if runMigrations {
			// Switching the journal mode rewrites the database file, so the
			// non-migrating (read-only inspection) open path leaves it untouched.
			if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
				return nil, fmt.Errorf("setting journal mode: %w", err)
			}
		}
		if _, err := conn.Exec("PRAGMA foreign_keys=ON"); err != nil {
			return nil, fmt.Errorf("enabling foreign keys: %w", err)
		}
	} else {
		// Networked backends (PostgreSQL) get a bounded pool so a fleet of replicas
		// does not exhaust the server's connection limit. Defaults are conservative
		// and overridable per deployment.
		maxOpen := opts.MaxOpenConns
		if maxOpen <= 0 {
			maxOpen = 10
		}
		maxIdle := opts.MaxIdleConns
		if maxIdle <= 0 {
			maxIdle = 5
		}
		if maxIdle > maxOpen {
			maxIdle = maxOpen
		}
		lifetime := opts.ConnMaxLifetime
		if lifetime <= 0 {
			lifetime = 30 * time.Minute
		}
		idleTime := opts.ConnMaxIdleTime
		if idleTime <= 0 {
			idleTime = 5 * time.Minute
		}
		conn.SetMaxOpenConns(maxOpen)
		conn.SetMaxIdleConns(maxIdle)
		conn.SetConnMaxLifetime(lifetime)
		conn.SetConnMaxIdleTime(idleTime)
	}
	db := &DB{conn: conn, driver: driver}
	if runMigrations {
		if err := db.migrate(); err != nil {
			return nil, fmt.Errorf("migrating: %w", err)
		}
	}
	return db, nil
}

func (db *DB) isPostgres() bool {
	return db.driver == "postgres" || db.driver == "postgresql"
}

// Driver returns the configured database driver name ("sqlite", "postgres").
func (db *DB) Driver() string { return db.driver }

// SnapshotSQLite writes a consistent, self-contained copy of a SQLite database
// to destPath using "VACUUM INTO", which is safe to run online (it takes a read
// lock and produces a defragmented copy). It is used by the CA-metadata backup
// procedure to capture the authoritative store without stopping the service.
//
// It returns an error for non-SQLite drivers, where an operator should use the
// engine's native tooling (e.g. pg_dump) instead — see the DR runbook.
func (db *DB) SnapshotSQLite(destPath string) error {
	if db.driver != "sqlite" && db.driver != "sqlite3" {
		return fmt.Errorf("SnapshotSQLite: unsupported driver %q; use the engine's native backup (e.g. pg_dump)", db.driver)
	}
	// VACUUM INTO does not accept a bound parameter for the destination, so the
	// path is inlined as a single-quoted SQL string literal with embedded quotes
	// escaped. destPath originates from a trusted operator CLI flag.
	escaped := strings.ReplaceAll(destPath, "'", "''")
	if _, err := db.conn.Exec("VACUUM INTO '" + escaped + "'"); err != nil {
		return fmt.Errorf("SnapshotSQLite: %w", err)
	}
	return nil
}

// ph converts ? placeholders to $1, $2, ... for PostgreSQL
func (db *DB) ph(query string) string {
	if !db.isPostgres() {
		return query
	}
	n := 0
	var result strings.Builder
	for _, c := range query {
		if c == '?' {
			n++
			result.WriteRune('$')
			result.WriteString(strconv.Itoa(n))
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// forUpdate returns the row-locking clause for transactional counter reads. On
// PostgreSQL, where the pool hands out multiple connections and the default
// READ COMMITTED isolation lets two transactions read the same counter value
// before either writes, "FOR UPDATE" serializes them by locking the counter row
// until commit — the guarantee that keeps serial and CRL numbers strictly
// monotonic and non-repeating under concurrent, multi-replica issuance. SQLite
// is pinned to a single connection (see New), so its counter transactions are
// already serialized and it does not support the clause.
func (db *DB) forUpdate() string {
	if db.isPostgres() {
		return " FOR UPDATE"
	}
	return ""
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// Ping verifies the database connection is alive, for readiness checks. It uses
// PingContext so a hung backend cannot block the probe past the caller's
// deadline.
func (db *DB) Ping(ctx context.Context) error {
	return db.conn.PingContext(ctx)
}

// ServerTime returns the database server's wall-clock time for networked
// backends, so diagnostics can detect clock skew between this host and the
// shared store (which would distort certificate validity windows, CRL
// thisUpdate/nextUpdate, and audit timestamps across replicas). ok is false
// for embedded SQLite, which runs in-process and shares the host clock.
func (db *DB) ServerTime(ctx context.Context) (t time.Time, ok bool, err error) {
	if !db.isPostgres() {
		return time.Time{}, false, nil
	}
	err = db.conn.QueryRowContext(ctx, `SELECT NOW()`).Scan(&t)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

func (db *DB) exec(query string, args ...interface{}) (sql.Result, error) {
	return db.conn.Exec(db.ph(query), args...)
}

func (db *DB) queryRow(query string, args ...interface{}) *sql.Row {
	return db.conn.QueryRow(db.ph(query), args...)
}

func (db *DB) query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.conn.Query(db.ph(query), args...)
}

func (db *DB) migrate() error {
	blob := "BLOB"
	autoIncPK := "INTEGER PRIMARY KEY AUTOINCREMENT"
	boolType := "INTEGER NOT NULL DEFAULT 0"

	if db.isPostgres() {
		blob = "BYTEA"
		autoIncPK = "SERIAL PRIMARY KEY"
		boolType = "BOOLEAN NOT NULL DEFAULT FALSE"
	}

	currentTimestamp := "DATETIME DEFAULT CURRENT_TIMESTAMP"
	if db.isPostgres() {
		currentTimestamp = "TIMESTAMP DEFAULT NOW()"
	}

	stmts := []string{
		// Tenants are the top-level isolation boundary (Task 43). Every deployment
		// has the built-in 'default' tenant; single-organization installs use it
		// implicitly. Tenant-scoped resources (cas, restriction_sets, groups_,
		// event_log) carry the owning tenant, and authorization forbids reaching
		// another tenant's resources.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS tenants (
			id TEXT PRIMARY KEY,
			slug TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			kek_label TEXT,
			created_at %s,
			max_certs_per_day INTEGER NOT NULL DEFAULT 0,
			max_active_certs INTEGER NOT NULL DEFAULT 0,
			max_secret_ops_per_day INTEGER NOT NULL DEFAULT 0,
			rate_limit_per_second REAL NOT NULL DEFAULT 0,
			rate_limit_burst REAL NOT NULL DEFAULT 0
		)`, currentTimestamp),
		// Per-tenant, per-UTC-day usage counters (Task 61). One row per tenant
		// per day, upserted atomically on the issuance/secret paths; the daily
		// quotas (max_certs_per_day, max_secret_ops_per_day) meter against the
		// current day's row, and the usage report reads a rolling window of rows.
		`CREATE TABLE IF NOT EXISTS tenant_usage (
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			day TEXT NOT NULL,
			certs_issued INTEGER NOT NULL DEFAULT 0,
			certs_revoked INTEGER NOT NULL DEFAULT 0,
			secret_ops INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant_id, day)
		)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS cas (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			parent_id TEXT REFERENCES cas(id),
			label TEXT NOT NULL,
			pkcs11_uri TEXT NOT NULL,
			key_type TEXT NOT NULL,
			public_key %s NOT NULL,
			default_ssh_restriction_set_id TEXT,
			default_x509_restriction_set_id TEXT,
			certificate TEXT,
			subject TEXT,
			serial TEXT,
			not_before TIMESTAMP,
			not_after TIMESTAMP,
			max_path_len INTEGER,
			status TEXT NOT NULL DEFAULT 'active',
			successor_id TEXT,
			predecessor_id TEXT,
			retire_after TIMESTAMP,
			csr TEXT,
			external_chain TEXT,
			created_at %s
		)`, blob, currentTimestamp),
		// Per-CA monotonic serial counter used to allocate unique certificate
		// serial numbers for the subordinate certificates a CA issues.
		`CREATE TABLE IF NOT EXISTS ca_serial_counters (
			ca_id TEXT PRIMARY KEY REFERENCES cas(id) ON DELETE CASCADE,
			next_serial INTEGER NOT NULL
		)`,
		// Per-CA monotonic CRL number counter. Each published CRL must carry a
		// strictly greater number than the previous one (RFC 5280 §5.2.3).
		`CREATE TABLE IF NOT EXISTS ca_crl_counters (
			ca_id TEXT PRIMARY KEY REFERENCES cas(id) ON DELETE CASCADE,
			next_number INTEGER NOT NULL
		)`,
		// End-entity certificates issued by a CA. The authority keeps a copy for
		// renewal, listing, and revocation bookkeeping. (serial is unique per
		// issuing CA.)
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS issued_certificates (
			id TEXT PRIMARY KEY,
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			serial TEXT NOT NULL,
			subject TEXT,
			common_name TEXT,
			sans TEXT,
			profile TEXT,
			certificate TEXT NOT NULL,
			not_before TIMESTAMP,
			not_after TIMESTAMP,
			status TEXT NOT NULL DEFAULT 'valid',
			revoked_at TIMESTAMP,
			revocation_reason INTEGER NOT NULL DEFAULT 0,
			requested_by TEXT,
			created_at %s,
			ct_status TEXT NOT NULL DEFAULT 'none',
			sct_count INTEGER NOT NULL DEFAULT 0,
			marker TEXT NOT NULL DEFAULT '',
			public_key_fingerprint TEXT NOT NULL DEFAULT '',
			UNIQUE(ca_id, serial)
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_issued_certs_keyfp ON issued_certificates(public_key_fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_issued_certs_ca ON issued_certificates(ca_id)`,
		`CREATE INDEX IF NOT EXISTS idx_issued_certs_status ON issued_certificates(ca_id, status)`,
		// Authoritative revocation store read by CRL/OCSP generation. Kept
		// separate from issued_certificates so a serial that was never recorded
		// (e.g. an externally issued certificate) can still be revoked.
		`CREATE TABLE IF NOT EXISTS revoked_certificates (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			serial TEXT NOT NULL,
			revoked_at TIMESTAMP NOT NULL,
			reason INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ca_id, serial)
		)`,
		// Certificates that were on hold (RFC 5280 certificateHold) and have since
		// been released. The row survives the release so delta CRL generation can
		// emit the removeFromCRL (reason 8) entry for relying parties still holding a
		// base CRL that lists the hold (RFC 5280 §5.2.4). A serial here is NOT in the
		// current revocation set — OCSP reports it good and the base CRL omits it —
		// and it is cleared if the serial is later re-suspended or permanently
		// revoked.
		`CREATE TABLE IF NOT EXISTS released_holds (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			serial TEXT NOT NULL,
			reason INTEGER NOT NULL DEFAULT 6,
			held_at TIMESTAMP NOT NULL,
			released_at TIMESTAMP NOT NULL,
			PRIMARY KEY (ca_id, serial)
		)`,
		// Per-CA-and-scope monotonic CRL number counter for partitioned CRLs. The
		// unsharded ("full") scope keeps using ca_crl_counters for backward
		// compatibility; each partition ("partition:N") gets its own independent
		// monotonic sequence shared by its base and delta CRLs (RFC 5280 §5.2.3).
		`CREATE TABLE IF NOT EXISTS ca_scoped_crl_counters (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			scope TEXT NOT NULL,
			next_number INTEGER NOT NULL,
			PRIMARY KEY (ca_id, scope)
		)`,
		// The last published base/delta CRL per (CA, scope, kind). Persisting the
		// artifact keeps a base CRL and the delta CRLs that reference it a
		// consistent pair: a delta's Delta CRL Indicator points at the stored
		// base's CRLNumber, and both are served byte-for-byte until regenerated.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS ca_published_crls (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			scope TEXT NOT NULL,
			kind TEXT NOT NULL,
			crl_number INTEGER NOT NULL,
			base_number INTEGER NOT NULL DEFAULT 0,
			this_update TIMESTAMP NOT NULL,
			next_update TIMESTAMP NOT NULL,
			generated_at TIMESTAMP NOT NULL,
			der %s NOT NULL,
			PRIMARY KEY (ca_id, scope, kind)
		)`, blob),
		// Cross-signing relationships (Task 47): a certificate an issuer CA has
		// signed for a subject public key that another issuer may also certify.
		// subject_ca_id is set only for locally held subjects; subject_key_id (the
		// hex SKI) groups every certificate for the same subject key and is the join
		// for alternate-chain selection. The record is tenant-scoped through its
		// issuer CA; deleting either the issuer or a local subject CA cascades.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS cross_signs (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			issuer_ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			subject_ca_id TEXT REFERENCES cas(id) ON DELETE CASCADE,
			subject_key_id TEXT NOT NULL,
			subject TEXT NOT NULL,
			serial TEXT NOT NULL,
			certificate TEXT NOT NULL,
			not_before TIMESTAMP NOT NULL,
			not_after TIMESTAMP NOT NULL,
			source TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			requested_by TEXT,
			created_at %s,
			UNIQUE(issuer_ca_id, serial)
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_cross_signs_subject_key ON cross_signs(subject_key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cross_signs_subject_ca ON cross_signs(subject_ca_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cross_signs_issuer ON cross_signs(issuer_ca_id)`,
		`CREATE TABLE IF NOT EXISTS groups_ (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default',
			name TEXT NOT NULL
		)`,
		// A group name is unique within a tenant, not globally, so the same name
		// may be reused across tenants without collision.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_name ON groups_(tenant_id, name)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL REFERENCES groups_(id) ON DELETE CASCADE,
			user_sub TEXT NOT NULL,
			PRIMARY KEY (group_id, user_sub)
		)`,
		`CREATE TABLE IF NOT EXISTS restriction_sets (
			id TEXT PRIMARY KEY,
			tenant_id TEXT REFERENCES tenants(id),
			ca_id TEXT REFERENCES cas(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'ssh',
			max_validity_secs INTEGER,
			deny_all ` + boolType + `
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_restriction_details (
			restriction_set_id TEXT PRIMARY KEY REFERENCES restriction_sets(id) ON DELETE CASCADE,
			allowed_principals TEXT,
			allowed_cert_types TEXT,
			force_key_id_email_reason ` + boolType + `,
			require_reason ` + boolType + `,
			allowed_extensions TEXT,
			deny_extensions ` + boolType + `,
			deny_critical_options ` + boolType + `,
			max_valid_after_offset INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS x509_restriction_details (
			restriction_set_id TEXT PRIMARY KEY REFERENCES restriction_sets(id) ON DELETE CASCADE,
			allowed_key_usages TEXT,
			allowed_ext_key_usages TEXT,
			allowed_san_types TEXT,
			allowed_san_patterns TEXT,
			allowed_subject_fields TEXT,
			max_path_length INTEGER,
			deny_ca ` + boolType + `
		)`,
		`CREATE TABLE IF NOT EXISTS permissions (
			id TEXT PRIMARY KEY,
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			entity_type TEXT NOT NULL CHECK(entity_type IN ('user', 'group')),
			entity_id TEXT NOT NULL,
			permission TEXT NOT NULL CHECK(permission IN ('SIGN_CERTIFICATE', 'MANAGE_PERMISSIONS', 'CONFIGURE_CA')),
			ssh_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL,
			x509_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL,
			UNIQUE(ca_id, entity_type, entity_id, permission)
		)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp %s,
			user_sub TEXT NOT NULL,
			user_email TEXT,
			user_name TEXT,
			ca_id TEXT NOT NULL,
			ca_label TEXT NOT NULL,
			key_id TEXT NOT NULL,
			cert_type TEXT NOT NULL,
			principals TEXT,
			valid_after TIMESTAMP NOT NULL,
			valid_before TIMESTAMP NOT NULL,
			extensions TEXT,
			critical_options TEXT,
			public_key %s NOT NULL,
			certificate %s,
			cert_hash TEXT,
			restriction_set_id TEXT,
			serial TEXT NOT NULL,
			UNIQUE(ca_id, cert_hash)
		)`, currentTimestamp, blob, blob),
		`CREATE INDEX IF NOT EXISTS idx_audit_log_ca ON audit_log(ca_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_sub)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(timestamp)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS access_log (
			id TEXT PRIMARY KEY,
			timestamp %s,
			user_sub TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			status INTEGER NOT NULL,
			ip TEXT NOT NULL,
			request_id TEXT
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_access_log_time ON access_log(timestamp)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hsm_audit_entries (
			id %s,
			fetched_at %s,
			number INTEGER NOT NULL,
			command INTEGER NOT NULL,
			length INTEGER NOT NULL,
			session_key INTEGER NOT NULL,
			target_key INTEGER NOT NULL,
			second_key INTEGER NOT NULL,
			result INTEGER NOT NULL,
			tick INTEGER NOT NULL,
			hash TEXT NOT NULL,
			sign_audit_id TEXT REFERENCES audit_log(id)
		)`, autoIncPK, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_hsm_audit_number ON hsm_audit_entries(number)`,
		// Tamper-evident, append-only event log. seq is a gap-free monotonic
		// counter (assigned by the app under eventMu, not the DB, so it is part of
		// the hashed content); prev_hash/hash form the chain. Any edit, deletion,
		// or reordering of rows is detectable via audit.VerifyChain.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS event_log (
			seq INTEGER PRIMARY KEY,
			id TEXT NOT NULL,
			timestamp %s,
			actor TEXT NOT NULL,
			actor_name TEXT,
			actor_roles TEXT,
			action TEXT NOT NULL,
			tenant TEXT,
			target TEXT,
			target_name TEXT,
			result TEXT NOT NULL,
			detail TEXT,
			ip TEXT,
			request_id TEXT,
			prev_hash TEXT NOT NULL,
			hash TEXT NOT NULL
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_event_log_actor ON event_log(actor)`,
		`CREATE INDEX IF NOT EXISTS idx_event_log_action ON event_log(action)`,
		`CREATE INDEX IF NOT EXISTS idx_event_log_time ON event_log(timestamp)`,
		// Durable per-sink export cursor for the SIEM streaming exporter. Each row
		// records the highest event_log.seq a given sink has durably acknowledged.
		// The exporter only advances a cursor after a successful delivery, so on
		// restart it resumes from here — giving at-least-once delivery with no lost
		// events (a crash between delivery and cursor commit redelivers the batch).
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS siem_export_cursor (
			sink TEXT PRIMARY KEY,
			last_seq INTEGER NOT NULL,
			updated_at %s
		)`, currentTimestamp),
		// Audit-chain anchors (Task 64): periodic RFC 3161 attestations of the
		// event_log head. Each row records that at created_at the chain's newest
		// entry was (seq, head_hash), proven by the DER TimeStampToken in token —
		// signed by a TSA key the store writer does not hold, so truncating or
		// rewriting the log behind an anchor is detectable by `secsy-ca audit
		// verify`. tsa_url is NULL for the internal TSA, else the external URL.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS audit_anchors (
			id TEXT PRIMARY KEY,
			seq INTEGER NOT NULL,
			head_hash TEXT NOT NULL,
			token %s NOT NULL,
			tsa_url TEXT,
			gen_time TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`, blob),
		`CREATE INDEX IF NOT EXISTS idx_audit_anchors_seq ON audit_anchors(seq)`,
		// Registered WebAuthn passkeys for operator step-up authentication (Task
		// 50). Only the credential id, public key (SPKI DER), and signature counter
		// are stored; the private key never leaves the authenticator.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT PRIMARY KEY,
			subject TEXT NOT NULL,
			name TEXT,
			public_key %s NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0,
			created_at %s
		)`, blob, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_webauthn_subject ON webauthn_credentials(subject)`,
		// Certificates observed on external TLS endpoints by the discovery scanner
		// (Task 54). Unlike issued_certificates, these were not necessarily minted by
		// this PKI; the scanner records each served leaf's details plus the security
		// flags it raised (expiring, weak key, SHA-1, self-signed, hostname mismatch,
		// and rogue/shadow certs not issued by this PKI). Boolean flags are stored as
		// 0/1 INTEGERs for portability across SQLite and PostgreSQL. Keyed on
		// (endpoint, fingerprint) so re-scanning updates the row in place.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS discovered_certificates (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			endpoint TEXT NOT NULL,
			server_name TEXT,
			subject TEXT,
			common_name TEXT,
			sans TEXT,
			issuer TEXT,
			serial TEXT,
			not_before TIMESTAMP,
			not_after TIMESTAMP,
			key_algorithm TEXT,
			key_size INTEGER NOT NULL DEFAULT 0,
			signature_algorithm TEXT,
			chain_length INTEGER NOT NULL DEFAULT 0,
			chain_complete INTEGER NOT NULL DEFAULT 0,
			fingerprint TEXT NOT NULL,
			certificate TEXT,
			issued_by_pki INTEGER NOT NULL DEFAULT 0,
			rogue INTEGER NOT NULL DEFAULT 0,
			self_signed INTEGER NOT NULL DEFAULT 0,
			weak_key INTEGER NOT NULL DEFAULT 0,
			sha1_signature INTEGER NOT NULL DEFAULT 0,
			hostname_mismatch INTEGER NOT NULL DEFAULT 0,
			expiring_soon INTEGER NOT NULL DEFAULT 0,
			severity TEXT NOT NULL DEFAULT 'ok',
			flags TEXT,
			discovered_at %s,
			UNIQUE(endpoint, fingerprint)
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_discovered_certs_tenant ON discovered_certificates(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_certs_rogue ON discovered_certificates(rogue)`,

		// OpenSSH certificates signed by an HSM-backed SSH CA (Task 57). Serials
		// come from the CA's ca_serial_counters allocator, so (ca_id, serial) is
		// the natural key. tenant_id mirrors the issuing CA's tenant so inventory
		// queries stay tenant-scoped without a join.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS ssh_certificates (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			serial TEXT NOT NULL,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			cert_type TEXT NOT NULL,
			key_id TEXT NOT NULL,
			principals TEXT NOT NULL DEFAULT '',
			profile TEXT NOT NULL DEFAULT '',
			public_key_fingerprint TEXT NOT NULL DEFAULT '',
			certificate TEXT NOT NULL,
			valid_after TIMESTAMP NOT NULL,
			valid_before TIMESTAMP NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			issued_by TEXT NOT NULL DEFAULT '',
			created_at %s,
			PRIMARY KEY (ca_id, serial)
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_ssh_certs_tenant ON ssh_certificates(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ssh_certs_status ON ssh_certificates(ca_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_ssh_certs_key_id ON ssh_certificates(ca_id, key_id)`,

		// SSH revocation store (Task 57), published to relying hosts as an OpenSSH
		// KRL. A row revokes either one certificate serial or every certificate
		// bearing a key ID; the unused half is stored as '' (not NULL) so the
		// composite primary key enforces idempotence on both drivers.
		`CREATE TABLE IF NOT EXISTS ssh_revocations (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			serial TEXT NOT NULL DEFAULT '',
			key_id TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			revoked_by TEXT NOT NULL DEFAULT '',
			revoked_at TIMESTAMP NOT NULL,
			PRIMARY KEY (ca_id, serial, key_id)
		)`,

		// Secret-layer KEK rotation lineage (Task 63). One row per versioned
		// key-encryption key of a family (family = the base KEK label from config
		// or a tenant's kek_label); at most one row per family is 'active'. label
		// is globally unique — it is the HSM CKA_LABEL, and duplicate labels make
		// PKCS#11 lookups ambiguous. A family with no rows has never rotated: its
		// base key is implicitly version 1, active. Rows carry only bookkeeping
		// about HSM-resident keys, never key material.
		`CREATE TABLE IF NOT EXISTS kek_versions (
			family TEXT NOT NULL,
			version INTEGER NOT NULL,
			label TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMP NOT NULL,
			rotated_at TIMESTAMP,
			retired_at TIMESTAMP,
			PRIMARY KEY (family, version)
		)`,

		// Server-held envelope-encrypted secrets (Task 63). The envelope is the
		// same opaque JSON the encrypt API returns — never plaintext, never key
		// material. kek_family/kek_label/kek_version are denormalized from the
		// envelope header so re-wrap work lists and the secrets-on-old-KEK gauge
		// are cheap queries.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS stored_secrets (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			name TEXT NOT NULL,
			envelope TEXT NOT NULL,
			kek_family TEXT NOT NULL,
			kek_label TEXT NOT NULL,
			kek_version INTEGER NOT NULL DEFAULT 1,
			context_bound %s,
			escrowed %s,
			current_version INTEGER NOT NULL DEFAULT 1,
			expires_at TIMESTAMP,
			rotate_every_days INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			value_changed_at TIMESTAMP,
			UNIQUE (tenant_id, name)
		)`, boolType, boolType),
		`CREATE INDEX IF NOT EXISTS idx_stored_secrets_kek ON stored_secrets(kek_family, kek_label)`,

		// Stored-secret value history (Task 73). Every put appends the new
		// envelope as the next version; a rollback appends a copy of an older
		// version rather than rewriting history. Rows are ciphertext only.
		// The (secret_id, current_version) row always mirrors the parent's
		// envelope, and re-wrap batches migrate historical envelopes onto the
		// active KEK so old versions stay decryptable across KEK rotations
		// (the KEK retire guard counts historical rows too).
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS stored_secret_versions (
			secret_id TEXT NOT NULL REFERENCES stored_secrets(id),
			version INTEGER NOT NULL,
			envelope TEXT NOT NULL,
			kek_family TEXT NOT NULL,
			kek_label TEXT NOT NULL,
			kek_version INTEGER NOT NULL DEFAULT 1,
			context_bound %s,
			escrowed %s,
			created_by TEXT NOT NULL DEFAULT '',
			comment TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			PRIMARY KEY (secret_id, version)
		)`, boolType, boolType),
		`CREATE INDEX IF NOT EXISTS idx_stored_secret_versions_kek ON stored_secret_versions(kek_family, kek_label)`,

		// Post-quantum hybrid ML-KEM key material (Task 137). At most one active
		// record per KEK family. The encapsulation key is public; the
		// decapsulation-key seed is stored only SEALED under the family's classical
		// KEK (RSA-OAEP), so recovering it still requires the HSM. Both binary
		// fields are base64-encoded TEXT for cross-database portability, matching
		// the rest of the schema (no BYTEA/BLOB). No plaintext ML-KEM private key
		// is ever persisted. sealed_under_version records which classical KEK
		// rotation version currently seals the decapsulation key.
		`CREATE TABLE IF NOT EXISTS pqc_hybrid_keys (
			family TEXT PRIMARY KEY,
			key_id TEXT NOT NULL,
			alg TEXT NOT NULL,
			encap_key TEXT NOT NULL,
			sealed_decap_key TEXT NOT NULL,
			seal_alg TEXT NOT NULL,
			sealed_under_version INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,

		// Four-eyes / maker-checker approval requests (Task 81). A high-risk
		// operation is held here until enough DISTINCT approvers sign off. The row
		// stores only the operation's identity (class, resource_key, fingerprint)
		// and a human description — never the operation's payload. fingerprint pins
		// the exact parameters so an approval cannot authorize a different
		// operation. required_approvals is snapshotted at request time so a later
		// policy change cannot weaken an in-flight request.
		`CREATE TABLE IF NOT EXISTS pending_approvals (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			operation_class TEXT NOT NULL,
			resource_key TEXT NOT NULL,
			resource_name TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL,
			summary TEXT NOT NULL DEFAULT '',
			details TEXT NOT NULL DEFAULT '',
			requested_by TEXT NOT NULL,
			requested_by_name TEXT NOT NULL DEFAULT '',
			required_approvals INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'pending',
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			decided_at TIMESTAMP,
			executed_at TIMESTAMP,
			payload TEXT NOT NULL DEFAULT '',
			result TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_approvals_open ON pending_approvals(tenant_id, operation_class, fingerprint, status)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_approvals_status ON pending_approvals(status)`,

		// One row per approver decision on a request. UNIQUE(approval_id, approver)
		// is the mechanism that makes "N DISTINCT approvers" enforceable: a given
		// approver contributes at most one decision, so the threshold cannot be met
		// by one principal voting repeatedly.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS approval_decisions (
			id %s,
			approval_id TEXT NOT NULL REFERENCES pending_approvals(id),
			approver TEXT NOT NULL,
			approver_name TEXT NOT NULL DEFAULT '',
			decision TEXT NOT NULL,
			comment TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			UNIQUE (approval_id, approver)
		)`, autoIncPK),
		`CREATE INDEX IF NOT EXISTS idx_approval_decisions_approval ON approval_decisions(approval_id)`,

		// Native scoped API tokens / service accounts (Task 86). Only the one-way
		// hash of the opaque secret is stored (token_hash) — never the secret
		// itself — and its UNIQUE index is the O(1) lookup key on the verify path.
		// roles is a comma-separated RBAC role list; scope is 'tenant' or
		// 'platform'. created_at is written explicitly in UTC (no DEFAULT) so
		// ordering and the nullable lifecycle timestamps round-trip across backends.
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			prefix TEXT NOT NULL DEFAULT '',
			token_hash TEXT NOT NULL UNIQUE,
			roles TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT 'tenant',
			created_by TEXT NOT NULL DEFAULT '',
			created_by_name TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			last_used_at TIMESTAMP,
			last_used_ip TEXT NOT NULL DEFAULT '',
			revoked_at TIMESTAMP,
			revoked_by TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id)`,
		// Durable outbound webhook subscriptions (Task 116). A subscription binds an
		// external endpoint + HMAC secret to a set of certificate lifecycle event
		// types and a tenant scope. event_types is a comma-separated filter (empty =
		// all supported lifecycle events); scope 'platform' receives every tenant's
		// events. Tenant-scoped; references tenants.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS webhook_subscriptions (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
			scope TEXT NOT NULL DEFAULT 'tenant',
			url TEXT NOT NULL,
			secret TEXT NOT NULL DEFAULT '',
			event_types TEXT NOT NULL DEFAULT '',
			enabled %s,
			description TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`, boolType),
		`CREATE INDEX IF NOT EXISTS idx_webhook_subs_tenant ON webhook_subscriptions(tenant_id)`,
		// The durable outbound delivery queue (Task 116). One row per (subscription,
		// event); the UNIQUE(subscription_id, event_seq) constraint makes the
		// cursor-swept fan-out idempotent across restarts and re-scans. The
		// (status, next_attempt_at) index backs the "claim due work" read of the
		// delivery worker. References webhook_subscriptions.
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL REFERENCES webhook_subscriptions(id),
			tenant_id TEXT NOT NULL DEFAULT 'default',
			event_id TEXT NOT NULL DEFAULT '',
			event_seq BIGINT NOT NULL,
			event_type TEXT NOT NULL DEFAULT '',
			payload TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TIMESTAMP NOT NULL,
			last_attempt_at TIMESTAMP,
			last_status_code INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			delivered_at TIMESTAMP,
			UNIQUE(subscription_id, event_seq)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due ON webhook_deliveries(status, next_attempt_at)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_sub ON webhook_deliveries(subscription_id)`,
		// The webhook fan-out high-water mark (Task 116): a single-row table
		// tracking how far the leader-elected fan-out has scanned the event log,
		// mirroring the SIEM export cursor. Standalone (no foreign keys).
		`CREATE TABLE IF NOT EXISTS webhook_fanout_cursor (
			id TEXT PRIMARY KEY,
			last_seq BIGINT NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		// Certificate Transparency SCT inclusion-proof verification state (Task 93).
		// One row per embedded SCT: (issuing CA, certificate serial, log id). The
		// leader-elected inclusion monitor upserts a row each time it checks whether
		// the log that issued the SCT has honored it — merged the precertificate
		// entry into its Merkle tree within the log's Maximum Merge Delay. sct_timestamp
		// is the SCT's asserted time, from which the MMD deadline is measured; a
		// status of 'failed' is a mis-issuance / log-misbehavior signal. Scoped to a
		// CA (and thus a tenant) through ca_id; deleting the CA cascades.
		`CREATE TABLE IF NOT EXISTS sct_inclusion (
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			serial TEXT NOT NULL,
			log_id TEXT NOT NULL,
			log_name TEXT NOT NULL DEFAULT '',
			sct_timestamp TIMESTAMP NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			tree_size INTEGER NOT NULL DEFAULT 0,
			leaf_index INTEGER NOT NULL DEFAULT 0,
			checks INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			first_checked_at TIMESTAMP,
			last_checked_at TIMESTAMP,
			included_at TIMESTAMP,
			alerted ` + boolType + `,
			PRIMARY KEY (ca_id, serial, log_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sct_inclusion_status ON sct_inclusion(status)`,
		// Operator-managed compromised-key blocklist (Task 120). One row per public
		// key the CA must never certify again, keyed by its SubjectPublicKeyInfo
		// SHA-256 fingerprint ("SHA256:<base64>"). It holds no key material and is
		// deployment-global (a compromised key is compromised for every tenant), so
		// it has no tenant scope or foreign key. Consulted by the fail-closed
		// pre-issuance key-quality gate on every issuance surface.
		`CREATE TABLE IF NOT EXISTS blocked_keys (
			fingerprint TEXT PRIMARY KEY,
			reason TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT '',
			added_by TEXT NOT NULL DEFAULT '',
			added_at TIMESTAMP NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.exec(stmt); err != nil {
			return fmt.Errorf("executing %q: %w", stmt[:40], err)
		}
	}
	// Migration: add columns if they don't exist (for existing databases)
	// These are idempotent — errors are ignored for columns that already exist
	if db.isPostgres() {
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS default_ssh_restriction_set_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS default_x509_restriction_set_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS certificate TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS subject TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS serial TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS not_before TIMESTAMP")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS not_after TIMESTAMP")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS max_path_len INTEGER")
		// Key-rotation / rollover state (Task 24).
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS successor_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS predecessor_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS retire_after TIMESTAMP")
		// Externally-signed subordinate CA support (Task 69).
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS csr TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS external_chain TEXT")
		_, _ = db.conn.Exec("ALTER TABLE permissions ADD COLUMN IF NOT EXISTS ssh_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		_, _ = db.conn.Exec("ALTER TABLE permissions ADD COLUMN IF NOT EXISTS x509_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		_, _ = db.conn.Exec("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS certificate BYTEA")
		_, _ = db.conn.Exec("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS cert_hash TEXT")
		// Observability: correlate access/audit rows with the request log.
		_, _ = db.conn.Exec("ALTER TABLE access_log ADD COLUMN IF NOT EXISTS request_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE event_log ADD COLUMN IF NOT EXISTS request_id TEXT")
		// Certificate Transparency status (Task 26).
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS ct_status TEXT NOT NULL DEFAULT 'none'")
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS sct_count INTEGER NOT NULL DEFAULT 0")
		// Synthetic-certificate marker (Task 71): tags issuance-canary probes so
		// monitoring and reports can exclude them.
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS marker TEXT NOT NULL DEFAULT ''")
		// Certified subject public-key fingerprint (Task 120): drives the pre-issuance
		// key-quality gate's duplicate-subject-key detection and locating a compromised
		// key across the inventory. Existing rows backfill to empty.
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT NOT NULL DEFAULT ''")
		// Multi-tenant isolation (Task 43). Existing rows backfill to the default
		// tenant so the upgrade is transparent for single-organization installs.
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default'")
		_, _ = db.conn.Exec("ALTER TABLE groups_ ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default'")
		_, _ = db.conn.Exec("ALTER TABLE restriction_sets ADD COLUMN IF NOT EXISTS tenant_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE event_log ADD COLUMN IF NOT EXISTS tenant TEXT")
		// Per-tenant quotas (Task 61). Zero means unlimited, so existing tenants
		// are unaffected by the upgrade.
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_certs_per_day INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_active_certs INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_secret_ops_per_day INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS rate_limit_per_second REAL NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS rate_limit_burst REAL NOT NULL DEFAULT 0")
		// Secret lifecycle: value versioning + TTL/rotation reminders (Task 73).
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN IF NOT EXISTS current_version INTEGER NOT NULL DEFAULT 1")
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP")
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN IF NOT EXISTS rotate_every_days INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN IF NOT EXISTS value_changed_at TIMESTAMP")
		// Per-profile manual issuance-approval gate (Task 84): cert.issue requests
		// park their issuance inputs (payload) and, once completed, the issued
		// serial (result) so the certificate can be delivered after approval.
		// Existing approval rows default to empty, so admin-op approvals are
		// unaffected by the upgrade.
		_, _ = db.conn.Exec("ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS payload TEXT NOT NULL DEFAULT ''")
		_, _ = db.conn.Exec("ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT ''")
	} else {
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN default_ssh_restriction_set_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN default_x509_restriction_set_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN certificate TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN subject TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN serial TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN not_before TIMESTAMP")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN not_after TIMESTAMP")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN max_path_len INTEGER")
		// Key-rotation / rollover state (Task 24).
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN successor_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN predecessor_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN retire_after TIMESTAMP")
		// Externally-signed subordinate CA support (Task 69).
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN csr TEXT")
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN external_chain TEXT")
		_, _ = db.conn.Exec("ALTER TABLE permissions ADD COLUMN ssh_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		_, _ = db.conn.Exec("ALTER TABLE permissions ADD COLUMN x509_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		_, _ = db.conn.Exec("ALTER TABLE audit_log ADD COLUMN certificate BLOB")
		_, _ = db.conn.Exec("ALTER TABLE audit_log ADD COLUMN cert_hash TEXT")
		// Observability: correlate access/audit rows with the request log.
		_, _ = db.conn.Exec("ALTER TABLE access_log ADD COLUMN request_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE event_log ADD COLUMN request_id TEXT")
		// Certificate Transparency status (Task 26).
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN ct_status TEXT NOT NULL DEFAULT 'none'")
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN sct_count INTEGER NOT NULL DEFAULT 0")
		// Synthetic-certificate marker (Task 71): tags issuance-canary probes so
		// monitoring and reports can exclude them.
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN marker TEXT NOT NULL DEFAULT ''")
		// Certified subject public-key fingerprint (Task 120): drives the pre-issuance
		// key-quality gate's duplicate-subject-key detection.
		_, _ = db.conn.Exec("ALTER TABLE issued_certificates ADD COLUMN public_key_fingerprint TEXT NOT NULL DEFAULT ''")
		// Multi-tenant isolation (Task 43). SQLite ADD COLUMN is idempotently
		// retried; errors for already-present columns are ignored. Existing rows
		// backfill to the default tenant.
		_, _ = db.conn.Exec("ALTER TABLE cas ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
		_, _ = db.conn.Exec("ALTER TABLE groups_ ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
		_, _ = db.conn.Exec("ALTER TABLE restriction_sets ADD COLUMN tenant_id TEXT")
		_, _ = db.conn.Exec("ALTER TABLE event_log ADD COLUMN tenant TEXT")
		// Per-tenant quotas (Task 61). Zero means unlimited, so existing tenants
		// are unaffected by the upgrade.
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN max_certs_per_day INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN max_active_certs INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN max_secret_ops_per_day INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN rate_limit_per_second REAL NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE tenants ADD COLUMN rate_limit_burst REAL NOT NULL DEFAULT 0")
		// Secret lifecycle: value versioning + TTL/rotation reminders (Task 73).
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1")
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN expires_at TIMESTAMP")
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN rotate_every_days INTEGER NOT NULL DEFAULT 0")
		_, _ = db.conn.Exec("ALTER TABLE stored_secrets ADD COLUMN value_changed_at TIMESTAMP")
		// Per-profile manual issuance-approval gate (Task 84). SQLite ADD COLUMN is
		// idempotently retried; errors for already-present columns are ignored.
		_, _ = db.conn.Exec("ALTER TABLE pending_approvals ADD COLUMN payload TEXT NOT NULL DEFAULT ''")
		_, _ = db.conn.Exec("ALTER TABLE pending_approvals ADD COLUMN result TEXT NOT NULL DEFAULT ''")
	}

	// Backfill for stored secrets that predate value versioning (Task 73):
	// their rotation-reminder clock starts at the last envelope write, and
	// their current envelope becomes version-history entry 1 so history,
	// rollback, and the version-aware KEK retire guard see every secret.
	_, _ = db.exec(`UPDATE stored_secrets SET value_changed_at = updated_at WHERE value_changed_at IS NULL`)
	_, _ = db.exec(`INSERT INTO stored_secret_versions
			(secret_id, version, envelope, kek_family, kek_label, kek_version,
			 context_bound, escrowed, created_by, comment, created_at)
		 SELECT s.id, s.current_version, s.envelope, s.kek_family, s.kek_label, s.kek_version,
			 s.context_bound, s.escrowed, '', 'backfilled from pre-versioning registry', s.updated_at
		 FROM stored_secrets s
		 WHERE NOT EXISTS (SELECT 1 FROM stored_secret_versions v WHERE v.secret_id = s.id)`)

	// ACME (RFC 8555) server tables.
	if err := db.migrateACME(); err != nil {
		return err
	}

	// Migrate old mixed restriction_sets table to split tables (if old columns exist)
	db.migrateRestrictionSets()
	_, _ = db.conn.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_cert_unique ON audit_log(ca_id, cert_hash)")

	// Seed the built-in default tenant. insertOrIgnore keeps this idempotent and
	// preserves any operator edits to its name/status on restart.
	_, _ = db.exec(db.insertOrIgnore("tenants", "id, slug, name, status", "?, ?, ?, ?"),
		models.DefaultTenantID, models.DefaultTenantID, "Default Tenant", models.TenantStatusActive)
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_cas_tenant ON cas(tenant_id)")
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_event_log_tenant ON event_log(tenant)")

	// Create built-in restriction sets
	_, _ = db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinPermitAllSSH, "Permit all signatures", "ssh", 0)
	_, _ = db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinDenyAllSSH, "Disallow all signatures", "ssh", 1)
	_, _ = db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinPermitAllX509, "Permit all signatures", "x509", 0)
	_, _ = db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinDenyAllX509, "Disallow all signatures", "x509", 1)

	// Indexes backing the paginated/filtered inventory list endpoints (Task 83).
	// The keyset indexes match the (timestamp, tiebreaker) DESC sort so a page can
	// be served as an index range scan rather than a full sort; the filter indexes
	// back the common status/profile/expiry predicates. All are created after the
	// tables/columns above so they apply to both fresh and upgraded databases.
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_issued_certs_page ON issued_certificates(ca_id, created_at, serial)")
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_issued_certs_profile ON issued_certificates(ca_id, profile)")
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_issued_certs_notafter ON issued_certificates(ca_id, not_after)")
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_revoked_certs_page ON revoked_certificates(ca_id, revoked_at, serial)")
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_discovered_certs_page ON discovered_certificates(tenant_id, discovered_at, id)")
	_, _ = db.conn.Exec("CREATE INDEX IF NOT EXISTS idx_discovered_certs_notafter ON discovered_certificates(tenant_id, not_after)")

	// Keyset pagination (Task 83) compares issued_certificates.created_at against a
	// bound time.Time. On SQLite timestamps are stored as text and compared
	// lexically, so a cursor only excludes its own row when the stored format
	// matches what the driver binds. Rows written before Task 83 relied on the
	// column DEFAULT (CURRENT_TIMESTAMP → "YYYY-MM-DD HH:MM:SS", no timezone),
	// whereas RecordIssuedCertificate now writes an explicit UTC time.Time
	// (rendered "…+00:00"). Normalize the legacy rows once by appending the UTC
	// offset so both formats sort and self-exclude consistently. Idempotent: a
	// legacy value never contains '+' or a trailing 'Z' (the driver renders the
	// explicit UTC time as "…+00:00"), so already-normalized rows are skipped.
	// PostgreSQL stores real timestamps and compares them temporally, so it needs
	// no normalization.
	if !db.isPostgres() {
		_, _ = db.conn.Exec(`UPDATE issued_certificates
			SET created_at = created_at || '+00:00'
			WHERE created_at IS NOT NULL
			  AND created_at NOT LIKE '%+%'
			  AND created_at NOT LIKE '%Z'`)
	}

	return nil
}

const (
	BuiltinPermitAllSSH  = "builtin-permit-all-ssh"
	BuiltinDenyAllSSH    = "builtin-deny-all-ssh"
	BuiltinPermitAllX509 = "builtin-permit-all-x509"
	BuiltinDenyAllX509   = "builtin-deny-all-x509"
)

// migrateRestrictionSets migrates data from old mixed restriction_sets table
// (which had SSH and X.509 columns together) to the new split detail tables.
func (db *DB) migrateRestrictionSets() {
	// Check if old columns exist by trying to select them
	rows, err := db.query(`SELECT id, type, allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset, allowed_key_usages, allowed_ext_key_usages, allowed_san_types, allowed_san_patterns, allowed_subject_fields, max_path_length, deny_ca FROM restriction_sets LIMIT 1`)
	if err != nil {
		return // Old columns don't exist, nothing to migrate
	}
	rows.Close()

	// Migrate SSH rows
	_, _ = db.conn.Exec(`INSERT OR IGNORE INTO ssh_restriction_details (restriction_set_id, allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset)
		SELECT id, allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset FROM restriction_sets WHERE type = 'ssh' OR type = ''`)
	// Migrate X.509 rows
	_, _ = db.conn.Exec(`INSERT OR IGNORE INTO x509_restriction_details (restriction_set_id, allowed_key_usages, allowed_ext_key_usages, allowed_san_types, allowed_san_patterns, allowed_subject_fields, max_path_length, deny_ca)
		SELECT id, allowed_key_usages, allowed_ext_key_usages, allowed_san_types, allowed_san_patterns, allowed_subject_fields, max_path_length, deny_ca FROM restriction_sets WHERE type = 'x509'`)
}

// insertOrIgnore returns the appropriate INSERT statement for the driver.
func (db *DB) insertOrIgnore(table, columns, placeholders string) string {
	if db.isPostgres() {
		return db.ph(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING", table, columns, placeholders))
	}
	return fmt.Sprintf("INSERT OR IGNORE INTO %s (%s) VALUES (%s)", table, columns, placeholders)
}

// upsert returns an INSERT ... ON CONFLICT DO UPDATE for the driver.
func (db *DB) upsert(table, columns, placeholders, conflictCols, updateSet string) string {
	if db.isPostgres() {
		return db.ph(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s", table, columns, placeholders, conflictCols, updateSet))
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s", table, columns, placeholders, conflictCols, updateSet)
}

// CA operations

// caColumns is the canonical column list for CA reads. Keep it in sync with
// scanCA.
const caColumns = `id, tenant_id, parent_id, label, pkcs11_uri, key_type, public_key,
	default_ssh_restriction_set_id, default_x509_restriction_set_id,
	certificate, subject, serial, not_before, not_after, max_path_len,
	status, successor_id, predecessor_id, retire_after, csr, external_chain, created_at`

// caScanner is the minimal surface shared by *sql.Row and *sql.Rows.
type caScanner interface {
	Scan(dest ...interface{}) error
}

// scanCA reads a single CA row selected with caColumns.
func scanCA(s caScanner) (*models.CA, error) {
	var ca models.CA
	var pubBlob []byte
	var tenantID, cert, subject, serial, status sql.NullString
	var successorID, predecessorID, csr, externalChain sql.NullString
	var notBefore, notAfter, retireAfter sql.NullTime
	var maxPathLen sql.NullInt64
	if err := s.Scan(
		&ca.ID, &tenantID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &pubBlob,
		&ca.DefaultSSHRestrictionSetID, &ca.DefaultX509RestrictionSetID,
		&cert, &subject, &serial, &notBefore, &notAfter, &maxPathLen,
		&status, &successorID, &predecessorID, &retireAfter, &csr, &externalChain, &ca.CreatedAt,
	); err != nil {
		return nil, err
	}
	if csr.Valid {
		ca.CSR = csr.String
	}
	if externalChain.Valid {
		ca.ExternalChain = externalChain.String
	}
	if tenantID.Valid && tenantID.String != "" {
		ca.TenantID = tenantID.String
	} else {
		ca.TenantID = models.DefaultTenantID
	}
	ca.PublicKey = blobToAuthorizedKey(pubBlob)
	if cert.Valid {
		ca.Certificate = cert.String
	}
	if subject.Valid {
		ca.Subject = subject.String
	}
	if serial.Valid {
		ca.Serial = serial.String
	}
	if notBefore.Valid {
		t := notBefore.Time
		ca.NotBefore = &t
	}
	if notAfter.Valid {
		t := notAfter.Time
		ca.NotAfter = &t
	}
	if maxPathLen.Valid {
		v := int(maxPathLen.Int64)
		ca.MaxPathLen = &v
	}
	if status.Valid && status.String != "" {
		ca.Status = status.String
	} else {
		ca.Status = models.CAStatusActive
	}
	if successorID.Valid && successorID.String != "" {
		v := successorID.String
		ca.SuccessorID = &v
	}
	if predecessorID.Valid && predecessorID.String != "" {
		v := predecessorID.String
		ca.PredecessorID = &v
	}
	if retireAfter.Valid {
		t := retireAfter.Time
		ca.RetireAfter = &t
	}
	return &ca, nil
}

// nullString returns a NULL-able string, treating "" as NULL.
func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// CreateCA inserts a CA and initializes its serial counter atomically. The
// counter starts at 2, reserving serial 1 for a CA's own self-issued material.
func (db *DB) CreateCA(ca *models.CA) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var notBefore, notAfter interface{}
	if ca.NotBefore != nil {
		notBefore = *ca.NotBefore
	}
	if ca.NotAfter != nil {
		notAfter = *ca.NotAfter
	}
	var maxPathLen interface{}
	if ca.MaxPathLen != nil {
		maxPathLen = *ca.MaxPathLen
	}
	var retireAfter interface{}
	if ca.RetireAfter != nil {
		retireAfter = *ca.RetireAfter
	}
	status := ca.Status
	if status == "" {
		status = models.CAStatusActive
	}
	tenantID := ca.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}

	if _, err := tx.Exec(db.ph(
		`INSERT INTO cas (id, tenant_id, parent_id, label, pkcs11_uri, key_type, public_key,
			default_ssh_restriction_set_id, default_x509_restriction_set_id,
			certificate, subject, serial, not_before, not_after, max_path_len,
			status, successor_id, predecessor_id, retire_after, csr, external_chain)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		ca.ID, tenantID, ca.ParentID, ca.Label, ca.PKCS11URI, ca.KeyType, pubKeyToBlob(ca.PublicKey),
		ca.DefaultSSHRestrictionSetID, ca.DefaultX509RestrictionSetID,
		nullString(ca.Certificate), nullString(ca.Subject), nullString(ca.Serial),
		notBefore, notAfter, maxPathLen,
		status, ca.SuccessorID, ca.PredecessorID, retireAfter,
		nullString(ca.CSR), nullString(ca.ExternalChain),
	); err != nil {
		return err
	}

	if _, err := tx.Exec(db.ph(
		`INSERT INTO ca_serial_counters (ca_id, next_serial) VALUES (?, ?)`), ca.ID, 2); err != nil {
		return err
	}
	if _, err := tx.Exec(db.ph(
		`INSERT INTO ca_crl_counters (ca_id, next_number) VALUES (?, ?)`), ca.ID, 1); err != nil {
		return err
	}
	return tx.Commit()
}

// AllocateSerial atomically returns the next unused certificate serial number
// for certificates issued by the given CA and advances the counter. Serials are
// unique per issuing CA.
func (db *DB) AllocateSerial(caID string) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var next int64
	err = tx.QueryRow(db.ph(`SELECT next_serial FROM ca_serial_counters WHERE ca_id = ?`+db.forUpdate()), caID).Scan(&next)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("no serial counter for CA %q", caID)
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(db.ph(`UPDATE ca_serial_counters SET next_serial = ? WHERE ca_id = ?`), next+1, caID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

func (db *DB) GetCA(id string) (*models.CA, error) {
	ca, err := scanCA(db.queryRow(`SELECT `+caColumns+` FROM cas WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ca, err
}

// GetCAByLabel resolves a CA by its label. Returns (nil, nil) if none matches.
func (db *DB) GetCAByLabel(label string) (*models.CA, error) {
	ca, err := scanCA(db.queryRow(`SELECT `+caColumns+` FROM cas WHERE label = ?`, label))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ca, err
}

func (db *DB) ListCAs() ([]models.CA, error) {
	rows, err := db.query(`SELECT ` + caColumns + ` FROM cas`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		cas = append(cas, *ca)
	}
	return cas, rows.Err()
}

// ListCAsForTenant returns only the CAs owned by the given tenant. It is the
// tenant-scoped read path used by the API so a principal never sees another
// tenant's authorities.
func (db *DB) ListCAsForTenant(tenantID string) ([]models.CA, error) {
	rows, err := db.query(`SELECT `+caColumns+` FROM cas WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		cas = append(cas, *ca)
	}
	return cas, rows.Err()
}

// GetCATenant resolves the owning tenant of a CA by its ID. It returns
// ("", nil) when the CA does not exist. This is the cheap lookup used to
// authorize CA-scoped requests against the caller's tenant memberships.
func (db *DB) GetCATenant(caID string) (string, error) {
	var tenantID sql.NullString
	err := db.queryRow(`SELECT tenant_id FROM cas WHERE id = ?`, caID).Scan(&tenantID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !tenantID.Valid || tenantID.String == "" {
		return models.DefaultTenantID, nil
	}
	return tenantID.String, nil
}

func (db *DB) DeleteCA(id string) error {
	_, err := db.exec(`DELETE FROM cas WHERE id = ?`, id)
	return err
}

// MarkCARotated records a completed intermediate-CA key rollover atomically: the
// old CA is marked superseded and pointed at its successor with a retire-after
// deadline, and the new CA is pointed back at its predecessor. Both rows are
// updated in one transaction so a rollover never leaves a half-linked pair.
func (db *DB) MarkCARotated(oldID, newID string, retireAfter *time.Time) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var retire interface{}
	if retireAfter != nil {
		retire = *retireAfter
	}
	if _, err := tx.Exec(db.ph(
		`UPDATE cas SET status = ?, successor_id = ?, retire_after = ? WHERE id = ?`),
		models.CAStatusSuperseded, newID, retire, oldID); err != nil {
		return err
	}
	if _, err := tx.Exec(db.ph(
		`UPDATE cas SET predecessor_id = ? WHERE id = ?`), oldID, newID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetCAStatus updates a CA's rollover lifecycle status (see models.CAStatus*).
func (db *DB) SetCAStatus(id, status string) error {
	_, err := db.exec(`UPDATE cas SET status = ? WHERE id = ?`, status, id)
	return err
}

// InstallCACertificate installs an externally signed certificate on a CA in one
// atomic update: the certificate and its parsed metadata (subject, serial,
// validity, path-length constraint), the imported external issuing chain, and
// the new lifecycle status (pending → active). It is the persistence half of
// the externally-signed subordinate CA flow; validation happens in the ca
// package before this is called.
func (db *DB) InstallCACertificate(id, certificate, subject, serial string, notBefore, notAfter time.Time, maxPathLen *int, externalChain, status string) error {
	var mpl interface{}
	if maxPathLen != nil {
		mpl = *maxPathLen
	}
	res, err := db.exec(
		`UPDATE cas SET certificate = ?, subject = ?, serial = ?, not_before = ?, not_after = ?,
			max_path_len = ?, external_chain = ?, status = ? WHERE id = ?`,
		certificate, subject, serial, notBefore, notAfter, mpl, nullString(externalChain), status, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("CA %q not found", id)
	}
	return nil
}

func (db *DB) SetCADefaultRestrictionSet(caID string, rsType string, rsID *string) error {
	col := "default_ssh_restriction_set_id"
	if rsType == "x509" {
		col = "default_x509_restriction_set_id"
	}
	_, err := db.exec(fmt.Sprintf(`UPDATE cas SET %s = ? WHERE id = ?`, col), rsID, caID)
	return err
}

func (db *DB) GetChildren(parentID string) ([]models.CA, error) {
	rows, err := db.query(`SELECT `+caColumns+` FROM cas WHERE parent_id = ?`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		cas = append(cas, *ca)
	}
	return cas, rows.Err()
}

// Cross-sign operations (Task 47)

// crossSignColumns is the canonical column list for cross-sign reads. Keep it in
// sync with scanCrossSign.
const crossSignColumns = `id, tenant_id, issuer_ca_id, subject_ca_id, subject_key_id,
	subject, serial, certificate, not_before, not_after, source, status,
	requested_by, created_at`

// scanCrossSign reads a single cross_signs row selected with crossSignColumns.
func scanCrossSign(s caScanner) (*models.CrossSign, error) {
	var cs models.CrossSign
	var tenantID, subjectCAID, requestedBy sql.NullString
	if err := s.Scan(
		&cs.ID, &tenantID, &cs.IssuerCAID, &subjectCAID, &cs.SubjectKeyID,
		&cs.Subject, &cs.Serial, &cs.Certificate, &cs.NotBefore, &cs.NotAfter,
		&cs.Source, &cs.Status, &requestedBy, &cs.CreatedAt,
	); err != nil {
		return nil, err
	}
	if tenantID.Valid && tenantID.String != "" {
		cs.TenantID = tenantID.String
	} else {
		cs.TenantID = models.DefaultTenantID
	}
	if subjectCAID.Valid && subjectCAID.String != "" {
		v := subjectCAID.String
		cs.SubjectCAID = &v
	}
	if requestedBy.Valid {
		cs.RequestedBy = requestedBy.String
	}
	if cs.Status == "" {
		cs.Status = models.CrossSignStatusActive
	}
	return &cs, nil
}

// CreateCrossSign persists a new cross-signing relationship.
func (db *DB) CreateCrossSign(cs *models.CrossSign) error {
	tenantID := cs.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	status := cs.Status
	if status == "" {
		status = models.CrossSignStatusActive
	}
	_, err := db.exec(db.ph(
		`INSERT INTO cross_signs (id, tenant_id, issuer_ca_id, subject_ca_id, subject_key_id,
			subject, serial, certificate, not_before, not_after, source, status, requested_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		cs.ID, tenantID, cs.IssuerCAID, cs.SubjectCAID, cs.SubjectKeyID,
		cs.Subject, cs.Serial, cs.Certificate, cs.NotBefore, cs.NotAfter,
		cs.Source, status, nullString(cs.RequestedBy))
	return err
}

// GetCrossSign resolves a cross-sign by id. Returns (nil, nil) if none matches.
func (db *DB) GetCrossSign(id string) (*models.CrossSign, error) {
	cs, err := scanCrossSign(db.queryRow(`SELECT `+crossSignColumns+` FROM cross_signs WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return cs, err
}

func (db *DB) listCrossSigns(where string, arg string) ([]models.CrossSign, error) {
	rows, err := db.query(`SELECT `+crossSignColumns+` FROM cross_signs WHERE `+where+` ORDER BY created_at`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CrossSign
	for rows.Next() {
		cs, err := scanCrossSign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cs)
	}
	return out, rows.Err()
}

// ListCrossSignsForSubjectKey returns every cross-sign certifying the given SKI.
func (db *DB) ListCrossSignsForSubjectKey(subjectKeyID string) ([]models.CrossSign, error) {
	return db.listCrossSigns("subject_key_id = ?", subjectKeyID)
}

// ListCrossSignsBySubjectCA returns cross-signs whose subject is the given CA.
func (db *DB) ListCrossSignsBySubjectCA(subjectCAID string) ([]models.CrossSign, error) {
	return db.listCrossSigns("subject_ca_id = ?", subjectCAID)
}

// ListCrossSignsByIssuer returns cross-signs an issuer CA has produced.
func (db *DB) ListCrossSignsByIssuer(issuerCAID string) ([]models.CrossSign, error) {
	return db.listCrossSigns("issuer_ca_id = ?", issuerCAID)
}

// SetCrossSignStatus updates a cross-sign's lifecycle status.
func (db *DB) SetCrossSignStatus(id, status string) error {
	_, err := db.exec(`UPDATE cross_signs SET status = ? WHERE id = ?`, status, id)
	return err
}

// Group operations

func (db *DB) CreateGroup(g *models.Group) error {
	tenantID := g.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	_, err := db.exec(`INSERT INTO groups_ (id, tenant_id, name) VALUES (?, ?, ?)`, g.ID, tenantID, g.Name)
	return err
}

func scanGroup(s caScanner) (*models.Group, error) {
	g := &models.Group{}
	var tenantID sql.NullString
	if err := s.Scan(&g.ID, &tenantID, &g.Name); err != nil {
		return nil, err
	}
	if tenantID.Valid && tenantID.String != "" {
		g.TenantID = tenantID.String
	} else {
		g.TenantID = models.DefaultTenantID
	}
	return g, nil
}

func (db *DB) GetGroup(id string) (*models.Group, error) {
	g, err := scanGroup(db.queryRow(`SELECT id, tenant_id, name FROM groups_ WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return g, err
}

func (db *DB) ListGroups() ([]models.Group, error) {
	return db.listGroupsWhere("")
}

// ListGroupsForTenant returns only the groups owned by the given tenant.
func (db *DB) ListGroupsForTenant(tenantID string) ([]models.Group, error) {
	return db.listGroupsWhere(tenantID)
}

func (db *DB) listGroupsWhere(tenantID string) ([]models.Group, error) {
	q := `SELECT id, tenant_id, name FROM groups_`
	var args []interface{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []models.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, *g)
	}
	return groups, rows.Err()
}

func (db *DB) DeleteGroup(id string) error {
	_, err := db.exec(`DELETE FROM groups_ WHERE id = ?`, id)
	return err
}

func (db *DB) AddGroupMember(groupID, userSub string) error {
	_, err := db.conn.Exec(db.insertOrIgnore("group_members", "group_id, user_sub", "?, ?"), groupID, userSub)
	return err
}

func (db *DB) RemoveGroupMember(groupID, userSub string) error {
	_, err := db.exec(`DELETE FROM group_members WHERE group_id = ? AND user_sub = ?`, groupID, userSub)
	return err
}

func (db *DB) GetGroupMembers(groupID string) ([]string, error) {
	rows, err := db.query(`SELECT user_sub FROM group_members WHERE group_id = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subs []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

func (db *DB) GetUserGroups(userSub string) ([]string, error) {
	rows, err := db.query(`SELECT group_id FROM group_members WHERE user_sub = ?`, userSub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Permission operations

func (db *DB) GrantPermission(p *models.PermissionEntry) error {
	_, err := db.exec(
		`INSERT INTO permissions (id, ca_id, entity_type, entity_id, permission, ssh_restriction_set_id, x509_restriction_set_id) VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(ca_id, entity_type, entity_id, permission) DO UPDATE SET ssh_restriction_set_id = excluded.ssh_restriction_set_id, x509_restriction_set_id = excluded.x509_restriction_set_id`,
		p.ID, p.CAID, p.EntityType, p.EntityID, p.Permission, p.SSHRestrictionSetID, p.X509RestrictionSetID,
	)
	return err
}

func (db *DB) RevokePermission(caID, entityType, entityID string, perm models.Permission) error {
	_, err := db.exec(
		`DELETE FROM permissions WHERE ca_id = ? AND entity_type = ? AND entity_id = ? AND permission = ?`,
		caID, entityType, entityID, perm,
	)
	return err
}

func (db *DB) GetPermissions(caID string) ([]models.PermissionEntry, error) {
	rows, err := db.query(
		`SELECT id, ca_id, entity_type, entity_id, permission, ssh_restriction_set_id, x509_restriction_set_id FROM permissions WHERE ca_id = ?`, caID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var perms []models.PermissionEntry
	for rows.Next() {
		var p models.PermissionEntry
		if err := rows.Scan(&p.ID, &p.CAID, &p.EntityType, &p.EntityID, &p.Permission, &p.SSHRestrictionSetID, &p.X509RestrictionSetID); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (db *DB) HasPermission(caID, userSub string, perm models.Permission, groupIDs []string) (bool, error) {
	var count int
	err := db.queryRow(
		`SELECT COUNT(*) FROM permissions WHERE ca_id = ? AND entity_type = 'user' AND entity_id = ? AND permission = ?`,
		caID, userSub, perm,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	for _, gid := range groupIDs {
		err := db.queryRow(
			`SELECT COUNT(*) FROM permissions WHERE ca_id = ? AND entity_type = 'group' AND entity_id = ? AND permission = ?`,
			caID, gid, perm,
		).Scan(&count)
		if err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}

	return false, nil
}

// GetEffectiveRestrictionSet returns the restriction set that applies to this user for SIGN_CERTIFICATE on a CA.
// certFormat is "ssh" or "x509". Priority: user-specific > group-specific > CA default.
func (db *DB) GetEffectiveRestrictionSet(caID, userSub string, groupIDs []string, certFormat string) (*models.RestrictionSet, error) {
	col := "ssh_restriction_set_id"
	defaultCol := "default_ssh_restriction_set_id"
	if certFormat == "x509" {
		col = "x509_restriction_set_id"
		defaultCol = "default_x509_restriction_set_id"
	}

	// Check user-specific SIGN_CERTIFICATE permission
	var rsID sql.NullString
	err := db.queryRow(
		fmt.Sprintf(`SELECT %s FROM permissions WHERE ca_id = ? AND entity_type = 'user' AND entity_id = ? AND permission = 'SIGN_CERTIFICATE' AND %s IS NOT NULL`, col, col),
		caID, userSub,
	).Scan(&rsID)
	if err == nil && rsID.Valid {
		return db.GetRestrictionSet(rsID.String)
	}

	// Check group-specific
	for _, gid := range groupIDs {
		err := db.queryRow(
			fmt.Sprintf(`SELECT %s FROM permissions WHERE ca_id = ? AND entity_type = 'group' AND entity_id = ? AND permission = 'SIGN_CERTIFICATE' AND %s IS NOT NULL`, col, col),
			caID, gid,
		).Scan(&rsID)
		if err == nil && rsID.Valid {
			return db.GetRestrictionSet(rsID.String)
		}
	}

	// Fall back to CA default
	var defaultID sql.NullString
	err = db.queryRow(fmt.Sprintf(`SELECT %s FROM cas WHERE id = ?`, defaultCol), caID).Scan(&defaultID)
	if err == nil && defaultID.Valid {
		return db.GetRestrictionSet(defaultID.String)
	}

	return nil, nil
}

// Restriction set operations

type marshaledRS struct {
	principals, certTypes, extensions                             string
	forceEmail, requireReason, denyExt, denyCrit, denyCa          int
	keyUsages, extKeyUsages, sanTypes, sanPatterns, subjectFields string
}

func (db *DB) marshalRS(rs *models.RestrictionSet) marshaledRS {
	m := marshaledRS{}
	p, _ := json.Marshal(rs.AllowedPrincipals)
	c, _ := json.Marshal(rs.AllowedCertTypes)
	e, _ := json.Marshal(rs.AllowedExtensions)
	m.principals, m.certTypes, m.extensions = string(p), string(c), string(e)
	if rs.ForceKeyIDEmail {
		m.forceEmail = 1
	}
	if rs.RequireReason {
		m.requireReason = 1
	}
	if rs.DenyExtensions {
		m.denyExt = 1
	}
	if rs.DenyCriticalOptions {
		m.denyCrit = 1
	}
	if rs.DenyCA {
		m.denyCa = 1
	}

	ku, _ := json.Marshal(rs.AllowedKeyUsages)
	eku, _ := json.Marshal(rs.AllowedExtKeyUsages)
	st, _ := json.Marshal(rs.AllowedSANTypes)
	sp, _ := json.Marshal(rs.AllowedSANPatterns)
	sf, _ := json.Marshal(rs.AllowedSubjectFields)
	m.keyUsages, m.extKeyUsages, m.sanTypes, m.sanPatterns, m.subjectFields = string(ku), string(eku), string(st), string(sp), string(sf)
	return m
}

func (db *DB) CreateRestrictionSet(rs *models.RestrictionSet) error {
	if rs.Type == "" {
		rs.Type = models.RestrictionSetSSH
	}
	var caID interface{} = rs.CAID
	if rs.CAID == "" {
		caID = nil
	}
	denyAll := 0
	if rs.DenyAll {
		denyAll = 1
	}
	_, err := db.exec(
		`INSERT INTO restriction_sets (id, tenant_id, ca_id, name, type, max_validity_secs, deny_all) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rs.ID, nullString(rs.TenantID), caID, rs.Name, rs.Type, rs.MaxValiditySecs, denyAll,
	)
	if err != nil {
		return err
	}
	return db.upsertRestrictionDetails(rs)
}

func (db *DB) UpdateRestrictionSet(rs *models.RestrictionSet) error {
	denyAll := 0
	if rs.DenyAll {
		denyAll = 1
	}
	_, err := db.exec(
		`UPDATE restriction_sets SET name=?, type=?, max_validity_secs=?, deny_all=? WHERE id=?`,
		rs.Name, rs.Type, rs.MaxValiditySecs, denyAll, rs.ID,
	)
	if err != nil {
		return err
	}
	// Clean up old details and insert new
	_, _ = db.exec(`DELETE FROM ssh_restriction_details WHERE restriction_set_id = ?`, rs.ID)
	_, _ = db.exec(`DELETE FROM x509_restriction_details WHERE restriction_set_id = ?`, rs.ID)
	return db.upsertRestrictionDetails(rs)
}

func (db *DB) upsertRestrictionDetails(rs *models.RestrictionSet) error {
	m := db.marshalRS(rs)
	if rs.Type == models.RestrictionSetX509 {
		_, err := db.exec(
			`INSERT INTO x509_restriction_details (restriction_set_id, allowed_key_usages, allowed_ext_key_usages, allowed_san_types, allowed_san_patterns, allowed_subject_fields, max_path_length, deny_ca)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rs.ID, m.keyUsages, m.extKeyUsages, m.sanTypes, m.sanPatterns, m.subjectFields, rs.MaxPathLength, m.denyCa,
		)
		return err
	}
	_, err := db.exec(
		`INSERT INTO ssh_restriction_details (restriction_set_id, allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rs.ID, m.principals, m.certTypes, m.forceEmail, m.requireReason, m.extensions, m.denyExt, m.denyCrit, rs.MaxValidAfterOffset,
	)
	return err
}

func (db *DB) loadSSHDetails(rs *models.RestrictionSet) {
	var principals, certTypes, extensions sql.NullString
	var forceEmail, requireReason, denyExt, denyCrit int
	err := db.queryRow(
		`SELECT allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset FROM ssh_restriction_details WHERE restriction_set_id = ?`, rs.ID,
	).Scan(&principals, &certTypes, &forceEmail, &requireReason, &extensions, &denyExt, &denyCrit, &rs.MaxValidAfterOffset)
	if err != nil {
		return
	}
	rs.ForceKeyIDEmail = forceEmail != 0
	rs.RequireReason = requireReason != 0
	rs.DenyExtensions = denyExt != 0
	rs.DenyCriticalOptions = denyCrit != 0
	if principals.Valid {
		_ = json.Unmarshal([]byte(principals.String), &rs.AllowedPrincipals)
	}
	if certTypes.Valid {
		_ = json.Unmarshal([]byte(certTypes.String), &rs.AllowedCertTypes)
	}
	if extensions.Valid {
		_ = json.Unmarshal([]byte(extensions.String), &rs.AllowedExtensions)
	}
}

func (db *DB) loadX509Details(rs *models.RestrictionSet) {
	var keyUsages, extKeyUsages, sanTypes, sanPatterns, subjectFields sql.NullString
	var denyCa int
	err := db.queryRow(
		`SELECT allowed_key_usages, allowed_ext_key_usages, allowed_san_types, allowed_san_patterns, allowed_subject_fields, max_path_length, deny_ca FROM x509_restriction_details WHERE restriction_set_id = ?`, rs.ID,
	).Scan(&keyUsages, &extKeyUsages, &sanTypes, &sanPatterns, &subjectFields, &rs.MaxPathLength, &denyCa)
	if err != nil {
		return
	}
	rs.DenyCA = denyCa != 0
	if keyUsages.Valid {
		_ = json.Unmarshal([]byte(keyUsages.String), &rs.AllowedKeyUsages)
	}
	if extKeyUsages.Valid {
		_ = json.Unmarshal([]byte(extKeyUsages.String), &rs.AllowedExtKeyUsages)
	}
	if sanTypes.Valid {
		_ = json.Unmarshal([]byte(sanTypes.String), &rs.AllowedSANTypes)
	}
	if sanPatterns.Valid {
		_ = json.Unmarshal([]byte(sanPatterns.String), &rs.AllowedSANPatterns)
	}
	if subjectFields.Valid {
		_ = json.Unmarshal([]byte(subjectFields.String), &rs.AllowedSubjectFields)
	}
}

func (db *DB) GetRestrictionSet(id string) (*models.RestrictionSet, error) {
	var rs models.RestrictionSet
	var tenantID, caID sql.NullString
	var denyAll int
	err := db.queryRow(
		`SELECT id, tenant_id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets WHERE id = ?`, id,
	).Scan(&rs.ID, &tenantID, &caID, &rs.Name, &rs.Type, &rs.MaxValiditySecs, &denyAll)
	if tenantID.Valid {
		rs.TenantID = tenantID.String
	}
	if caID.Valid {
		rs.CAID = caID.String
	}
	rs.DenyAll = denyAll != 0
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rs.Type == "" {
		rs.Type = models.RestrictionSetSSH
	}
	if rs.Type == models.RestrictionSetX509 {
		db.loadX509Details(&rs)
	} else {
		db.loadSSHDetails(&rs)
	}
	return &rs, nil
}

func (db *DB) ListAllRestrictionSets() ([]models.RestrictionSet, error) {
	return db.scanRestrictionSets(db.query(`SELECT id, tenant_id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets`))
}

func (db *DB) ListRestrictionSets(caID string) ([]models.RestrictionSet, error) {
	return db.scanRestrictionSets(db.query(
		`SELECT id, tenant_id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets WHERE ca_id = ? OR ca_id IS NULL`, caID,
	))
}

// ListRestrictionSetsForTenant returns the restriction sets (issuance profiles)
// a tenant may use: its own sets plus the global built-ins (which have no
// tenant). A tenant never sees another tenant's custom restriction sets.
func (db *DB) ListRestrictionSetsForTenant(tenantID string) ([]models.RestrictionSet, error) {
	return db.scanRestrictionSets(db.query(
		`SELECT id, tenant_id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets WHERE tenant_id = ? OR tenant_id IS NULL`, tenantID,
	))
}

func (db *DB) scanRestrictionSets(rows *sql.Rows, err error) ([]models.RestrictionSet, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []models.RestrictionSet
	for rows.Next() {
		var rs models.RestrictionSet
		var tenantID, caID sql.NullString
		var denyAll int
		if err := rows.Scan(&rs.ID, &tenantID, &caID, &rs.Name, &rs.Type, &rs.MaxValiditySecs, &denyAll); err != nil {
			return nil, err
		}
		if tenantID.Valid {
			rs.TenantID = tenantID.String
		}
		if caID.Valid {
			rs.CAID = caID.String
		}
		rs.DenyAll = denyAll != 0
		if rs.Type == "" {
			rs.Type = models.RestrictionSetSSH
		}
		sets = append(sets, rs)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Load details for each set
	for i := range sets {
		if sets[i].Type == models.RestrictionSetX509 {
			db.loadX509Details(&sets[i])
		} else {
			db.loadSSHDetails(&sets[i])
		}
	}
	return sets, nil
}

func (db *DB) DeleteRestrictionSet(id string) error {
	// Clear references from CA defaults
	_, _ = db.exec(`UPDATE cas SET default_ssh_restriction_set_id = NULL WHERE default_ssh_restriction_set_id = ?`, id)
	_, _ = db.exec(`UPDATE cas SET default_x509_restriction_set_id = NULL WHERE default_x509_restriction_set_id = ?`, id)
	_, err := db.exec(`DELETE FROM restriction_sets WHERE id = ?`, id)
	return err
}

// pubKeyToBlob converts an SSH authorized_key string to raw wire-format bytes.
func pubKeyToBlob(authorizedKey string) []byte {
	if authorizedKey == "" {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(authorizedKey)))
	if err != nil {
		return []byte(authorizedKey) // fallback: store as-is if not parseable
	}
	return pub.Marshal()
}

// blobToAuthorizedKey converts raw SSH public key bytes to an authorized_key string.
func blobToAuthorizedKey(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return string(blob) // fallback: return as-is if not parseable
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// certBlobToAuthorizedKey converts raw SSH certificate bytes to an authorized_key string.
func certBlobToAuthorizedKey(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// Audit log operations

func (db *DB) CreateAuditLogEntry(e *models.AuditLogEntry) error {
	principals, _ := json.Marshal(e.Principals)
	extensions, _ := json.Marshal(e.Extensions)
	critOpts, _ := json.Marshal(e.CriticalOptions)

	// Convert public key and certificate to raw wire-format bytes
	pubKeyBlob := pubKeyToBlob(e.PublicKey)

	var certBlob []byte
	var certHash *string
	if e.Certificate != "" {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(e.Certificate))); err == nil {
			certBlob = pub.Marshal()
			h := sha256.Sum256(certBlob)
			s := hex.EncodeToString(h[:])
			certHash = &s
		}
	}

	_, err := db.exec(
		`INSERT INTO audit_log (id, user_sub, user_email, user_name, ca_id, ca_label, key_id, cert_type, principals, valid_after, valid_before, extensions, critical_options, public_key, certificate, cert_hash, restriction_set_id, serial)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.UserSub, e.UserEmail, e.UserName, e.CAID, e.CALabel, e.KeyID, e.CertType,
		string(principals), e.ValidAfter, e.ValidBefore, string(extensions), string(critOpts),
		pubKeyBlob, certBlob, certHash, e.RestrictionSetID, e.Serial,
	)
	return err
}

func (db *DB) FindExistingCertificate(caID, publicKey string) (*models.AuditLogEntry, error) {
	var e models.AuditLogEntry
	var principals, extensions, critOpts sql.NullString
	var pubBlob, certBlob []byte
	err := db.queryRow(
		`SELECT id, timestamp, user_sub, user_email, user_name, ca_id, ca_label, key_id, cert_type, principals, valid_after, valid_before, extensions, critical_options, public_key, certificate, restriction_set_id, serial
		 FROM audit_log WHERE ca_id = ? AND public_key = ? AND certificate IS NOT NULL ORDER BY timestamp DESC LIMIT 1`,
		caID, pubKeyToBlob(publicKey),
	).Scan(&e.ID, &e.Timestamp, &e.UserSub, &e.UserEmail, &e.UserName, &e.CAID, &e.CALabel, &e.KeyID, &e.CertType, &principals, &e.ValidAfter, &e.ValidBefore, &extensions, &critOpts, &pubBlob, &certBlob, &e.RestrictionSetID, &e.Serial)
	e.PublicKey = blobToAuthorizedKey(pubBlob)
	e.Certificate = certBlobToAuthorizedKey(certBlob)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if principals.Valid {
		_ = json.Unmarshal([]byte(principals.String), &e.Principals)
	}
	if extensions.Valid {
		_ = json.Unmarshal([]byte(extensions.String), &e.Extensions)
	}
	if critOpts.Valid {
		_ = json.Unmarshal([]byte(critOpts.String), &e.CriticalOptions)
	}
	return &e, nil
}

func (db *DB) ListAuditLog(caID string, limit, offset int) ([]models.AuditLogEntry, int, error) {
	// Count total
	var total int
	countQuery := `SELECT COUNT(*) FROM audit_log`
	args := []interface{}{}
	if caID != "" {
		countQuery += ` WHERE ca_id = ?`
		args = append(args, caID)
	}
	if err := db.queryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, timestamp, user_sub, user_email, user_name, ca_id, ca_label, key_id, cert_type, principals, valid_after, valid_before, extensions, critical_options, public_key, certificate, restriction_set_id, serial FROM audit_log`
	queryArgs := []interface{}{}
	if caID != "" {
		query += ` WHERE ca_id = ?`
		queryArgs = append(queryArgs, caID)
	}
	query += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	queryArgs = append(queryArgs, limit, offset)

	rows, err := db.query(query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.AuditLogEntry
	for rows.Next() {
		var e models.AuditLogEntry
		var principals, extensions, critOpts sql.NullString
		var pubBlob, certBlob []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserSub, &e.UserEmail, &e.UserName, &e.CAID, &e.CALabel, &e.KeyID, &e.CertType, &principals, &e.ValidAfter, &e.ValidBefore, &extensions, &critOpts, &pubBlob, &certBlob, &e.RestrictionSetID, &e.Serial); err != nil {
			return nil, 0, err
		}
		e.PublicKey = blobToAuthorizedKey(pubBlob)
		e.Certificate = certBlobToAuthorizedKey(certBlob)
		if principals.Valid {
			_ = json.Unmarshal([]byte(principals.String), &e.Principals)
		}
		if extensions.Valid {
			_ = json.Unmarshal([]byte(extensions.String), &e.Extensions)
		}
		if critOpts.Valid {
			_ = json.Unmarshal([]byte(critOpts.String), &e.CriticalOptions)
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// Access log operations

func (db *DB) CreateAccessLogEntry(e *models.AccessLogEntry) error {
	_, err := db.exec(
		`INSERT INTO access_log (id, user_sub, method, path, status, ip, request_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.UserSub, e.Method, e.Path, e.Status, e.IP, nullString(e.RequestID),
	)
	return err
}

func (db *DB) ListAccessLog(limit, offset int) ([]models.AccessLogEntry, int, error) {
	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM access_log`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.query(
		`SELECT id, timestamp, user_sub, method, path, status, ip, request_id FROM access_log ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.AccessLogEntry
	for rows.Next() {
		var e models.AccessLogEntry
		var requestID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserSub, &e.Method, &e.Path, &e.Status, &e.IP, &requestID); err != nil {
			return nil, 0, err
		}
		e.RequestID = requestID.String
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// HSM audit entry operations

func (db *DB) StoreHSMAuditEntries(entries []models.HSMAuditEntry) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		db.insertOrIgnore("hsm_audit_entries", "number, command, length, session_key, target_key, second_key, result, tick, hash, sign_audit_id", "?, ?, ?, ?, ?, ?, ?, ?, ?, ?"))
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, e := range entries {
		_, err := stmt.Exec(e.Number, e.Command, e.Length, e.SessionKey, e.TargetKey, e.SecondKey, e.Result, e.Tick, e.Hash, e.SignAuditID)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) LinkLatestHSMSignEntry(signAuditID string) error {
	_, err := db.exec(
		`UPDATE hsm_audit_entries SET sign_audit_id = ?
		 WHERE id = (SELECT id FROM hsm_audit_entries WHERE sign_audit_id IS NULL AND command IN (?, ?, ?, ?, ?) ORDER BY number DESC LIMIT 1)`,
		signAuditID, 0x56, 0x6a, 0x47, 0x55, 0x46,
	)
	return err
}

func (db *DB) ExportCombinedAuditLog() (*models.CombinedAuditExport, error) {
	rows, err := db.query(
		`SELECT number, command, length, session_key, target_key, second_key, result, tick, hash, sign_audit_id FROM hsm_audit_entries ORDER BY number ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hsmEntries []models.HSMAuditEntry
	for rows.Next() {
		var e models.HSMAuditEntry
		if err := rows.Scan(&e.Number, &e.Command, &e.Length, &e.SessionKey, &e.TargetKey, &e.SecondKey, &e.Result, &e.Tick, &e.Hash, &e.SignAuditID); err != nil {
			return nil, err
		}
		hsmEntries = append(hsmEntries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	signOps, _, err := db.ListAuditLog("", 100000, 0)
	if err != nil {
		return nil, err
	}

	return &models.CombinedAuditExport{
		HSMEntries: hsmEntries,
		SignOps:    signOps,
	}, nil
}
