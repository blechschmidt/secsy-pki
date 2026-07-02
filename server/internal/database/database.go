package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

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
	eventMu sync.Mutex
}

func New(driver, dsn string) (*DB, error) {
	driverName := driver
	if driverName == "sqlite" {
		driverName = "sqlite3"
	}
	conn, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if driver == "sqlite" || driver == "sqlite3" {
		conn.SetMaxOpenConns(1)
		if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
			return nil, fmt.Errorf("setting journal mode: %w", err)
		}
		if _, err := conn.Exec("PRAGMA foreign_keys=ON"); err != nil {
			return nil, fmt.Errorf("enabling foreign keys: %w", err)
		}
	}
	db := &DB{conn: conn, driver: driver}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrating: %w", err)
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

func (db *DB) Close() error {
	return db.conn.Close()
}

// Ping verifies the database connection is alive, for readiness checks. It uses
// PingContext so a hung backend cannot block the probe past the caller's
// deadline.
func (db *DB) Ping(ctx context.Context) error {
	return db.conn.PingContext(ctx)
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
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS cas (
			id TEXT PRIMARY KEY,
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
			UNIQUE(ca_id, serial)
		)`, currentTimestamp),
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
		`CREATE TABLE IF NOT EXISTS groups_ (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE
		)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL REFERENCES groups_(id) ON DELETE CASCADE,
			user_sub TEXT NOT NULL,
			PRIMARY KEY (group_id, user_sub)
		)`,
		`CREATE TABLE IF NOT EXISTS restriction_sets (
			id TEXT PRIMARY KEY,
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
	}
	for _, stmt := range stmts {
		if _, err := db.exec(stmt); err != nil {
			return fmt.Errorf("executing %q: %w", stmt[:40], err)
		}
	}
	// Migration: add columns if they don't exist (for existing databases)
	// These are idempotent — errors are ignored for columns that already exist
	if db.isPostgres() {
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS default_ssh_restriction_set_id TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS default_x509_restriction_set_id TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS certificate TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS subject TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS serial TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS not_before TIMESTAMP")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS not_after TIMESTAMP")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN IF NOT EXISTS max_path_len INTEGER")
		db.conn.Exec("ALTER TABLE permissions ADD COLUMN IF NOT EXISTS ssh_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		db.conn.Exec("ALTER TABLE permissions ADD COLUMN IF NOT EXISTS x509_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		db.conn.Exec("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS certificate BYTEA")
		db.conn.Exec("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS cert_hash TEXT")
		// Observability: correlate access/audit rows with the request log.
		db.conn.Exec("ALTER TABLE access_log ADD COLUMN IF NOT EXISTS request_id TEXT")
		db.conn.Exec("ALTER TABLE event_log ADD COLUMN IF NOT EXISTS request_id TEXT")
	} else {
		db.conn.Exec("ALTER TABLE cas ADD COLUMN default_ssh_restriction_set_id TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN default_x509_restriction_set_id TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN certificate TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN subject TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN serial TEXT")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN not_before TIMESTAMP")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN not_after TIMESTAMP")
		db.conn.Exec("ALTER TABLE cas ADD COLUMN max_path_len INTEGER")
		db.conn.Exec("ALTER TABLE permissions ADD COLUMN ssh_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		db.conn.Exec("ALTER TABLE permissions ADD COLUMN x509_restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
		db.conn.Exec("ALTER TABLE audit_log ADD COLUMN certificate BLOB")
		db.conn.Exec("ALTER TABLE audit_log ADD COLUMN cert_hash TEXT")
		// Observability: correlate access/audit rows with the request log.
		db.conn.Exec("ALTER TABLE access_log ADD COLUMN request_id TEXT")
		db.conn.Exec("ALTER TABLE event_log ADD COLUMN request_id TEXT")
	}

	// ACME (RFC 8555) server tables.
	if err := db.migrateACME(); err != nil {
		return err
	}

	// Migrate old mixed restriction_sets table to split tables (if old columns exist)
	db.migrateRestrictionSets()
	db.conn.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_cert_unique ON audit_log(ca_id, cert_hash)")

	// Create built-in restriction sets
	db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinPermitAllSSH, "Permit all signatures", "ssh", 0)
	db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinDenyAllSSH, "Disallow all signatures", "ssh", 1)
	db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinPermitAllX509, "Permit all signatures", "x509", 0)
	db.exec(db.insertOrIgnore("restriction_sets", "id, name, type, deny_all", "?, ?, ?, ?"),
		BuiltinDenyAllX509, "Disallow all signatures", "x509", 1)

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
	db.conn.Exec(`INSERT OR IGNORE INTO ssh_restriction_details (restriction_set_id, allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset)
		SELECT id, allowed_principals, allowed_cert_types, force_key_id_email_reason, require_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset FROM restriction_sets WHERE type = 'ssh' OR type = ''`)
	// Migrate X.509 rows
	db.conn.Exec(`INSERT OR IGNORE INTO x509_restriction_details (restriction_set_id, allowed_key_usages, allowed_ext_key_usages, allowed_san_types, allowed_san_patterns, allowed_subject_fields, max_path_length, deny_ca)
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
const caColumns = `id, parent_id, label, pkcs11_uri, key_type, public_key,
	default_ssh_restriction_set_id, default_x509_restriction_set_id,
	certificate, subject, serial, not_before, not_after, max_path_len, created_at`

// caScanner is the minimal surface shared by *sql.Row and *sql.Rows.
type caScanner interface {
	Scan(dest ...interface{}) error
}

// scanCA reads a single CA row selected with caColumns.
func scanCA(s caScanner) (*models.CA, error) {
	var ca models.CA
	var pubBlob []byte
	var cert, subject, serial sql.NullString
	var notBefore, notAfter sql.NullTime
	var maxPathLen sql.NullInt64
	if err := s.Scan(
		&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &pubBlob,
		&ca.DefaultSSHRestrictionSetID, &ca.DefaultX509RestrictionSetID,
		&cert, &subject, &serial, &notBefore, &notAfter, &maxPathLen, &ca.CreatedAt,
	); err != nil {
		return nil, err
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
	defer tx.Rollback()

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

	if _, err := tx.Exec(db.ph(
		`INSERT INTO cas (id, parent_id, label, pkcs11_uri, key_type, public_key,
			default_ssh_restriction_set_id, default_x509_restriction_set_id,
			certificate, subject, serial, not_before, not_after, max_path_len)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		ca.ID, ca.ParentID, ca.Label, ca.PKCS11URI, ca.KeyType, pubKeyToBlob(ca.PublicKey),
		ca.DefaultSSHRestrictionSetID, ca.DefaultX509RestrictionSetID,
		nullString(ca.Certificate), nullString(ca.Subject), nullString(ca.Serial),
		notBefore, notAfter, maxPathLen,
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
	err = tx.QueryRow(db.ph(`SELECT next_serial FROM ca_serial_counters WHERE ca_id = ?`), caID).Scan(&next)
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

func (db *DB) DeleteCA(id string) error {
	_, err := db.exec(`DELETE FROM cas WHERE id = ?`, id)
	return err
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

// Group operations

func (db *DB) CreateGroup(g *models.Group) error {
	_, err := db.exec(`INSERT INTO groups_ (id, name) VALUES (?, ?)`, g.ID, g.Name)
	return err
}

func (db *DB) GetGroup(id string) (*models.Group, error) {
	g := &models.Group{}
	err := db.queryRow(`SELECT id, name FROM groups_ WHERE id = ?`, id).Scan(&g.ID, &g.Name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return g, err
}

func (db *DB) ListGroups() ([]models.Group, error) {
	rows, err := db.query(`SELECT id, name FROM groups_`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []models.Group
	for rows.Next() {
		var g models.Group
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, err
		}
		groups = append(groups, g)
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
		`INSERT INTO restriction_sets (id, ca_id, name, type, max_validity_secs, deny_all) VALUES (?, ?, ?, ?, ?, ?)`,
		rs.ID, caID, rs.Name, rs.Type, rs.MaxValiditySecs, denyAll,
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
	db.exec(`DELETE FROM ssh_restriction_details WHERE restriction_set_id = ?`, rs.ID)
	db.exec(`DELETE FROM x509_restriction_details WHERE restriction_set_id = ?`, rs.ID)
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
		json.Unmarshal([]byte(principals.String), &rs.AllowedPrincipals)
	}
	if certTypes.Valid {
		json.Unmarshal([]byte(certTypes.String), &rs.AllowedCertTypes)
	}
	if extensions.Valid {
		json.Unmarshal([]byte(extensions.String), &rs.AllowedExtensions)
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
		json.Unmarshal([]byte(keyUsages.String), &rs.AllowedKeyUsages)
	}
	if extKeyUsages.Valid {
		json.Unmarshal([]byte(extKeyUsages.String), &rs.AllowedExtKeyUsages)
	}
	if sanTypes.Valid {
		json.Unmarshal([]byte(sanTypes.String), &rs.AllowedSANTypes)
	}
	if sanPatterns.Valid {
		json.Unmarshal([]byte(sanPatterns.String), &rs.AllowedSANPatterns)
	}
	if subjectFields.Valid {
		json.Unmarshal([]byte(subjectFields.String), &rs.AllowedSubjectFields)
	}
}

func (db *DB) GetRestrictionSet(id string) (*models.RestrictionSet, error) {
	var rs models.RestrictionSet
	var caID sql.NullString
	var denyAll int
	err := db.queryRow(
		`SELECT id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets WHERE id = ?`, id,
	).Scan(&rs.ID, &caID, &rs.Name, &rs.Type, &rs.MaxValiditySecs, &denyAll)
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
	return db.scanRestrictionSets(db.query(`SELECT id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets`))
}

func (db *DB) ListRestrictionSets(caID string) ([]models.RestrictionSet, error) {
	return db.scanRestrictionSets(db.query(
		`SELECT id, ca_id, name, type, max_validity_secs, deny_all FROM restriction_sets WHERE ca_id = ? OR ca_id IS NULL`, caID,
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
		var caID sql.NullString
		var denyAll int
		if err := rows.Scan(&rs.ID, &caID, &rs.Name, &rs.Type, &rs.MaxValiditySecs, &denyAll); err != nil {
			return nil, err
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
	db.exec(`UPDATE cas SET default_ssh_restriction_set_id = NULL WHERE default_ssh_restriction_set_id = ?`, id)
	db.exec(`UPDATE cas SET default_x509_restriction_set_id = NULL WHERE default_x509_restriction_set_id = ?`, id)
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
		json.Unmarshal([]byte(principals.String), &e.Principals)
	}
	if extensions.Valid {
		json.Unmarshal([]byte(extensions.String), &e.Extensions)
	}
	if critOpts.Valid {
		json.Unmarshal([]byte(critOpts.String), &e.CriticalOptions)
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
			json.Unmarshal([]byte(principals.String), &e.Principals)
		}
		if extensions.Valid {
			json.Unmarshal([]byte(extensions.String), &e.Extensions)
		}
		if critOpts.Valid {
			json.Unmarshal([]byte(critOpts.String), &e.CriticalOptions)
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
	defer stmt.Close()

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
