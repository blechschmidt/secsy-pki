package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// migrateACME creates the tables backing the ACME (RFC 8555) server. It is
// called from migrate() so ACME storage is provisioned alongside the rest of the
// schema. The tables are self-contained (an operator can run without ACME
// enabled and the tables simply stay empty).
func (db *DB) migrateACME() error {
	currentTimestamp := "DATETIME DEFAULT CURRENT_TIMESTAMP"
	if db.isPostgres() {
		currentTimestamp = "TIMESTAMP DEFAULT NOW()"
	}
	boolType := "INTEGER NOT NULL DEFAULT 0"
	if db.isPostgres() {
		boolType = "BOOLEAN NOT NULL DEFAULT FALSE"
	}
	blob := "BLOB"
	if db.isPostgres() {
		blob = "BYTEA"
	}

	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS acme_accounts (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL DEFAULT 'valid',
			contacts TEXT,
			jwk TEXT NOT NULL,
			thumbprint TEXT NOT NULL UNIQUE,
			eab_kid TEXT,
			tos_agreed %s,
			created_at %s
		)`, boolType, currentTimestamp),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS acme_orders (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
			status TEXT NOT NULL DEFAULT 'pending',
			identifiers TEXT NOT NULL,
			not_before TIMESTAMP,
			not_after TIMESTAMP,
			expires TIMESTAMP NOT NULL,
			error TEXT,
			ca_id TEXT,
			serial TEXT,
			certificate TEXT,
			finalized_at TIMESTAMP,
			replaces TEXT,
			profile TEXT,
			star_auto_renewal TEXT,
			star_csr TEXT,
			star_next_renewal TIMESTAMP,
			created_at %s
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id)`,
		// order_id is nullable: a standalone pre-authorization (RFC 8555 §7.4.1,
		// created via newAuthz) exists independently of any order until an order
		// claims it, so its order_id is NULL. Order-created authorizations carry the
		// owning order's id and cascade-delete with it.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT REFERENCES acme_orders(id) ON DELETE CASCADE,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			expires TIMESTAMP NOT NULL,
			wildcard %s,
			created_at %s
		)`, boolType, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS acme_challenges (
			id TEXT PRIMARY KEY,
			authz_id TEXT NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			token TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			validated TIMESTAMP,
			error TEXT,
			email_token1 TEXT,
			email_message_id TEXT,
			created_at %s
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_acme_chall_authz ON acme_challenges(authz_id)`,
		// Shared/durable anti-replay nonce state (Task 97). Two tables back the
		// multi-replica-correct nonce design:
		//
		//   acme_nonces is the consumed-set: one row per nonce that has been spent.
		//   The ACME server mints self-authenticating (HMAC-signed) nonces without
		//   writing here; only a successful Consume inserts a row, so a replay — on
		//   this or any other replica sharing the store — finds the row and is
		//   rejected. Rows are keyed by the nonce's SHA-256 (fixed length; the raw
		//   token is not stored) and carry an expiry so the background GC can prune
		//   them. Pruning is safe: an expired nonce is rejected by its embedded
		//   timestamp before this set is ever consulted.
		//
		//   acme_nonce_secret holds the single server-wide HMAC key that lets any
		//   replica verify a nonce minted by any other. It is generated once on
		//   first use (insert-if-absent) and read by every replica, so no
		//   configuration is required for multi-replica correctness (an operator may
		//   still pin the key via config to skip the read or to rotate it).
		`CREATE TABLE IF NOT EXISTS acme_nonces (
			nonce_hash TEXT PRIMARY KEY,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_nonces_expires ON acme_nonces(expires_at)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS acme_nonce_secret (
			name TEXT PRIMARY KEY,
			secret %s NOT NULL,
			created_at %s
		)`, blob, currentTimestamp),
	}
	for _, stmt := range stmts {
		if _, err := db.exec(stmt); err != nil {
			return fmt.Errorf("acme migrate %q: %w", stmt[:40], err)
		}
	}
	// Additive migration for existing databases: the ARI "replaces" linkage
	// (draft-ietf-acme-ari) records which certificate a renewal order supersedes.
	// Errors are ignored — the column already exists on a fresh CREATE TABLE above
	// and on a second startup.
	if db.isPostgres() {
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN IF NOT EXISTS replaces TEXT`)
	} else {
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN replaces TEXT`)
	}
	// Additive migration for the ACME Profiles extension (RFC 9773): the internal
	// issuance profile id selected on each order. Errors are ignored — the column
	// already exists on a fresh CREATE TABLE above and on a second startup.
	if db.isPostgres() {
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN IF NOT EXISTS profile TEXT`)
	} else {
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN profile TEXT`)
	}
	_, _ = db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_acme_orders_serial ON acme_orders(serial)`)
	// Additive migration for the RFC 8823 email-reply-00 challenge (Task 108):
	// token-part-1 and the dispatched challenge email's Message-ID. Errors are
	// ignored — the columns already exist on a fresh CREATE TABLE above and on a
	// second startup.
	if db.isPostgres() {
		_, _ = db.conn.Exec(`ALTER TABLE acme_challenges ADD COLUMN IF NOT EXISTS email_token1 TEXT`)
		_, _ = db.conn.Exec(`ALTER TABLE acme_challenges ADD COLUMN IF NOT EXISTS email_message_id TEXT`)
	} else {
		_, _ = db.conn.Exec(`ALTER TABLE acme_challenges ADD COLUMN email_token1 TEXT`)
		_, _ = db.conn.Exec(`ALTER TABLE acme_challenges ADD COLUMN email_message_id TEXT`)
	}
	// Additive migration for ACME pre-authorization (Task 134, RFC 8555 §7.4.1):
	// relax acme_authorizations.order_id from NOT NULL to nullable on databases that
	// predate the feature, so a standalone pre-authorization (order_id NULL) can be
	// stored. A fresh database already has the nullable column from the CREATE above.
	db.relaxACMEAuthzOrderIDNullable()
	// Additive migration for ACME STAR short-term auto-renewed certificates
	// (Task 136, RFC 8739): the resolved recurrence parameters, the replayable CSR
	// captured at finalize, and the next-renewal deadline the background renewer
	// polls on. Errors are ignored — the columns already exist on a fresh CREATE
	// TABLE above and on a second startup.
	if db.isPostgres() {
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN IF NOT EXISTS star_auto_renewal TEXT`)
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN IF NOT EXISTS star_csr TEXT`)
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN IF NOT EXISTS star_next_renewal TIMESTAMP`)
	} else {
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN star_auto_renewal TEXT`)
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN star_csr TEXT`)
		_, _ = db.conn.Exec(`ALTER TABLE acme_orders ADD COLUMN star_next_renewal TIMESTAMP`)
	}
	// Index the renewal deadline so the leader-elected renewer's due-query stays a
	// cheap partial scan even with many active STAR orders.
	_, _ = db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_acme_orders_star_next_renewal ON acme_orders(star_next_renewal)`)
	return nil
}

// relaxACMEAuthzOrderIDNullable drops the NOT NULL constraint on
// acme_authorizations.order_id for databases created before ACME pre-authorization
// (Task 134). It is idempotent and a no-op on a fresh schema, where the column is
// already nullable.
func (db *DB) relaxACMEAuthzOrderIDNullable() {
	if db.isPostgres() {
		// DROP NOT NULL is a no-op (not an error) when the column is already
		// nullable, so this is safe to run on every startup.
		if _, err := db.conn.Exec(`ALTER TABLE acme_authorizations ALTER COLUMN order_id DROP NOT NULL`); err != nil {
			log.Printf("acme: relaxing acme_authorizations.order_id nullability: %v", err)
		}
		return
	}
	// SQLite has no ALTER COLUMN, so the column constraint can only be changed by
	// rebuilding the table. Do so only when order_id is still declared NOT NULL,
	// detected via PRAGMA table_info, so the rebuild runs at most once (never on a
	// fresh or already-migrated database).
	rows, err := db.conn.Query(`PRAGMA table_info(acme_authorizations)`)
	if err != nil {
		log.Printf("acme: inspecting acme_authorizations schema: %v", err)
		return
	}
	needsRebuild := false
	for rows.Next() {
		var (
			cid, notNull, pk int
			name, colType    string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			_ = rows.Close()
			log.Printf("acme: inspecting acme_authorizations schema: %v", err)
			return
		}
		if name == "order_id" && notNull == 1 {
			needsRebuild = true
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil || !needsRebuild {
		return
	}
	// FK-safe table rebuild. SQLite is pinned to a single connection, so toggling
	// foreign_keys here is sequential and cannot race other statements; disabling
	// it prevents the DROP TABLE from cascade-deleting acme_challenges rows (whose
	// authz_id references remain valid because the rebuilt table preserves every id).
	stmts := []string{
		`PRAGMA foreign_keys=OFF`,
		`CREATE TABLE acme_authorizations_new (
			id TEXT PRIMARY KEY,
			order_id TEXT REFERENCES acme_orders(id) ON DELETE CASCADE,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			expires TIMESTAMP NOT NULL,
			wildcard INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO acme_authorizations_new
			(id, order_id, account_id, identifier_type, identifier_value, status, expires, wildcard, created_at)
			SELECT id, order_id, account_id, identifier_type, identifier_value, status, expires, wildcard, created_at
			FROM acme_authorizations`,
		`DROP TABLE acme_authorizations`,
		`ALTER TABLE acme_authorizations_new RENAME TO acme_authorizations`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id)`,
		`PRAGMA foreign_keys=ON`,
	}
	for _, stmt := range stmts {
		if _, err := db.conn.Exec(stmt); err != nil {
			log.Printf("acme: rebuilding acme_authorizations to relax order_id: %v", err)
			// Best-effort restore of FK enforcement before giving up.
			_, _ = db.conn.Exec(`PRAGMA foreign_keys=ON`)
			return
		}
	}
}

// ---- Accounts -------------------------------------------------------------

// CreateACMEAccount inserts a new ACME account.
func (db *DB) CreateACMEAccount(a *models.ACMEAccount) error {
	contacts, _ := json.Marshal(a.Contacts)
	status := a.Status
	if status == "" {
		status = models.ACMEAccountStatusValid
	}
	_, err := db.exec(
		`INSERT INTO acme_accounts (id, status, contacts, jwk, thumbprint, eab_kid, tos_agreed)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, status, string(contacts), a.JWK, a.Thumbprint, nullString(a.EABKid), a.TermsOfServiceOK,
	)
	return err
}

const acmeAccountColumns = `id, status, contacts, jwk, thumbprint, eab_kid, tos_agreed, created_at`

func scanACMEAccount(s caScanner) (*models.ACMEAccount, error) {
	var a models.ACMEAccount
	var contacts, eabKid sql.NullString
	if err := s.Scan(&a.ID, &a.Status, &contacts, &a.JWK, &a.Thumbprint, &eabKid, &a.TermsOfServiceOK, &a.CreatedAt); err != nil {
		return nil, err
	}
	a.EABKid = eabKid.String
	if contacts.Valid && contacts.String != "" {
		_ = json.Unmarshal([]byte(contacts.String), &a.Contacts)
	}
	return &a, nil
}

// GetACMEAccount looks an account up by id. Returns (nil, nil) if absent.
func (db *DB) GetACMEAccount(id string) (*models.ACMEAccount, error) {
	a, err := scanACMEAccount(db.queryRow(`SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ListACMEAccounts returns registered accounts (newest first) for operator
// inventory.
func (db *DB) ListACMEAccounts(limit, offset int) ([]models.ACMEAccount, error) {
	rows, err := db.query(`SELECT `+acmeAccountColumns+` FROM acme_accounts ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEAccount
	for rows.Next() {
		a, err := scanACMEAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// GetACMEAccountByThumbprint looks an account up by its JWK thumbprint. Returns
// (nil, nil) if none matches.
func (db *DB) GetACMEAccountByThumbprint(thumbprint string) (*models.ACMEAccount, error) {
	a, err := scanACMEAccount(db.queryRow(`SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE thumbprint = ?`, thumbprint))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// UpdateACMEAccount updates the mutable fields of an account (status, contacts).
func (db *DB) UpdateACMEAccount(a *models.ACMEAccount) error {
	contacts, _ := json.Marshal(a.Contacts)
	_, err := db.exec(
		`UPDATE acme_accounts SET status = ?, contacts = ? WHERE id = ?`,
		a.Status, string(contacts), a.ID,
	)
	return err
}

// UpdateACMEAccountKey rotates an account's public key (RFC 8555 §7.3.5).
func (db *DB) UpdateACMEAccountKey(id, jwk, thumbprint string) error {
	_, err := db.exec(
		`UPDATE acme_accounts SET jwk = ?, thumbprint = ? WHERE id = ?`,
		jwk, thumbprint, id,
	)
	return err
}

// ---- Orders ---------------------------------------------------------------

// CreateACMEOrder inserts a new order. When the order carries an RFC 8739 STAR
// recurrence (AutoRenewal set, Task 136) it is serialized into star_auto_renewal;
// star_csr and star_next_renewal stay NULL until finalize captures them.
func (db *DB) CreateACMEOrder(o *models.ACMEOrder) error {
	ids, _ := json.Marshal(o.Identifiers)
	status := o.Status
	if status == "" {
		status = models.ACMEOrderStatusPending
	}
	var autoRenewal interface{}
	if o.AutoRenewal != nil {
		b, err := json.Marshal(o.AutoRenewal)
		if err != nil {
			return err
		}
		autoRenewal = string(b)
	}
	_, err := db.exec(
		`INSERT INTO acme_orders (id, account_id, status, identifiers, not_before, not_after, expires, replaces, profile, star_auto_renewal)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.AccountID, status, string(ids), nullTime(o.NotBefore), nullTime(o.NotAfter), o.Expires.UTC(), nullString(o.Replaces), nullString(o.Profile), autoRenewal,
	)
	return err
}

const acmeOrderColumns = `id, account_id, status, identifiers, not_before, not_after,
	expires, error, ca_id, serial, certificate, finalized_at, replaces, profile,
	star_auto_renewal, star_csr, star_next_renewal, created_at`

func scanACMEOrder(s caScanner) (*models.ACMEOrder, error) {
	var o models.ACMEOrder
	var ids string
	var notBefore, notAfter, finalizedAt, starNextRenewal sql.NullTime
	var errStr, caID, serial, cert, replaces, profile, autoRenewal, starCSR sql.NullString
	if err := s.Scan(&o.ID, &o.AccountID, &o.Status, &ids, &notBefore, &notAfter,
		&o.Expires, &errStr, &caID, &serial, &cert, &finalizedAt, &replaces, &profile,
		&autoRenewal, &starCSR, &starNextRenewal, &o.CreatedAt); err != nil {
		return nil, err
	}
	o.Replaces = replaces.String
	o.Profile = profile.String
	_ = json.Unmarshal([]byte(ids), &o.Identifiers)
	if notBefore.Valid {
		t := notBefore.Time
		o.NotBefore = &t
	}
	if notAfter.Valid {
		t := notAfter.Time
		o.NotAfter = &t
	}
	if finalizedAt.Valid {
		t := finalizedAt.Time
		o.FinalizedAt = &t
	}
	if autoRenewal.Valid && autoRenewal.String != "" {
		var ar models.ACMEAutoRenewal
		if err := json.Unmarshal([]byte(autoRenewal.String), &ar); err == nil {
			o.AutoRenewal = &ar
		}
	}
	o.StarCSR = starCSR.String
	if starNextRenewal.Valid {
		t := starNextRenewal.Time
		o.StarNextRenewal = &t
	}
	o.Error = errStr.String
	o.CAID = caID.String
	o.Serial = serial.String
	o.Certificate = cert.String
	return &o, nil
}

// GetACMEOrder looks an order up by id. Returns (nil, nil) if absent.
func (db *DB) GetACMEOrder(id string) (*models.ACMEOrder, error) {
	o, err := scanACMEOrder(db.queryRow(`SELECT `+acmeOrderColumns+` FROM acme_orders WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

// ListACMEOrdersByAccount returns an account's orders (newest first).
func (db *DB) ListACMEOrdersByAccount(accountID string) ([]models.ACMEOrder, error) {
	rows, err := db.query(`SELECT `+acmeOrderColumns+` FROM acme_orders WHERE account_id = ? ORDER BY created_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEOrder
	for rows.Next() {
		o, err := scanACMEOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// ListACMEOrders returns all orders (newest first), for operator inventory.
func (db *DB) ListACMEOrders(limit, offset int) ([]models.ACMEOrder, error) {
	rows, err := db.query(`SELECT `+acmeOrderColumns+` FROM acme_orders ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEOrder
	for rows.Next() {
		o, err := scanACMEOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// GetACMEOrderByCertificate returns the valid order that issued the certificate
// with the given (CA, serial), or (nil, nil) if none matches. It backs ARI
// renewal-info lookups and the newOrder "replaces" authorization check.
func (db *DB) GetACMEOrderByCertificate(caID, serial string) (*models.ACMEOrder, error) {
	o, err := scanACMEOrder(db.queryRow(
		`SELECT `+acmeOrderColumns+` FROM acme_orders WHERE ca_id = ? AND serial = ? ORDER BY created_at DESC`,
		caID, serial))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

// CountACMEOrdersReplacing returns how many orders name the given ARI CertID in
// their "replaces" field. A nonzero count means the predecessor certificate has
// already been superseded by a renewal order (draft-ietf-acme-ari §5).
func (db *DB) CountACMEOrdersReplacing(certID string) (int, error) {
	var n int
	// An "invalid" order that named this predecessor failed, so it does not count
	// as having replaced the certificate — the client may retry the renewal.
	err := db.queryRow(
		`SELECT COUNT(*) FROM acme_orders WHERE replaces = ? AND status != ?`,
		certID, models.ACMEOrderStatusInvalid).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// UpdateACMEOrderStatus sets an order's status and (optionally) its error.
func (db *DB) UpdateACMEOrderStatus(id, status, errDoc string) error {
	_, err := db.exec(`UPDATE acme_orders SET status = ?, error = ? WHERE id = ?`, status, nullString(errDoc), id)
	return err
}

// FinalizeACMEOrder records the issued certificate for an order and marks it
// valid.
func (db *DB) FinalizeACMEOrder(id, caID, serial, chainPEM string, finalizedAt time.Time) error {
	_, err := db.exec(
		`UPDATE acme_orders SET status = ?, ca_id = ?, serial = ?, certificate = ?, finalized_at = ? WHERE id = ?`,
		models.ACMEOrderStatusValid, caID, serial, chainPEM, finalizedAt.UTC(), id,
	)
	return err
}

// FinalizeACMEStarOrder records the first short-lived certificate of an RFC 8739
// STAR order (Task 136), marks it valid, and captures the replayable CSR plus the
// next-renewal deadline the background renewer polls on. A nil nextRenewal (the
// recurrence already fits in a single certificate) leaves star_next_renewal NULL,
// so the renewer never re-issues.
func (db *DB) FinalizeACMEStarOrder(id, caID, serial, chainPEM, csrB64 string, nextRenewal *time.Time, finalizedAt time.Time) error {
	_, err := db.exec(
		`UPDATE acme_orders
		 SET status = ?, ca_id = ?, serial = ?, certificate = ?, finalized_at = ?, star_csr = ?, star_next_renewal = ?
		 WHERE id = ?`,
		models.ACMEOrderStatusValid, caID, serial, chainPEM, finalizedAt.UTC(), csrB64, nullTime(nextRenewal), id,
	)
	return err
}

// RenewACMEStarOrder replaces the current STAR certificate with a freshly issued
// one and reschedules (or, with a nil nextRenewal, ends) the recurrence. It
// touches only the rotating fields, so the order stays valid and keeps its stored
// CSR and recurrence parameters. The status guard makes it a no-op if the order
// was canceled concurrently, so a renewal in flight cannot resurrect a canceled
// order.
func (db *DB) RenewACMEStarOrder(id, caID, serial, chainPEM string, nextRenewal *time.Time) error {
	_, err := db.exec(
		`UPDATE acme_orders
		 SET ca_id = ?, serial = ?, certificate = ?, star_next_renewal = ?
		 WHERE id = ? AND status = ?`,
		caID, serial, chainPEM, nullTime(nextRenewal), id, models.ACMEOrderStatusValid,
	)
	return err
}

// StopACMEStarRenewal clears a STAR order's next-renewal deadline without issuing
// a certificate, ending the recurrence (the horizon EndDate has passed). The order
// stays valid and keeps serving its last certificate.
func (db *DB) StopACMEStarRenewal(id string) error {
	_, err := db.exec(`UPDATE acme_orders SET star_next_renewal = NULL WHERE id = ?`, id)
	return err
}

// CancelACMEStarOrder marks a STAR order canceled (RFC 8739 §3.5) and clears its
// renewal deadline so the background renewer stops. The guards restrict it to a
// STAR order (star_auto_renewal present) that is not already terminal
// (canceled/invalid), so the cancel is idempotent and cannot fire on a non-STAR or
// dead order; it reports whether this call performed the cancellation.
func (db *DB) CancelACMEStarOrder(id string) (bool, error) {
	res, err := db.exec(
		`UPDATE acme_orders SET status = ?, star_next_renewal = NULL
		 WHERE id = ? AND star_auto_renewal IS NOT NULL AND status NOT IN (?, ?)`,
		models.ACMEOrderStatusCanceled, id, models.ACMEOrderStatusCanceled, models.ACMEOrderStatusInvalid,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListDueACMEStarOrders returns valid STAR orders whose next-renewal deadline has
// arrived (star_next_renewal <= now), oldest deadline first, capped at limit. It
// backs the leader-elected renewer's due-query; canceled and ended recurrences
// have a NULL deadline and are excluded.
func (db *DB) ListDueACMEStarOrders(now time.Time, limit int) ([]models.ACMEOrder, error) {
	rows, err := db.query(
		`SELECT `+acmeOrderColumns+` FROM acme_orders
		 WHERE status = ? AND star_next_renewal IS NOT NULL AND star_next_renewal <= ?
		 ORDER BY star_next_renewal ASC LIMIT ?`,
		models.ACMEOrderStatusValid, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEOrder
	for rows.Next() {
		o, err := scanACMEOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// ---- Authorizations -------------------------------------------------------

// CreateACMEAuthorization inserts an authorization. An empty OrderID stores a
// SQL NULL, marking a standalone pre-authorization (RFC 8555 §7.4.1) that no
// order has claimed yet.
func (db *DB) CreateACMEAuthorization(a *models.ACMEAuthorization) error {
	status := a.Status
	if status == "" {
		status = models.ACMEAuthzStatusPending
	}
	_, err := db.exec(
		`INSERT INTO acme_authorizations (id, order_id, account_id, identifier_type, identifier_value, status, expires, wildcard)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, nullString(a.OrderID), a.AccountID, a.IdentifierType, a.IdentifierValue, status, a.Expires.UTC(), a.Wildcard,
	)
	return err
}

const acmeAuthzColumns = `id, order_id, account_id, identifier_type, identifier_value, status, expires, wildcard, created_at`

func scanACMEAuthz(s caScanner) (*models.ACMEAuthorization, error) {
	var a models.ACMEAuthorization
	var orderID sql.NullString
	if err := s.Scan(&a.ID, &orderID, &a.AccountID, &a.IdentifierType, &a.IdentifierValue,
		&a.Status, &a.Expires, &a.Wildcard, &a.CreatedAt); err != nil {
		return nil, err
	}
	a.OrderID = orderID.String
	return &a, nil
}

// FindReusableACMEPreAuthorization returns the account's newest still-usable
// standalone pre-authorization (RFC 8555 §7.4.1) for an identifier, or (nil, nil)
// if none exists. "Usable" means unclaimed (order_id IS NULL), matching the exact
// identifier and wildcard flag, not yet expired, and in a status that can still
// authorize issuance (valid) or reach it (pending). An already-valid
// authorization is preferred so a subsequent order can skip re-validation.
func (db *DB) FindReusableACMEPreAuthorization(accountID, idType, idValue string, wildcard bool, now time.Time) (*models.ACMEAuthorization, error) {
	a, err := scanACMEAuthz(db.queryRow(
		`SELECT `+acmeAuthzColumns+` FROM acme_authorizations
		 WHERE order_id IS NULL AND account_id = ? AND identifier_type = ? AND identifier_value = ?
		   AND wildcard = ? AND status IN (?, ?) AND expires > ?
		 ORDER BY CASE WHEN status = ? THEN 0 ELSE 1 END, created_at DESC`,
		accountID, idType, idValue, wildcard,
		models.ACMEAuthzStatusValid, models.ACMEAuthzStatusPending, now.UTC(),
		models.ACMEAuthzStatusValid,
	))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ClaimACMEPreAuthorization links a standalone pre-authorization to an order,
// but only while it is still unclaimed (order_id IS NULL). The conditional update
// makes the claim atomic, so two concurrent orders for the same identifier cannot
// both reuse the same pre-authorization. It reports whether this call won the claim.
func (db *DB) ClaimACMEPreAuthorization(authzID, orderID string) (bool, error) {
	res, err := db.exec(
		`UPDATE acme_authorizations SET order_id = ? WHERE id = ? AND order_id IS NULL`,
		orderID, authzID,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetACMEAuthorization looks an authorization up by id. (nil, nil) if absent.
func (db *DB) GetACMEAuthorization(id string) (*models.ACMEAuthorization, error) {
	a, err := scanACMEAuthz(db.queryRow(`SELECT `+acmeAuthzColumns+` FROM acme_authorizations WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ListACMEAuthorizationsByOrder returns an order's authorizations.
func (db *DB) ListACMEAuthorizationsByOrder(orderID string) ([]models.ACMEAuthorization, error) {
	rows, err := db.query(`SELECT `+acmeAuthzColumns+` FROM acme_authorizations WHERE order_id = ?`, orderID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEAuthorization
	for rows.Next() {
		a, err := scanACMEAuthz(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// UpdateACMEAuthorizationStatus sets an authorization's status.
func (db *DB) UpdateACMEAuthorizationStatus(id, status string) error {
	_, err := db.exec(`UPDATE acme_authorizations SET status = ? WHERE id = ?`, status, id)
	return err
}

// ---- Challenges -----------------------------------------------------------

// CreateACMEChallenge inserts a challenge. For email-reply-00 challenges
// (RFC 8823) the caller pre-generates token-part-1 (EmailToken1); it is stored
// here and never exposed over HTTPS.
func (db *DB) CreateACMEChallenge(c *models.ACMEChallenge) error {
	status := c.Status
	if status == "" {
		status = models.ACMEChallengeStatusPending
	}
	_, err := db.exec(
		`INSERT INTO acme_challenges (id, authz_id, type, token, status, email_token1)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.AuthzID, c.Type, c.Token, status, nullString(c.EmailToken1),
	)
	return err
}

const acmeChallengeColumns = `id, authz_id, type, token, status, validated, error, email_token1, email_message_id, created_at`

func scanACMEChallenge(s caScanner) (*models.ACMEChallenge, error) {
	var c models.ACMEChallenge
	var validated sql.NullTime
	var errStr, token1, messageID sql.NullString
	if err := s.Scan(&c.ID, &c.AuthzID, &c.Type, &c.Token, &c.Status, &validated, &errStr, &token1, &messageID, &c.CreatedAt); err != nil {
		return nil, err
	}
	if validated.Valid {
		t := validated.Time
		c.Validated = &t
	}
	c.Error = errStr.String
	c.EmailToken1 = token1.String
	c.EmailMessageID = messageID.String
	return &c, nil
}

// GetACMEChallenge looks a challenge up by id. (nil, nil) if absent.
func (db *DB) GetACMEChallenge(id string) (*models.ACMEChallenge, error) {
	c, err := scanACMEChallenge(db.queryRow(`SELECT `+acmeChallengeColumns+` FROM acme_challenges WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// ListACMEChallengesByAuthz returns an authorization's challenges.
func (db *DB) ListACMEChallengesByAuthz(authzID string) ([]models.ACMEChallenge, error) {
	rows, err := db.query(`SELECT `+acmeChallengeColumns+` FROM acme_challenges WHERE authz_id = ?`, authzID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEChallenge
	for rows.Next() {
		c, err := scanACMEChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// UpdateACMEChallenge sets a challenge's status, validation time, and error.
func (db *DB) UpdateACMEChallenge(id, status string, validated *time.Time, errDoc string) error {
	_, err := db.exec(
		`UPDATE acme_challenges SET status = ?, validated = ?, error = ? WHERE id = ?`,
		status, nullTime(validated), nullString(errDoc), id,
	)
	return err
}

// MarkACMEChallengeEmailSent records that an email-reply-00 challenge email has
// been dispatched: it stores the message's Message-ID (to thread the reply back
// to this challenge) and moves the challenge to "processing" so a subsequent
// respond is idempotent and the inbound poller picks it up.
func (db *DB) MarkACMEChallengeEmailSent(id, messageID string) error {
	_, err := db.exec(
		`UPDATE acme_challenges SET status = ?, email_message_id = ? WHERE id = ?`,
		models.ACMEChallengeStatusProcessing, messageID, id,
	)
	return err
}

// ListACMEChallengesByStatusType returns every challenge in the given status of
// the given type. The inbound-mail poller uses it to enumerate email-reply-00
// challenges awaiting a reply; the set is small (one per outstanding S/MIME
// order) so no dedicated index is warranted.
func (db *DB) ListACMEChallengesByStatusType(status, challengeType string) ([]models.ACMEChallenge, error) {
	rows, err := db.query(
		`SELECT `+acmeChallengeColumns+` FROM acme_challenges WHERE status = ? AND type = ?`,
		status, challengeType)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []models.ACMEChallenge
	for rows.Next() {
		c, err := scanACMEChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// nullTime renders a *time.Time as a driver-friendly nullable value.
func nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC()
}
