package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
			created_at %s
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
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
			created_at %s
		)`, currentTimestamp),
		`CREATE INDEX IF NOT EXISTS idx_acme_chall_authz ON acme_challenges(authz_id)`,
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
	_, _ = db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_acme_orders_serial ON acme_orders(serial)`)
	return nil
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

// CreateACMEOrder inserts a new order.
func (db *DB) CreateACMEOrder(o *models.ACMEOrder) error {
	ids, _ := json.Marshal(o.Identifiers)
	status := o.Status
	if status == "" {
		status = models.ACMEOrderStatusPending
	}
	_, err := db.exec(
		`INSERT INTO acme_orders (id, account_id, status, identifiers, not_before, not_after, expires, replaces)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.AccountID, status, string(ids), nullTime(o.NotBefore), nullTime(o.NotAfter), o.Expires.UTC(), nullString(o.Replaces),
	)
	return err
}

const acmeOrderColumns = `id, account_id, status, identifiers, not_before, not_after,
	expires, error, ca_id, serial, certificate, finalized_at, replaces, created_at`

func scanACMEOrder(s caScanner) (*models.ACMEOrder, error) {
	var o models.ACMEOrder
	var ids string
	var notBefore, notAfter, finalizedAt sql.NullTime
	var errStr, caID, serial, cert, replaces sql.NullString
	if err := s.Scan(&o.ID, &o.AccountID, &o.Status, &ids, &notBefore, &notAfter,
		&o.Expires, &errStr, &caID, &serial, &cert, &finalizedAt, &replaces, &o.CreatedAt); err != nil {
		return nil, err
	}
	o.Replaces = replaces.String
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

// ---- Authorizations -------------------------------------------------------

// CreateACMEAuthorization inserts an authorization.
func (db *DB) CreateACMEAuthorization(a *models.ACMEAuthorization) error {
	status := a.Status
	if status == "" {
		status = models.ACMEAuthzStatusPending
	}
	_, err := db.exec(
		`INSERT INTO acme_authorizations (id, order_id, account_id, identifier_type, identifier_value, status, expires, wildcard)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.OrderID, a.AccountID, a.IdentifierType, a.IdentifierValue, status, a.Expires.UTC(), a.Wildcard,
	)
	return err
}

const acmeAuthzColumns = `id, order_id, account_id, identifier_type, identifier_value, status, expires, wildcard, created_at`

func scanACMEAuthz(s caScanner) (*models.ACMEAuthorization, error) {
	var a models.ACMEAuthorization
	if err := s.Scan(&a.ID, &a.OrderID, &a.AccountID, &a.IdentifierType, &a.IdentifierValue,
		&a.Status, &a.Expires, &a.Wildcard, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
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

// CreateACMEChallenge inserts a challenge.
func (db *DB) CreateACMEChallenge(c *models.ACMEChallenge) error {
	status := c.Status
	if status == "" {
		status = models.ACMEChallengeStatusPending
	}
	_, err := db.exec(
		`INSERT INTO acme_challenges (id, authz_id, type, token, status)
		 VALUES (?, ?, ?, ?, ?)`,
		c.ID, c.AuthzID, c.Type, c.Token, status,
	)
	return err
}

const acmeChallengeColumns = `id, authz_id, type, token, status, validated, error, created_at`

func scanACMEChallenge(s caScanner) (*models.ACMEChallenge, error) {
	var c models.ACMEChallenge
	var validated sql.NullTime
	var errStr sql.NullString
	if err := s.Scan(&c.ID, &c.AuthzID, &c.Type, &c.Token, &c.Status, &validated, &errStr, &c.CreatedAt); err != nil {
		return nil, err
	}
	if validated.Valid {
		t := validated.Time
		c.Validated = &t
	}
	c.Error = errStr.String
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

// nullTime renders a *time.Time as a driver-friendly nullable value.
func nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC()
}
