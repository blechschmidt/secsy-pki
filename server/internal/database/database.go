package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

type DB struct {
	conn *sql.DB
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
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrating: %w", err)
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cas (
			id TEXT PRIMARY KEY,
			parent_id TEXT REFERENCES cas(id),
			label TEXT NOT NULL,
			pkcs11_uri TEXT NOT NULL,
			key_type TEXT NOT NULL,
			public_key BLOB NOT NULL,
			default_restriction_set_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
		`CREATE TABLE IF NOT EXISTS permissions (
			id TEXT PRIMARY KEY,
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			entity_type TEXT NOT NULL CHECK(entity_type IN ('user', 'group')),
			entity_id TEXT NOT NULL,
			permission TEXT NOT NULL CHECK(permission IN ('SIGN_CERTIFICATE', 'MANAGE_PERMISSIONS', 'CONFIGURE_CA')),
			restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL,
			UNIQUE(ca_id, entity_type, entity_id, permission)
		)`,
		`CREATE TABLE IF NOT EXISTS restriction_sets (
			id TEXT PRIMARY KEY,
			ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			max_validity_secs INTEGER,
			allowed_principals TEXT,
			allowed_cert_types TEXT,
			force_key_id_email_reason INTEGER NOT NULL DEFAULT 0,
			allowed_extensions TEXT,
			deny_extensions INTEGER NOT NULL DEFAULT 0,
			deny_critical_options INTEGER NOT NULL DEFAULT 0,
			max_valid_after_offset INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			user_sub TEXT NOT NULL,
			user_email TEXT,
			user_name TEXT,
			ca_id TEXT NOT NULL,
			ca_label TEXT NOT NULL,
			key_id TEXT NOT NULL,
			cert_type TEXT NOT NULL,
			principals TEXT,
			valid_after DATETIME NOT NULL,
			valid_before DATETIME NOT NULL,
			extensions TEXT,
			critical_options TEXT,
			public_key BLOB NOT NULL,
			certificate BLOB,
			cert_hash TEXT,
			restriction_set_id TEXT,
			serial TEXT NOT NULL,
			UNIQUE(ca_id, cert_hash)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_ca ON audit_log(ca_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_sub)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(timestamp)`,
		`CREATE TABLE IF NOT EXISTS access_log (
			id TEXT PRIMARY KEY,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			user_sub TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			status INTEGER NOT NULL,
			ip TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_log_time ON access_log(timestamp)`,
		`CREATE TABLE IF NOT EXISTS hsm_audit_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hsm_audit_number ON hsm_audit_entries(number)`,
	}
	for _, stmt := range stmts {
		if _, err := db.conn.Exec(stmt); err != nil {
			return fmt.Errorf("executing %q: %w", stmt[:40], err)
		}
	}
	// Migration: add columns if they don't exist (for existing databases)
	db.conn.Exec("ALTER TABLE cas ADD COLUMN default_restriction_set_id TEXT")
	db.conn.Exec("ALTER TABLE permissions ADD COLUMN restriction_set_id TEXT REFERENCES restriction_sets(id) ON DELETE SET NULL")
	db.conn.Exec("ALTER TABLE restriction_sets ADD COLUMN deny_extensions INTEGER NOT NULL DEFAULT 0")
	db.conn.Exec("ALTER TABLE restriction_sets ADD COLUMN deny_critical_options INTEGER NOT NULL DEFAULT 0")
	db.conn.Exec("ALTER TABLE audit_log ADD COLUMN certificate TEXT")
	db.conn.Exec("ALTER TABLE audit_log ADD COLUMN cert_hash TEXT")
	db.conn.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_cert_unique ON audit_log(ca_id, cert_hash)")
	return nil
}

// CA operations

func (db *DB) CreateCA(ca *models.CA) error {
	_, err := db.conn.Exec(
		`INSERT INTO cas (id, parent_id, label, pkcs11_uri, key_type, public_key, default_restriction_set_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ca.ID, ca.ParentID, ca.Label, ca.PKCS11URI, ca.KeyType, pubKeyToBlob(ca.PublicKey), ca.DefaultRestrictionSetID,
	)
	return err
}

func (db *DB) GetCA(id string) (*models.CA, error) {
	ca := &models.CA{}
	var pubBlob []byte
	err := db.conn.QueryRow(
		`SELECT id, parent_id, label, pkcs11_uri, key_type, public_key, default_restriction_set_id, created_at FROM cas WHERE id = ?`, id,
	).Scan(&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &pubBlob, &ca.DefaultRestrictionSetID, &ca.CreatedAt)
	ca.PublicKey = blobToAuthorizedKey(pubBlob)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ca, err
}

func (db *DB) ListCAs() ([]models.CA, error) {
	rows, err := db.conn.Query(`SELECT id, parent_id, label, pkcs11_uri, key_type, public_key, default_restriction_set_id, created_at FROM cas`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		var ca models.CA
		var pubBlob []byte
		if err := rows.Scan(&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &pubBlob, &ca.DefaultRestrictionSetID, &ca.CreatedAt); err != nil {
			return nil, err
		}
		ca.PublicKey = blobToAuthorizedKey(pubBlob)
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

func (db *DB) DeleteCA(id string) error {
	_, err := db.conn.Exec(`DELETE FROM cas WHERE id = ?`, id)
	return err
}

func (db *DB) SetCADefaultRestrictionSet(caID string, rsID *string) error {
	_, err := db.conn.Exec(`UPDATE cas SET default_restriction_set_id = ? WHERE id = ?`, rsID, caID)
	return err
}

func (db *DB) GetChildren(parentID string) ([]models.CA, error) {
	rows, err := db.conn.Query(`SELECT id, parent_id, label, pkcs11_uri, key_type, public_key, default_restriction_set_id, created_at FROM cas WHERE parent_id = ?`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		var ca models.CA
		var pubBlob []byte
		if err := rows.Scan(&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &pubBlob, &ca.DefaultRestrictionSetID, &ca.CreatedAt); err != nil {
			return nil, err
		}
		ca.PublicKey = blobToAuthorizedKey(pubBlob)
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

// Group operations

func (db *DB) CreateGroup(g *models.Group) error {
	_, err := db.conn.Exec(`INSERT INTO groups_ (id, name) VALUES (?, ?)`, g.ID, g.Name)
	return err
}

func (db *DB) GetGroup(id string) (*models.Group, error) {
	g := &models.Group{}
	err := db.conn.QueryRow(`SELECT id, name FROM groups_ WHERE id = ?`, id).Scan(&g.ID, &g.Name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return g, err
}

func (db *DB) ListGroups() ([]models.Group, error) {
	rows, err := db.conn.Query(`SELECT id, name FROM groups_`)
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
	_, err := db.conn.Exec(`DELETE FROM groups_ WHERE id = ?`, id)
	return err
}

func (db *DB) AddGroupMember(groupID, userSub string) error {
	_, err := db.conn.Exec(`INSERT OR IGNORE INTO group_members (group_id, user_sub) VALUES (?, ?)`, groupID, userSub)
	return err
}

func (db *DB) RemoveGroupMember(groupID, userSub string) error {
	_, err := db.conn.Exec(`DELETE FROM group_members WHERE group_id = ? AND user_sub = ?`, groupID, userSub)
	return err
}

func (db *DB) GetGroupMembers(groupID string) ([]string, error) {
	rows, err := db.conn.Query(`SELECT user_sub FROM group_members WHERE group_id = ?`, groupID)
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
	rows, err := db.conn.Query(`SELECT group_id FROM group_members WHERE user_sub = ?`, userSub)
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
	_, err := db.conn.Exec(
		`INSERT INTO permissions (id, ca_id, entity_type, entity_id, permission, restriction_set_id) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(ca_id, entity_type, entity_id, permission) DO UPDATE SET restriction_set_id = excluded.restriction_set_id`,
		p.ID, p.CAID, p.EntityType, p.EntityID, p.Permission, p.RestrictionSetID,
	)
	return err
}

func (db *DB) RevokePermission(caID, entityType, entityID string, perm models.Permission) error {
	_, err := db.conn.Exec(
		`DELETE FROM permissions WHERE ca_id = ? AND entity_type = ? AND entity_id = ? AND permission = ?`,
		caID, entityType, entityID, perm,
	)
	return err
}

func (db *DB) GetPermissions(caID string) ([]models.PermissionEntry, error) {
	rows, err := db.conn.Query(
		`SELECT id, ca_id, entity_type, entity_id, permission, restriction_set_id FROM permissions WHERE ca_id = ?`, caID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var perms []models.PermissionEntry
	for rows.Next() {
		var p models.PermissionEntry
		if err := rows.Scan(&p.ID, &p.CAID, &p.EntityType, &p.EntityID, &p.Permission, &p.RestrictionSetID); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (db *DB) HasPermission(caID, userSub string, perm models.Permission, groupIDs []string) (bool, error) {
	var count int
	err := db.conn.QueryRow(
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
		err := db.conn.QueryRow(
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
// Priority: user-specific > group-specific > CA default. Returns nil if no restriction set applies.
func (db *DB) GetEffectiveRestrictionSet(caID, userSub string, groupIDs []string) (*models.RestrictionSet, error) {
	// Check user-specific SIGN_CERTIFICATE permission with a restriction set
	var rsID sql.NullString
	err := db.conn.QueryRow(
		`SELECT restriction_set_id FROM permissions WHERE ca_id = ? AND entity_type = 'user' AND entity_id = ? AND permission = 'SIGN_CERTIFICATE' AND restriction_set_id IS NOT NULL`,
		caID, userSub,
	).Scan(&rsID)
	if err == nil && rsID.Valid {
		return db.GetRestrictionSet(rsID.String)
	}

	// Check group-specific
	for _, gid := range groupIDs {
		err := db.conn.QueryRow(
			`SELECT restriction_set_id FROM permissions WHERE ca_id = ? AND entity_type = 'group' AND entity_id = ? AND permission = 'SIGN_CERTIFICATE' AND restriction_set_id IS NOT NULL`,
			caID, gid,
		).Scan(&rsID)
		if err == nil && rsID.Valid {
			return db.GetRestrictionSet(rsID.String)
		}
	}

	// Fall back to CA default
	var defaultID sql.NullString
	err = db.conn.QueryRow(`SELECT default_restriction_set_id FROM cas WHERE id = ?`, caID).Scan(&defaultID)
	if err == nil && defaultID.Valid {
		return db.GetRestrictionSet(defaultID.String)
	}

	return nil, nil
}

// Restriction set operations

func (db *DB) marshalRS(rs *models.RestrictionSet) (principals, certTypes, extensions string, forceEmail, denyExt, denyCrit int) {
	p, _ := json.Marshal(rs.AllowedPrincipals)
	c, _ := json.Marshal(rs.AllowedCertTypes)
	e, _ := json.Marshal(rs.AllowedExtensions)
	principals, certTypes, extensions = string(p), string(c), string(e)
	if rs.ForceKeyIDEmailReason { forceEmail = 1 }
	if rs.DenyExtensions { denyExt = 1 }
	if rs.DenyCriticalOptions { denyCrit = 1 }
	return
}

func (db *DB) CreateRestrictionSet(rs *models.RestrictionSet) error {
	principals, certTypes, extensions, forceEmail, denyExt, denyCrit := db.marshalRS(rs)
	_, err := db.conn.Exec(
		`INSERT INTO restriction_sets (id, ca_id, name, max_validity_secs, allowed_principals, allowed_cert_types, force_key_id_email_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rs.ID, rs.CAID, rs.Name, rs.MaxValiditySecs, principals, certTypes, forceEmail, extensions, denyExt, denyCrit, rs.MaxValidAfterOffset,
	)
	return err
}

func (db *DB) UpdateRestrictionSet(rs *models.RestrictionSet) error {
	principals, certTypes, extensions, forceEmail, denyExt, denyCrit := db.marshalRS(rs)
	_, err := db.conn.Exec(
		`UPDATE restriction_sets SET name=?, max_validity_secs=?, allowed_principals=?, allowed_cert_types=?, force_key_id_email_reason=?, allowed_extensions=?, deny_extensions=?, deny_critical_options=?, max_valid_after_offset=? WHERE id=?`,
		rs.Name, rs.MaxValiditySecs, principals, certTypes, forceEmail, extensions, denyExt, denyCrit, rs.MaxValidAfterOffset, rs.ID,
	)
	return err
}

func (db *DB) unmarshalRS(rs *models.RestrictionSet, principals, certTypes, extensions sql.NullString, forceEmail, denyExt, denyCrit int) {
	rs.ForceKeyIDEmailReason = forceEmail != 0
	rs.DenyExtensions = denyExt != 0
	rs.DenyCriticalOptions = denyCrit != 0
	if principals.Valid { json.Unmarshal([]byte(principals.String), &rs.AllowedPrincipals) }
	if certTypes.Valid { json.Unmarshal([]byte(certTypes.String), &rs.AllowedCertTypes) }
	if extensions.Valid { json.Unmarshal([]byte(extensions.String), &rs.AllowedExtensions) }
}

func (db *DB) GetRestrictionSet(id string) (*models.RestrictionSet, error) {
	var rs models.RestrictionSet
	var principals, certTypes, extensions sql.NullString
	var forceEmail, denyExt, denyCrit int
	err := db.conn.QueryRow(
		`SELECT id, ca_id, name, max_validity_secs, allowed_principals, allowed_cert_types, force_key_id_email_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset FROM restriction_sets WHERE id = ?`, id,
	).Scan(&rs.ID, &rs.CAID, &rs.Name, &rs.MaxValiditySecs, &principals, &certTypes, &forceEmail, &extensions, &denyExt, &denyCrit, &rs.MaxValidAfterOffset)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	db.unmarshalRS(&rs, principals, certTypes, extensions, forceEmail, denyExt, denyCrit)
	return &rs, nil
}

func (db *DB) ListRestrictionSets(caID string) ([]models.RestrictionSet, error) {
	rows, err := db.conn.Query(
		`SELECT id, ca_id, name, max_validity_secs, allowed_principals, allowed_cert_types, force_key_id_email_reason, allowed_extensions, deny_extensions, deny_critical_options, max_valid_after_offset FROM restriction_sets WHERE ca_id = ?`, caID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []models.RestrictionSet
	for rows.Next() {
		var rs models.RestrictionSet
		var principals, certTypes, extensions sql.NullString
		var forceEmail, denyExt, denyCrit int
		if err := rows.Scan(&rs.ID, &rs.CAID, &rs.Name, &rs.MaxValiditySecs, &principals, &certTypes, &forceEmail, &extensions, &denyExt, &denyCrit, &rs.MaxValidAfterOffset); err != nil {
			return nil, err
		}
		db.unmarshalRS(&rs, principals, certTypes, extensions, forceEmail, denyExt, denyCrit)
		sets = append(sets, rs)
	}
	return sets, rows.Err()
}

func (db *DB) DeleteRestrictionSet(id string) error {
	// Clear references from CA defaults
	db.conn.Exec(`UPDATE cas SET default_restriction_set_id = NULL WHERE default_restriction_set_id = ?`, id)
	_, err := db.conn.Exec(`DELETE FROM restriction_sets WHERE id = ?`, id)
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

	_, err := db.conn.Exec(
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
	err := db.conn.QueryRow(
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
	if principals.Valid { json.Unmarshal([]byte(principals.String), &e.Principals) }
	if extensions.Valid { json.Unmarshal([]byte(extensions.String), &e.Extensions) }
	if critOpts.Valid { json.Unmarshal([]byte(critOpts.String), &e.CriticalOptions) }
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
	if err := db.conn.QueryRow(countQuery, args...).Scan(&total); err != nil {
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

	rows, err := db.conn.Query(query, queryArgs...)
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
		if principals.Valid { json.Unmarshal([]byte(principals.String), &e.Principals) }
		if extensions.Valid { json.Unmarshal([]byte(extensions.String), &e.Extensions) }
		if critOpts.Valid { json.Unmarshal([]byte(critOpts.String), &e.CriticalOptions) }
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// Access log operations

func (db *DB) CreateAccessLogEntry(e *models.AccessLogEntry) error {
	_, err := db.conn.Exec(
		`INSERT INTO access_log (id, user_sub, method, path, status, ip) VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID, e.UserSub, e.Method, e.Path, e.Status, e.IP,
	)
	return err
}

func (db *DB) ListAccessLog(limit, offset int) ([]models.AccessLogEntry, int, error) {
	var total int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM access_log`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.conn.Query(
		`SELECT id, timestamp, user_sub, method, path, status, ip FROM access_log ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.AccessLogEntry
	for rows.Next() {
		var e models.AccessLogEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserSub, &e.Method, &e.Path, &e.Status, &e.IP); err != nil {
			return nil, 0, err
		}
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
		`INSERT OR IGNORE INTO hsm_audit_entries (number, command, length, session_key, target_key, second_key, result, tick, hash, sign_audit_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
	_, err := db.conn.Exec(
		`UPDATE hsm_audit_entries SET sign_audit_id = ?
		 WHERE id = (SELECT id FROM hsm_audit_entries WHERE sign_audit_id IS NULL AND command IN (?, ?, ?, ?, ?) ORDER BY number DESC LIMIT 1)`,
		signAuditID, 0x56, 0x6a, 0x47, 0x55, 0x46,
	)
	return err
}

func (db *DB) ExportCombinedAuditLog() (*models.CombinedAuditExport, error) {
	rows, err := db.conn.Query(
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
