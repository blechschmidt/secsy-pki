package database

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ssh-pki/server/internal/models"
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
			public_key TEXT NOT NULL,
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
			permission TEXT NOT NULL CHECK(permission IN ('SIGN_CERTIFICATE', 'MANAGE_PERMISSIONS')),
			UNIQUE(ca_id, entity_type, entity_id, permission)
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.conn.Exec(stmt); err != nil {
			return fmt.Errorf("executing %q: %w", stmt[:40], err)
		}
	}
	return nil
}

// CA operations

func (db *DB) CreateCA(ca *models.CA) error {
	_, err := db.conn.Exec(
		`INSERT INTO cas (id, parent_id, label, pkcs11_uri, key_type, public_key) VALUES (?, ?, ?, ?, ?, ?)`,
		ca.ID, ca.ParentID, ca.Label, ca.PKCS11URI, ca.KeyType, ca.PublicKey,
	)
	return err
}

func (db *DB) GetCA(id string) (*models.CA, error) {
	ca := &models.CA{}
	err := db.conn.QueryRow(
		`SELECT id, parent_id, label, pkcs11_uri, key_type, public_key, created_at FROM cas WHERE id = ?`, id,
	).Scan(&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &ca.PublicKey, &ca.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ca, err
}

func (db *DB) ListCAs() ([]models.CA, error) {
	rows, err := db.conn.Query(`SELECT id, parent_id, label, pkcs11_uri, key_type, public_key, created_at FROM cas`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		var ca models.CA
		if err := rows.Scan(&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &ca.PublicKey, &ca.CreatedAt); err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

func (db *DB) DeleteCA(id string) error {
	_, err := db.conn.Exec(`DELETE FROM cas WHERE id = ?`, id)
	return err
}

func (db *DB) GetChildren(parentID string) ([]models.CA, error) {
	rows, err := db.conn.Query(`SELECT id, parent_id, label, pkcs11_uri, key_type, public_key, created_at FROM cas WHERE parent_id = ?`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cas []models.CA
	for rows.Next() {
		var ca models.CA
		if err := rows.Scan(&ca.ID, &ca.ParentID, &ca.Label, &ca.PKCS11URI, &ca.KeyType, &ca.PublicKey, &ca.CreatedAt); err != nil {
			return nil, err
		}
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
		`INSERT OR IGNORE INTO permissions (id, ca_id, entity_type, entity_id, permission) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.CAID, p.EntityType, p.EntityID, p.Permission,
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
		`SELECT id, ca_id, entity_type, entity_id, permission FROM permissions WHERE ca_id = ?`, caID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var perms []models.PermissionEntry
	for rows.Next() {
		var p models.PermissionEntry
		if err := rows.Scan(&p.ID, &p.CAID, &p.EntityType, &p.EntityID, &p.Permission); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (db *DB) HasPermission(caID, userSub string, perm models.Permission, groupIDs []string) (bool, error) {
	// Check direct user permission
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

	// Check group permissions
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
