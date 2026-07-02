package database

import (
	"database/sql"
	"errors"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// AddWebAuthnCredential persists a newly registered passkey. The credential id
// is the primary key; re-registering the same id updates its public key and
// resets the counter (an authenticator re-enrolled by the same operator).
func (db *DB) AddWebAuthnCredential(c *models.WebAuthnCredential) error {
	_, err := db.exec(db.upsert(
		"webauthn_credentials",
		"id, subject, name, public_key, sign_count",
		"?, ?, ?, ?, ?",
		"id",
		"subject = excluded.subject, name = excluded.name, public_key = excluded.public_key, sign_count = excluded.sign_count",
	), c.ID, c.Subject, c.Name, c.PublicKeyDER, c.SignCount)
	return err
}

// ListWebAuthnCredentials returns all passkeys registered by subject.
func (db *DB) ListWebAuthnCredentials(subject string) ([]models.WebAuthnCredential, error) {
	rows, err := db.query(
		`SELECT id, subject, name, public_key, sign_count, created_at FROM webauthn_credentials WHERE subject = ? ORDER BY created_at`,
		subject,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetWebAuthnCredential loads a single credential by its id, or (nil, nil) when
// it does not exist.
func (db *DB) GetWebAuthnCredential(id string) (*models.WebAuthnCredential, error) {
	row := db.queryRow(
		`SELECT id, subject, name, public_key, sign_count, created_at FROM webauthn_credentials WHERE id = ?`,
		id,
	)
	c, err := scanWebAuthn(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateWebAuthnSignCount advances a credential's stored signature counter after
// a successful assertion, supporting authenticator-clone detection.
func (db *DB) UpdateWebAuthnSignCount(id string, count uint32) error {
	_, err := db.exec(`UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`, count, id)
	return err
}

// DeleteWebAuthnCredential removes a passkey. The subject is required so an
// operator can only delete their own credentials.
func (db *DB) DeleteWebAuthnCredential(subject, id string) error {
	_, err := db.exec(`DELETE FROM webauthn_credentials WHERE id = ? AND subject = ?`, id, subject)
	return err
}

// scanner abstracts *sql.Row and *sql.Rows for the shared scan helper.
type scanner interface {
	Scan(dest ...interface{}) error
}

func scanWebAuthn(s scanner) (*models.WebAuthnCredential, error) {
	var (
		c        models.WebAuthnCredential
		name     sql.NullString
		signCnt  int64
		createdT sql.NullTime
	)
	if err := s.Scan(&c.ID, &c.Subject, &name, &c.PublicKeyDER, &signCnt, &createdT); err != nil {
		return nil, err
	}
	c.Name = name.String
	if signCnt > 0 {
		c.SignCount = uint32(signCnt)
	}
	if createdT.Valid {
		c.CreatedAt = createdT.Time
	}
	return &c, nil
}
