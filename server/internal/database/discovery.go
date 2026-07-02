package database

import (
	"database/sql"
	"encoding/json"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// b2i converts a Go bool to the 0/1 INTEGER used by the discovered_certificates
// flag columns, keeping storage portable across SQLite and PostgreSQL.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// discoveredCertColumns is the canonical column list for discovered-certificate
// reads. Keep it in sync with scanDiscoveredCert.
const discoveredCertColumns = `id, tenant_id, endpoint, server_name, subject, common_name,
	sans, issuer, serial, not_before, not_after, key_algorithm, key_size,
	signature_algorithm, chain_length, chain_complete, fingerprint, certificate,
	issued_by_pki, rogue, self_signed, weak_key, sha1_signature, hostname_mismatch,
	expiring_soon, severity, flags, discovered_at`

// RecordDiscoveredCertificate upserts a discovered certificate keyed on its
// (endpoint, fingerprint): re-scanning the same certificate on the same endpoint
// refreshes its analysis (flags, severity, timestamps) in place rather than
// creating a duplicate row.
func (db *DB) RecordDiscoveredCertificate(d *models.DiscoveredCertificate) error {
	tenantID := d.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	sans, _ := json.Marshal(d.SANs)
	flags, _ := json.Marshal(d.Flags)
	severity := d.Severity
	if severity == "" {
		severity = "ok"
	}

	q := db.upsert("discovered_certificates",
		`id, tenant_id, endpoint, server_name, subject, common_name, sans, issuer,
		 serial, not_before, not_after, key_algorithm, key_size, signature_algorithm,
		 chain_length, chain_complete, fingerprint, certificate, issued_by_pki, rogue,
		 self_signed, weak_key, sha1_signature, hostname_mismatch, expiring_soon,
		 severity, flags, discovered_at`,
		`?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`,
		"endpoint, fingerprint",
		`server_name = excluded.server_name,
		 subject = excluded.subject,
		 common_name = excluded.common_name,
		 sans = excluded.sans,
		 issuer = excluded.issuer,
		 serial = excluded.serial,
		 not_before = excluded.not_before,
		 not_after = excluded.not_after,
		 key_algorithm = excluded.key_algorithm,
		 key_size = excluded.key_size,
		 signature_algorithm = excluded.signature_algorithm,
		 chain_length = excluded.chain_length,
		 chain_complete = excluded.chain_complete,
		 certificate = excluded.certificate,
		 issued_by_pki = excluded.issued_by_pki,
		 rogue = excluded.rogue,
		 self_signed = excluded.self_signed,
		 weak_key = excluded.weak_key,
		 sha1_signature = excluded.sha1_signature,
		 hostname_mismatch = excluded.hostname_mismatch,
		 expiring_soon = excluded.expiring_soon,
		 severity = excluded.severity,
		 flags = excluded.flags,
		 discovered_at = excluded.discovered_at`)

	_, err := db.exec(q,
		d.ID, tenantID, d.Endpoint, nullString(d.ServerName), nullString(d.Subject),
		nullString(d.CommonName), string(sans), nullString(d.Issuer), nullString(d.Serial),
		d.NotBefore, d.NotAfter, nullString(d.KeyAlgorithm), d.KeySize,
		nullString(d.SignatureAlgorithm), d.ChainLength, b2i(d.ChainComplete), d.Fingerprint,
		nullString(d.Certificate), b2i(d.IssuedByPKI), b2i(d.Rogue), b2i(d.SelfSigned),
		b2i(d.WeakKey), b2i(d.SHA1Signature), b2i(d.HostnameMismatch), b2i(d.ExpiringSoon),
		severity, string(flags), d.DiscoveredAt,
	)
	return err
}

func scanDiscoveredCert(s caScanner) (*models.DiscoveredCertificate, error) {
	var d models.DiscoveredCertificate
	var serverName, subject, commonName, sans, issuer, serial sql.NullString
	var keyAlg, sigAlg, fingerprint, certificate, flags sql.NullString
	var notBefore, notAfter sql.NullTime
	var chainComplete, issuedByPKI, rogue, selfSigned, weakKey, sha1Sig, hostnameMismatch, expiringSoon int
	if err := s.Scan(
		&d.ID, &d.TenantID, &d.Endpoint, &serverName, &subject, &commonName,
		&sans, &issuer, &serial, &notBefore, &notAfter, &keyAlg, &d.KeySize,
		&sigAlg, &d.ChainLength, &chainComplete, &fingerprint, &certificate,
		&issuedByPKI, &rogue, &selfSigned, &weakKey, &sha1Sig, &hostnameMismatch,
		&expiringSoon, &d.Severity, &flags, &d.DiscoveredAt,
	); err != nil {
		return nil, err
	}
	d.ServerName = serverName.String
	d.Subject = subject.String
	d.CommonName = commonName.String
	d.Issuer = issuer.String
	d.Serial = serial.String
	d.KeyAlgorithm = keyAlg.String
	d.SignatureAlgorithm = sigAlg.String
	d.Fingerprint = fingerprint.String
	d.Certificate = certificate.String
	if notBefore.Valid {
		d.NotBefore = notBefore.Time
	}
	if notAfter.Valid {
		d.NotAfter = notAfter.Time
	}
	d.ChainComplete = chainComplete != 0
	d.IssuedByPKI = issuedByPKI != 0
	d.Rogue = rogue != 0
	d.SelfSigned = selfSigned != 0
	d.WeakKey = weakKey != 0
	d.SHA1Signature = sha1Sig != 0
	d.HostnameMismatch = hostnameMismatch != 0
	d.ExpiringSoon = expiringSoon != 0
	if sans.Valid && sans.String != "" {
		json.Unmarshal([]byte(sans.String), &d.SANs)
	}
	if flags.Valid && flags.String != "" {
		json.Unmarshal([]byte(flags.String), &d.Flags)
	}
	if d.TenantID == "" {
		d.TenantID = models.DefaultTenantID
	}
	return &d, nil
}

// ListDiscoveredCertificates returns discovered certificates, newest first. An
// empty tenantID returns every tenant's records (used by the CLI and platform
// admins); a specific tenantID scopes the read to that tenant.
func (db *DB) ListDiscoveredCertificates(tenantID string) ([]models.DiscoveredCertificate, error) {
	q := `SELECT ` + discoveredCertColumns + ` FROM discovered_certificates`
	var args []interface{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	q += ` ORDER BY discovered_at DESC`
	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.DiscoveredCertificate
	for rows.Next() {
		d, err := scanDiscoveredCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// DeleteDiscoveredCertificate removes a discovered-certificate record by id.
func (db *DB) DeleteDiscoveredCertificate(id string) error {
	_, err := db.exec(`DELETE FROM discovered_certificates WHERE id = ?`, id)
	return err
}
