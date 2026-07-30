package database

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ErrInvalidCursor wraps every failure to decode a pagination cursor so callers
// can map a client-supplied bad cursor to a 400 rather than a 500. A cursor is
// opaque to clients, so any decode failure is a malformed request, not a store
// fault.
var ErrInvalidCursor = errors.New("invalid pagination cursor")

// Server-side pagination, filtering, and search for the certificate-inventory
// list endpoints (Task 83). The core list reads — issued, revoked, and
// discovered certificates — previously selected every matching row, which does
// not scale to large deployments. These paginated variants return one bounded
// page plus an opaque continuation cursor, the total number of matching rows,
// and a has-more flag. The full-dump ListIssuedCertificates / ...Revoked... /
// ...Discovered... methods are retained for the internal batch consumers (CRL
// generation, the expiry monitor, presigning, rotation, and reporting) that
// legitimately need the complete set.
//
// Pagination is keyset (a.k.a. seek) rather than offset based: the cursor
// encodes the (timestamp, tiebreaker) of the last row on a page and the next
// query returns rows ordering strictly after it under the newest-first sort.
// Unlike LIMIT/OFFSET this is stable while rows are inserted between page
// fetches — a new (newer) row never shifts an already-returned page — and it
// avoids the growing scan cost of a large OFFSET.

// DefaultPageSize is the page size used when a caller does not request one.
const DefaultPageSize = 100

// MaxPageSize is the hard ceiling on a single page. Callers (REST/gRPC/CLI)
// clamp requested page sizes to this; the store also caps defensively so a
// direct caller cannot request an unbounded read.
const MaxPageSize = 500

// CertFilter holds the optional predicates shared by the inventory list
// endpoints. A zero value applies no filtering. Not every field applies to
// every table — the revoked-certificate store, for example, records only
// (ca, serial, revoked_at, reason), so only SerialPrefix is meaningful there —
// and each Page* method applies exactly the predicates its table supports.
type CertFilter struct {
	// Status matches the certificate lifecycle status exactly (valid, revoked,
	// held, expired). Empty matches any. Applies to issued certificates.
	Status string
	// Profile matches the issuing profile exactly. Empty matches any. Applies to
	// issued certificates.
	Profile string
	// Query is a case-insensitive substring matched against the subject, common
	// name, and SANs (and, for discovered certificates, the issuer). Empty
	// disables the text search.
	Query string
	// SerialPrefix restricts to serials beginning with this decimal string.
	SerialPrefix string
	// ExpiresBefore restricts to certificates whose NotAfter is strictly before
	// this instant. The zero value applies no expiry bound. Applies to tables
	// that record NotAfter (issued, discovered).
	ExpiresBefore time.Time
	// PublicKeySHA256 restricts to certificates whose certified subject public
	// key has exactly this SubjectPublicKeyInfo fingerprint, in the canonical
	// "SHA256:<base64>" form the inventory stores (see keycheck.Fingerprint /
	// keycheck.NormalizeFingerprint). It is the key-compromise incident-response
	// filter: given a leaked key, find every certificate that shares it. Empty
	// applies no fingerprint bound. Applies to issued certificates.
	PublicKeySHA256 string
}

// CertPageRequest is the pagination window for a Page* read.
type CertPageRequest struct {
	// Limit is the maximum number of items to return. Values <= 0 fall back to
	// DefaultPageSize; values above MaxPageSize are clamped to it.
	Limit int
	// Cursor continues a previous page. Empty starts from the newest row. It is
	// the opaque NextCursor returned by the prior page and must not be
	// interpreted by clients.
	Cursor string
}

// effectiveLimit resolves the requested page size against the default and hard
// maximum.
func (p CertPageRequest) effectiveLimit() int {
	switch {
	case p.Limit <= 0:
		return DefaultPageSize
	case p.Limit > MaxPageSize:
		return MaxPageSize
	default:
		return p.Limit
	}
}

// IssuedCertPage is one page of issued certificates.
type IssuedCertPage struct {
	Items      []models.IssuedCertificate `json:"items"`
	NextCursor string                     `json:"next_cursor"`
	Total      int                        `json:"total"`
	HasMore    bool                       `json:"has_more"`
}

// RevokedCertPage is one page of revocation records.
type RevokedCertPage struct {
	Items      []models.RevokedCertificate `json:"items"`
	NextCursor string                      `json:"next_cursor"`
	Total      int                         `json:"total"`
	HasMore    bool                        `json:"has_more"`
}

// DiscoveredCertPage is one page of discovered (externally observed) certificates.
type DiscoveredCertPage struct {
	Items      []models.DiscoveredCertificate `json:"items"`
	NextCursor string                         `json:"next_cursor"`
	Total      int                            `json:"total"`
	HasMore    bool                           `json:"has_more"`
}

// cursorSep separates the timestamp and tiebreaker halves inside a decoded
// cursor. It is a control byte that cannot appear in an RFC 3339 timestamp or a
// decimal serial, so the split is unambiguous.
const cursorSep = 0x1f

// encodeCursor builds the opaque continuation token for a keyset page from the
// ordering timestamp and tiebreaker of the last row returned. The timestamp is
// rendered in UTC so it round-trips to the exact value the driver binds for the
// next page's comparison.
func encodeCursor(t time.Time, tiebreak string) string {
	raw := t.UTC().Format(time.RFC3339Nano) + string(rune(cursorSep)) + tiebreak
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor parses a token produced by encodeCursor. It returns a descriptive
// error (not a panic) for any malformed input so a hand-crafted cursor becomes a
// 400 rather than a 500.
func decodeCursor(s string) (t time.Time, tiebreak string, err error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: bad encoding: %v", ErrInvalidCursor, err)
	}
	i := bytes.IndexByte(b, cursorSep)
	if i < 0 {
		return time.Time{}, "", fmt.Errorf("%w: missing separator", ErrInvalidCursor)
	}
	t, err = time.Parse(time.RFC3339Nano, string(b[:i]))
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: bad timestamp: %v", ErrInvalidCursor, err)
	}
	return t.UTC(), string(b[i+1:]), nil
}

// escapeLike escapes the LIKE metacharacters in user-supplied text so a search
// term such as "50%" or "a_b" matches literally rather than as a wildcard. It
// pairs with an "ESCAPE '\'" clause, which both SQLite and PostgreSQL honor.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// filterColumns names the columns a given inventory table exposes to the shared
// CertFilter. An empty name means the table has no such column, so that
// predicate is skipped. Column names are compile-time constants, never user
// input, so they are safe to interpolate into SQL.
type filterColumns struct {
	status    string   // status column, or "" if absent
	profile   string   // profile column, or "" if absent
	serial    string   // serial column, or "" if absent
	notAfter  string   // not_after column, or "" if absent
	keyFprint string   // public-key fingerprint column, or "" if absent
	search    []string // text columns the free-text Query matches
}

// appendCertFilter appends the WHERE predicates for f (that the table supports)
// to b and their bound values to args. The caller has already opened the WHERE
// clause (e.g. with the mandatory tenant/CA scope), so every predicate is added
// as " AND …".
func appendCertFilter(b *strings.Builder, args *[]interface{}, f CertFilter, cols filterColumns) {
	if cols.status != "" && f.Status != "" {
		b.WriteString(" AND " + cols.status + " = ?")
		*args = append(*args, f.Status)
	}
	if cols.profile != "" && f.Profile != "" {
		b.WriteString(" AND " + cols.profile + " = ?")
		*args = append(*args, f.Profile)
	}
	if f.Query != "" && len(cols.search) > 0 {
		pattern := "%" + escapeLike(strings.ToLower(f.Query)) + "%"
		b.WriteString(" AND (")
		for i, c := range cols.search {
			if i > 0 {
				b.WriteString(" OR ")
			}
			b.WriteString("LOWER(" + c + ") LIKE ? ESCAPE '\\'")
			*args = append(*args, pattern)
		}
		b.WriteString(")")
	}
	if cols.serial != "" && f.SerialPrefix != "" {
		b.WriteString(" AND " + cols.serial + " LIKE ? ESCAPE '\\'")
		*args = append(*args, escapeLike(f.SerialPrefix)+"%")
	}
	if cols.notAfter != "" && !f.ExpiresBefore.IsZero() {
		b.WriteString(" AND " + cols.notAfter + " < ?")
		*args = append(*args, f.ExpiresBefore.UTC())
	}
	// Exact fingerprint match (no LIKE): the value is the canonical, fixed-length
	// "SHA256:<base64>" form, so equality both is correct and lets the index on
	// public_key_fingerprint serve the key-compromise lookup directly.
	if cols.keyFprint != "" && f.PublicKeySHA256 != "" {
		b.WriteString(" AND " + cols.keyFprint + " = ?")
		*args = append(*args, f.PublicKeySHA256)
	}
}

var issuedFilterCols = filterColumns{
	status:    "status",
	profile:   "profile",
	serial:    "serial",
	notAfter:  "not_after",
	keyFprint: "public_key_fingerprint",
	search:    []string{"subject", "common_name", "sans"},
}

// PageIssuedCertificates returns one keyset page of a CA's issued certificates,
// newest first, matching the filter. The cursor keys on (created_at, serial):
// created_at gives the newest-first order and serial breaks ties so pages remain
// stable and gap-free even when several certificates share a created_at instant.
func (db *DB) PageIssuedCertificates(caID string, f CertFilter, p CertPageRequest) (IssuedCertPage, error) {
	var where strings.Builder
	where.WriteString(" WHERE ca_id = ?")
	args := []interface{}{caID}
	appendCertFilter(&where, &args, f, issuedFilterCols)

	var page IssuedCertPage
	if err := db.queryRow(`SELECT COUNT(*) FROM issued_certificates`+where.String(), args...).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("counting issued certificates: %w", err)
	}

	limit := p.effectiveLimit()
	q := `SELECT ` + issuedCertColumns + ` FROM issued_certificates` + where.String()
	pargs := append([]interface{}(nil), args...)
	if p.Cursor != "" {
		ct, serial, err := decodeCursor(p.Cursor)
		if err != nil {
			return page, err
		}
		q += ` AND (created_at, serial) < (?, ?)`
		pargs = append(pargs, ct, serial)
	}
	q += ` ORDER BY created_at DESC, serial DESC LIMIT ?`
	pargs = append(pargs, limit+1) // fetch one extra to detect a further page

	rows, err := db.query(q, pargs...)
	if err != nil {
		return page, fmt.Errorf("listing issued certificates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanIssuedCert(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, *c)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > limit {
		page.HasMore = true
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.Serial)
	}
	return page, nil
}

// PageRevokedCertificates returns one keyset page of a CA's revocation records,
// newest revocation first. The revoked store records only (ca, serial,
// revoked_at, reason), so SerialPrefix is the only applicable filter; the cursor
// keys on (revoked_at, serial).
func (db *DB) PageRevokedCertificates(caID string, f CertFilter, p CertPageRequest) (RevokedCertPage, error) {
	var where strings.Builder
	where.WriteString(" WHERE ca_id = ?")
	args := []interface{}{caID}
	appendCertFilter(&where, &args, f, filterColumns{serial: "serial"})

	var page RevokedCertPage
	if err := db.queryRow(`SELECT COUNT(*) FROM revoked_certificates`+where.String(), args...).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("counting revoked certificates: %w", err)
	}

	limit := p.effectiveLimit()
	q := `SELECT ca_id, serial, revoked_at, reason FROM revoked_certificates` + where.String()
	pargs := append([]interface{}(nil), args...)
	if p.Cursor != "" {
		rt, serial, err := decodeCursor(p.Cursor)
		if err != nil {
			return page, err
		}
		q += ` AND (revoked_at, serial) < (?, ?)`
		pargs = append(pargs, rt, serial)
	}
	q += ` ORDER BY revoked_at DESC, serial DESC LIMIT ?`
	pargs = append(pargs, limit+1)

	rows, err := db.query(q, pargs...)
	if err != nil {
		return page, fmt.Errorf("listing revoked certificates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rc models.RevokedCertificate
		if err := rows.Scan(&rc.CAID, &rc.Serial, &rc.RevokedAt, &rc.Reason); err != nil {
			return page, err
		}
		page.Items = append(page.Items, rc)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > limit {
		page.HasMore = true
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.RevokedAt, last.Serial)
	}
	return page, nil
}

var discoveredFilterCols = filterColumns{
	serial:   "serial",
	notAfter: "not_after",
	search:   []string{"subject", "common_name", "sans", "issuer"},
}

// PageDiscoveredCertificates returns one keyset page of discovered (externally
// observed) certificates, newest observation first. An empty tenantID reads
// across every tenant (platform/CLI view); a specific tenantID scopes the read.
// The cursor keys on (discovered_at, id) — id is the row's UUID primary key, a
// stable tiebreaker since a discovered serial may repeat or be absent.
func (db *DB) PageDiscoveredCertificates(tenantID string, f CertFilter, p CertPageRequest) (DiscoveredCertPage, error) {
	var where strings.Builder
	where.WriteString(" WHERE 1 = 1")
	var args []interface{}
	if tenantID != "" {
		where.WriteString(" AND tenant_id = ?")
		args = append(args, tenantID)
	}
	appendCertFilter(&where, &args, f, discoveredFilterCols)

	var page DiscoveredCertPage
	if err := db.queryRow(`SELECT COUNT(*) FROM discovered_certificates`+where.String(), args...).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("counting discovered certificates: %w", err)
	}

	limit := p.effectiveLimit()
	q := `SELECT ` + discoveredCertColumns + ` FROM discovered_certificates` + where.String()
	pargs := append([]interface{}(nil), args...)
	if p.Cursor != "" {
		dt, id, err := decodeCursor(p.Cursor)
		if err != nil {
			return page, err
		}
		q += ` AND (discovered_at, id) < (?, ?)`
		pargs = append(pargs, dt, id)
	}
	q += ` ORDER BY discovered_at DESC, id DESC LIMIT ?`
	pargs = append(pargs, limit+1)

	rows, err := db.query(q, pargs...)
	if err != nil {
		return page, fmt.Errorf("listing discovered certificates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		d, err := scanDiscoveredCert(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, *d)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > limit {
		page.HasMore = true
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.DiscoveredAt, last.ID)
	}
	return page, nil
}
