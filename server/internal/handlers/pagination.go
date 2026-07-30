package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
)

// Shared query-parameter parsing for the paginated inventory list endpoints
// (Task 83): ?limit, ?cursor, ?status, ?profile, ?q, ?serial_prefix,
// ?expires_before, and ?public_key_sha256. The page size defaults to
// database.DefaultPageSize and is clamped to the hard maximum
// database.MaxPageSize.

// parseCertListParams reads the pagination and filter parameters. It returns a
// filter, a page request, and clamped=true when the caller asked for a larger
// page than the hard maximum (so the handler can log the truncation). A
// malformed ?expires_before or ?public_key_sha256 is a request error; a
// malformed ?limit is treated leniently (falls back to the default), matching
// the existing list endpoints.
func parseCertListParams(r *http.Request) (database.CertFilter, database.CertPageRequest, bool, error) {
	q := r.URL.Query()
	f := database.CertFilter{
		Status:       q.Get("status"),
		Profile:      q.Get("profile"),
		Query:        q.Get("q"),
		SerialPrefix: q.Get("serial_prefix"),
	}
	if v := q.Get("expires_before"); v != "" {
		t, err := parseTimeParam(v)
		if err != nil {
			return f, database.CertPageRequest{}, false, fmt.Errorf("invalid expires_before %q: want RFC3339 or YYYY-MM-DD", v)
		}
		f.ExpiresBefore = t
	}
	// public_key_sha256 is the key-compromise search: locate every certificate
	// sharing a leaked subject public key. Accept either a hex SHA-256 of the
	// SubjectPublicKeyInfo or the canonical "SHA256:<base64>" fingerprint, and
	// normalize to the stored form so the equality match succeeds. A malformed
	// value is a request error rather than a silent empty page.
	if v := q.Get("public_key_sha256"); v != "" {
		fp, err := keycheck.NormalizeFingerprint(v)
		if err != nil {
			return f, database.CertPageRequest{}, false, fmt.Errorf("invalid public_key_sha256: %w", err)
		}
		f.PublicKeySHA256 = fp
	}

	p := database.CertPageRequest{Cursor: q.Get("cursor"), Limit: database.DefaultPageSize}
	clamped := false
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > database.MaxPageSize {
				p.Limit = database.MaxPageSize
				clamped = true
			} else {
				p.Limit = n
			}
		}
	}
	return f, p, clamped, nil
}

// parseTimeParam accepts an RFC 3339 timestamp or a bare calendar date
// (YYYY-MM-DD, interpreted as UTC midnight) for the expires_before window.
func parseTimeParam(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", v)
}

// logPageTruncation emits an operational log line when a list response does not
// return the full matching set — either because the caller's requested page size
// exceeded the hard maximum (clamped) or because more matching rows remain past
// this page (hasMore). It gives operators visibility that a client may be seeing
// a partial view of a large inventory.
func logPageTruncation(r *http.Request, endpoint string, returned, total int, clamped, hasMore bool) {
	if !clamped && !hasMore {
		return
	}
	reason := "more_pages"
	if clamped {
		reason = "page_size_clamped"
	}
	log.Printf("inventory list truncated: endpoint=%s path=%s returned=%d total=%d max=%d reason=%s",
		endpoint, r.URL.Path, returned, total, database.MaxPageSize, reason)
}
