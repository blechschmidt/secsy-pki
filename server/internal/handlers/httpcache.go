package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RFC 5019 §6.2 (Lightweight OCSP Profile) HTTP caching. Public OCSP and CRL
// responses are signed objects valid until their nextUpdate, so CDNs and clients
// may cache and revalidate them. These constants cap the advertised freshness so
// a misconfigured or far-future nextUpdate can never pin an artifact in a shared
// cache for an unreasonable time; the natural max-age (nextUpdate − now) is used
// whenever it is smaller. The bounds mirror the default validity windows: 24h for
// OCSP responses (defaultOCSPValidity) and 7 days for CRLs (defaultCRLValidity),
// so a normally configured deployment is never truncated.
const (
	maxOCSPCacheAge = 24 * time.Hour
	maxCRLCacheAge  = 7 * 24 * time.Hour
)

// strongETag computes a strong ETag validator (RFC 7232 §2.3) over the exact
// bytes that will be served, returned already quoted. Extra parts (e.g. a CRL
// number) are folded into the hash so two artifacts that would serialize to the
// same bytes but represent distinct versions still validate differently. Because
// the validator is derived from the full served body it is a strong validator:
// byte-for-byte identity guarantees an identical ETag.
func strongETag(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return `"` + hex.EncodeToString(h.Sum(nil)) + `"`
}

// cacheableResponse describes a signed, publicly cacheable artifact (an OCSP
// response without a nonce, or a CRL) for the HTTP caching layer: the exact bytes
// to be served, the validity window carried inside the artifact, its strong ETag,
// and the upper bound applied to the advertised max-age.
type cacheableResponse struct {
	thisUpdate time.Time
	nextUpdate time.Time
	etag       string
	maxAge     time.Duration
}

// applyCacheHeaders sets RFC 5019 §6.2 / RFC 7234 caching headers on w for a
// signed, publicly cacheable response. It derives Cache-Control max-age and
// Expires from nextUpdate (clamped to [0, c.maxAge]), Last-Modified from
// thisUpdate, and sets the strong ETag. It then evaluates the request's
// conditional headers (If-None-Match, then If-Modified-Since) and reports whether
// the client already holds the current version, in which case the caller must
// answer 304 Not Modified with no body. Conditional evaluation is performed only
// for GET/HEAD, the methods for which 304 is defined (RFC 7232 §4.1).
func applyCacheHeaders(w http.ResponseWriter, r *http.Request, c cacheableResponse) (notModified bool) {
	now := time.Now()

	maxAge := time.Duration(0)
	if !c.nextUpdate.IsZero() {
		maxAge = c.nextUpdate.Sub(now)
	}
	if maxAge < 0 {
		maxAge = 0
	}
	if c.maxAge > 0 && maxAge > c.maxAge {
		maxAge = c.maxAge
	}
	// no-transform keeps proxies from altering the binary DER payload.
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, no-transform", int64(maxAge/time.Second)))

	if !c.nextUpdate.IsZero() {
		// Expires must never advertise a longer life than max-age permits.
		exp := now.Add(maxAge)
		if exp.After(c.nextUpdate) {
			exp = c.nextUpdate
		}
		w.Header().Set("Expires", exp.UTC().Format(http.TimeFormat))
	}
	if !c.thisUpdate.IsZero() {
		w.Header().Set("Last-Modified", c.thisUpdate.UTC().Format(http.TimeFormat))
	}
	if c.etag != "" {
		w.Header().Set("ETag", c.etag)
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	// If-None-Match takes precedence over If-Modified-Since (RFC 7232 §6): when a
	// validator is present the modification date is ignored entirely.
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return c.etag != "" && etagMatches(inm, c.etag)
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" && !c.thisUpdate.IsZero() {
		if since, err := http.ParseTime(ims); err == nil {
			// HTTP dates carry one-second precision; truncate before comparing so a
			// sub-second thisUpdate does not spuriously count as "modified since".
			return !c.thisUpdate.Truncate(time.Second).After(since)
		}
	}
	return false
}

// etagMatches reports whether an If-None-Match header field value matches etag.
// It accepts the "*" wildcard and a comma-separated list, and uses the weak
// comparison function (RFC 7232 §2.3.2) as required for If-None-Match: the
// optional weak "W/" prefix is ignored on both sides.
func etagMatches(ifNoneMatch, etag string) bool {
	want := strings.TrimPrefix(etag, "W/")
	for _, cand := range strings.Split(ifNoneMatch, ",") {
		cand = strings.TrimSpace(cand)
		if cand == "*" {
			return true
		}
		if strings.TrimPrefix(cand, "W/") == want {
			return true
		}
	}
	return false
}
