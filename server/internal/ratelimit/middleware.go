package ratelimit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// Prefixes carries the mount points of the public protocol servers so the
// middleware can classify a request from its path alone, without duplicating
// the routing tables. Empty fields disable classification for that protocol.
type Prefixes struct {
	ACME string // e.g. "/acme"
	EST  string // e.g. "/.well-known/est"
	SCEP string // e.g. "/scep"
	TSA  string // e.g. "/tsa"
	CMP  string // e.g. "/cmp"
	Sign string // e.g. "/api/sign" (authenticated, but HSM-bound per request)
}

// TenantState is what the middleware needs to know about the tenant behind a
// public enrollment request (Task 61): whether the tenant may enroll at all,
// and its per-tenant rate override, if any.
type TenantState struct {
	// ID is the tenant identifier, used as the per-tenant bucket key.
	ID string
	// Suspended blocks the tenant's enrollment endpoints outright (403). The
	// OCSP/CRL classes are never tenant-blocked: relying parties must keep
	// validating a suspended tenant's already-issued certificates.
	Suspended bool
	// Limit optionally overrides the deployment-wide per-tenant rate for this
	// tenant. nil inherits the configured default.
	Limit *Rate
}

// Options configures the rate-limit middleware.
type Options struct {
	Limiter  *TieredLimiter
	Guard    *Guard
	Prefixes Prefixes
	// TenantState resolves the tenant behind a public enrollment request, keyed
	// by the endpoint class the middleware assigned (e.g. "acme_new_order",
	// "est_enroll"). Enrollment protocol instances are each bound to one CA and
	// therefore one tenant, so the resolution is per protocol, not per caller.
	// nil (or a nil result) disables tenant-aware handling for the request.
	TenantState func(r *http.Request, endpoint string) *TenantState
}

// Middleware applies tiered rate limiting and the HSM concurrency guard to the
// public-facing endpoints, passing every other request through untouched.
type Middleware struct {
	limiter     *TieredLimiter
	guard       *Guard
	prefixes    Prefixes
	tenantState func(r *http.Request, endpoint string) *TenantState
}

// New builds the middleware. Path prefixes are normalized (leading slash, no
// trailing slash) so classification matches regardless of how they were
// configured.
func New(opts Options) *Middleware {
	return &Middleware{
		limiter:     opts.Limiter,
		guard:       opts.Guard,
		tenantState: opts.TenantState,
		prefixes: Prefixes{
			ACME: normalizePrefix(opts.Prefixes.ACME),
			EST:  normalizePrefix(opts.Prefixes.EST),
			SCEP: normalizePrefix(opts.Prefixes.SCEP),
			TSA:  normalizePrefix(opts.Prefixes.TSA),
			CMP:  normalizePrefix(opts.Prefixes.CMP),
			Sign: normalizePrefix(opts.Prefixes.Sign),
		},
	}
}

// Active reports whether the middleware would enforce anything. When false the
// caller may skip installing it.
func (m *Middleware) Active() bool {
	if m == nil {
		return false
	}
	return (m.limiter != nil && m.limiter.Enabled()) ||
		(m.guard != nil && m.guard.Enabled()) ||
		m.tenantState != nil
}

func normalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return "/" + strings.Trim(p, "/")
}

// class describes how a matched public endpoint is metered.
type class struct {
	name     string // metric label, e.g. "acme_new_order"
	hsmBound bool   // gate behind the concurrency guard (signing/enrollment)
	acme     bool   // emit RFC 8555 problem+json on rejection
	account  func(*http.Request) string
	// tenantScoped marks the enrollment protocol surfaces that belong to one
	// tenant (via the protocol instance's bound CA): they honor the per-tenant
	// rate tier and are blocked outright while the tenant is suspended. The
	// OCSP/CRL and TSA classes deliberately stay false — revocation status for
	// already-issued certificates must keep flowing to relying parties, and the
	// timestamp authority is deployment-scoped.
	tenantScoped bool
}

// Handler wraps next with rate limiting and the HSM concurrency guard for the
// public endpoints. Requests that do not match a public endpoint pass straight
// through.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := m.classify(r)
		if c == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Resolve the tenant behind a tenant-scoped enrollment endpoint. A
		// suspended tenant's enrollment surface is refused outright — one 403
		// wall in front of the whole protocol — while OCSP/CRL (never
		// tenant-scoped) keep serving its already-issued certificates. This
		// complements the fail-closed gate inside the CA manager, which holds
		// even when this middleware is not installed.
		var tenant *TenantState
		if c.tenantScoped && m.tenantState != nil {
			tenant = m.tenantState(r, c.name)
			if tenant != nil && tenant.Suspended {
				metrics.TenantDenied.Inc(metrics.TenantLabel(tenant.ID), "suspended")
				writeTenantSuspended(w, c)
				return
			}
		}

		limiterActive := m.limiter != nil && (m.limiter.Enabled() ||
			(tenant != nil && tenant.Limit != nil))
		if limiterActive {
			keys := Keys{IP: clientIP(r)}
			if tenant != nil {
				keys.Tenant = tenant.ID
				keys.TenantLimit = tenant.Limit
			}
			if c.account != nil {
				keys.Account = c.account(r)
				// Namespace the per-account bucket by tenant so accounts of
				// different tenants never share a quota bucket (and one tenant
				// cannot exhaust another's per-account allowance). The tenant
				// selector is carried in the X-Secsy-Tenant header on public
				// requests; absent it, the default namespace applies.
				if keys.Account != "" {
					if tenant := r.Header.Get("X-Secsy-Tenant"); tenant != "" {
						keys.Account = "t:" + tenant + "|" + keys.Account
					}
				}
			}
			if d := m.limiter.Allow(keys); !d.Allowed {
				metrics.RateLimitThrottled.Inc(c.name, d.Tier)
				if d.Tier == TierPerTenant && tenant != nil {
					metrics.TenantDenied.Inc(metrics.TenantLabel(tenant.ID), "rate_limit")
				}
				writeThrottled(w, c, d.RetryAfter)
				return
			}
			metrics.RateLimitAdmitted.Inc(c.name)
		}

		// Gate HSM-bound endpoints (issuance, enrollment) behind the bounded
		// in-flight guard so overload sheds fast instead of piling up behind the
		// PKCS#11 session pool.
		if c.hsmBound && m.guard != nil && m.guard.Enabled() {
			release, err := m.guard.Acquire(r.Context())
			if err != nil {
				metrics.HSMGuardRejected.Inc(c.name, guardReason(err))
				writeGuardRejected(w, c, err)
				return
			}
			defer release()
		}

		next.ServeHTTP(w, r)
	})
}

// classify maps a request to its metering class, or returns nil when the path
// is not a rate-limited public endpoint.
func (m *Middleware) classify(r *http.Request) *class {
	path := r.URL.Path

	// OCSP / CRL live under the CA API but are unauthenticated public endpoints.
	if strings.HasPrefix(path, "/api/ca/") {
		switch {
		case strings.HasSuffix(path, "/crl"):
			return &class{name: "crl"}
		case strings.Contains(path, "/ocsp"):
			return &class{name: "ocsp"}
		}
	}

	if p := m.prefixes.ACME; p != "" && underPrefix(path, p) {
		switch {
		case strings.HasSuffix(path, "/new-account"):
			return &class{name: "acme_new_account", acme: true, tenantScoped: true}
		case strings.HasSuffix(path, "/new-order"):
			return &class{name: "acme_new_order", acme: true, account: acmeAccount, tenantScoped: true}
		case strings.HasSuffix(path, "/finalize"):
			return &class{name: "acme_finalize", hsmBound: true, acme: true, account: acmeAccount, tenantScoped: true}
		case strings.Contains(path, "/renewal-info"):
			// ARI (draft-ietf-acme-ari): an unauthenticated GET carrying no JWS, so
			// it is metered by the global and per-IP tiers only (no account key).
			return &class{name: "acme_renewal_info", acme: true, tenantScoped: true}
		default:
			return &class{name: "acme_other", acme: true, account: acmeAccount, tenantScoped: true}
		}
	}

	if p := m.prefixes.EST; p != "" && underPrefix(path, p) {
		switch {
		case strings.HasSuffix(path, "/simpleenroll"),
			strings.HasSuffix(path, "/simplereenroll"),
			strings.HasSuffix(path, "/serverkeygen"):
			return &class{name: "est_enroll", hsmBound: true, account: estAccount, tenantScoped: true}
		default:
			return &class{name: "est_other", tenantScoped: true}
		}
	}

	if p := m.prefixes.SCEP; p != "" && (path == p || path == p+"/pkiclient.exe") {
		if r.Method == http.MethodPost && strings.EqualFold(r.URL.Query().Get("operation"), "PKIOperation") {
			return &class{name: "scep_enroll", hsmBound: true, tenantScoped: true}
		}
		return &class{name: "scep_other", tenantScoped: true}
	}

	// RFC 3161 time-stamping signs on the HSM, so gate it behind the concurrency
	// guard like the other signing endpoints.
	if p := m.prefixes.TSA; p != "" && path == p {
		return &class{name: "tsa", hsmBound: true}
	}

	// Lightweight CMP (RFC 9483) issues/revokes on the HSM, so gate it behind the
	// concurrency guard like the other signing endpoints.
	if p := m.prefixes.CMP; p != "" && path == p {
		return &class{name: "cmp", hsmBound: true, tenantScoped: true}
	}

	// Artifact signing. POST /api/sign signs on the HSM, so it is both metered
	// and gated behind the concurrency guard; verification and the signer
	// listing are CPU-only, so they are metered but never queue on the HSM
	// guard. Requests are keyed per credential (Basic user or bearer-token
	// digest) so one pipeline cannot starve others behind the same NAT.
	if p := m.prefixes.Sign; p != "" && underPrefix(path, p) {
		if path == p && r.Method == http.MethodPost {
			return &class{name: "artifact_sign", hsmBound: true, account: apiAccount}
		}
		return &class{name: "artifact_sign_other", account: apiAccount}
	}

	return nil
}

// underPrefix reports whether path is the prefix itself or a child of it.
func underPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// writeThrottled emits a 429 with a Retry-After header. For ACME endpoints it
// uses the RFC 8555 rateLimited problem document so compliant clients back off
// gracefully; other endpoints get a plain-text body.
func writeThrottled(w http.ResponseWriter, c *class, retryAfter time.Duration) {
	setRetryAfter(w, retryAfter)
	if c.acme {
		writeACMEProblem(w, http.StatusTooManyRequests,
			"urn:ietf:params:acme:error:rateLimited",
			"request rate limit exceeded; slow down and honor the Retry-After header")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	io.WriteString(w, "429 Too Many Requests: rate limit exceeded\n")
}

// writeTenantSuspended refuses an enrollment request because its tenant is
// suspended. Unlike a throttle this is not retryable, so no Retry-After is
// sent; ACME clients get an RFC 8555 unauthorized problem.
func writeTenantSuspended(w http.ResponseWriter, c *class) {
	if c.acme {
		writeACMEProblem(w, http.StatusForbidden,
			"urn:ietf:params:acme:error:unauthorized",
			"the tenant behind this enrollment endpoint is suspended")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, "403 Forbidden: tenant is suspended; enrollment is disabled\n")
}

// writeGuardRejected responds when the HSM concurrency guard sheds a request.
// A saturated guard means the signing backend is momentarily overloaded, so we
// return 503 with a short Retry-After (a canceled client context yields no body).
func writeGuardRejected(w http.ResponseWriter, c *class, err error) {
	if errors.Is(err, context.Canceled) {
		// The client already went away; nothing useful to send.
		return
	}
	setRetryAfter(w, 2*time.Second)
	if c.acme {
		writeACMEProblem(w, http.StatusServiceUnavailable,
			"urn:ietf:params:acme:error:rateLimited",
			"issuance backend is at capacity; retry after the Retry-After header")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	io.WriteString(w, "503 Service Unavailable: issuance backend at capacity\n")
}

// setRetryAfter writes a Retry-After header in whole seconds (minimum 1).
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}

// writeACMEProblem writes an application/problem+json body per RFC 7807/8555.
func writeACMEProblem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"type":   typ,
		"detail": detail,
		"status": status,
	})
}

// guardReason maps a guard error to a stable metric label.
func guardReason(err error) string {
	switch {
	case errors.Is(err, ErrQueueFull):
		return "queue_full"
	case errors.Is(err, ErrAcquireTimeout):
		return "timeout"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	default:
		return "error"
	}
}

// clientIP returns the rate-limiting key for a request's source address. It
// honors X-Forwarded-For (the deployment terminates TLS at a trusted proxy),
// mirroring the observability middleware, and strips the port from a raw
// RemoteAddr so all connections from one host share a bucket.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// estAccount keys an EST request by its HTTP Basic username, so a single
// enrolling identity is metered independently of others sharing an IP.
func estAccount(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return "est:" + user
	}
	return ""
}

// apiAccount keys an authenticated API request by its credential: the Basic
// username when present, otherwise a digest of the Authorization header (a
// bearer token must never be used verbatim as a metric/bucket key). Cookie-
// session (console) callers fall back to the IP and global tiers.
func apiAccount(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return "api:" + user
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		sum := sha256.Sum256([]byte(auth))
		return "api:tok:" + hex.EncodeToString(sum[:8])
	}
	return ""
}

// maxJWSPeek bounds how much of an ACME request body we buffer to recover the
// account key ID. The JWS protected header is tiny; this is a safety cap.
const maxJWSPeek = 64 * 1024

// acmeAccount keys an ACME request by the account URL ("kid") in its JWS
// protected header, so per-account limits track the authenticated account
// rather than only its IP. It buffers and restores the request body so the
// downstream handler still reads the full JWS. Requests that carry an embedded
// JWK instead of a kid (e.g. newAccount) return "" and fall back to the IP and
// global tiers.
func acmeAccount(r *http.Request) string {
	if r.Method != http.MethodPost || r.Body == nil {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxJWSPeek))
	if err != nil {
		// Restore whatever we managed to read and give up on the account key.
		restoreBody(r, buf)
		return ""
	}
	restoreBody(r, buf)

	var env struct {
		Protected string `json:"protected"`
	}
	if json.Unmarshal(buf, &env) != nil || env.Protected == "" {
		return ""
	}
	hdr, err := b64urlDecode(env.Protected)
	if err != nil {
		return ""
	}
	var protected struct {
		KID string `json:"kid"`
	}
	if json.Unmarshal(hdr, &protected) != nil || protected.KID == "" {
		return ""
	}
	// The kid is an account URL; its final path segment is the account ID. Key
	// on that so it is stable and compact.
	kid := protected.KID
	if i := strings.LastIndexByte(kid, '/'); i >= 0 && i < len(kid)-1 {
		kid = kid[i+1:]
	}
	return "acme:" + kid
}

// restoreBody replaces r.Body so downstream readers see the bytes we consumed
// followed by any remainder (when the body exceeded our peek cap).
func restoreBody(r *http.Request, buf []byte) {
	rest := r.Body // whatever is left unread past the peek cap
	r.Body = &reReadCloser{
		r: io.MultiReader(bytes.NewReader(buf), rest),
		c: rest,
	}
}

type reReadCloser struct {
	r io.Reader
	c io.Closer
}

func (rc *reReadCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }
func (rc *reReadCloser) Close() error {
	if rc.c != nil {
		return rc.c.Close()
	}
	return nil
}

// b64urlDecode decodes base64url with or without padding (JWS uses the
// unpadded form, but be lenient).
func b64urlDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
