package handlers

import (
	"crypto/x509"
	"encoding/csv"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/report"
)

// reportFilter parses the shared report/inventory query parameters into a
// report.Filter. Bad time values are reported to the caller.
func reportFilter(r *http.Request) (report.Filter, error) {
	q := r.URL.Query()
	f := report.Filter{
		CAID:    strings.TrimSpace(q.Get("ca_id")),
		Profile: strings.TrimSpace(q.Get("profile")),
		// Synthetic issuance-canary probe certificates are excluded unless the
		// caller opts in.
		IncludeSynthetic: q.Get("include_synthetic") == "true",
	}
	parse := func(key string) (time.Time, error) {
		v := strings.TrimSpace(q.Get(key))
		if v == "" {
			return time.Time{}, nil
		}
		// Accept both a full RFC 3339 timestamp and a bare YYYY-MM-DD date, so the
		// console's date pickers (which submit dates) work without a time part.
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, nil
		}
		return time.Parse("2006-01-02", v)
	}
	var err error
	if f.From, err = parse("from"); err != nil {
		return f, err
	}
	if f.To, err = parse("to"); err != nil {
		return f, err
	}
	return f, nil
}

// ReportInventory returns the certificate inventory across the filtered CAs.
// Read-gated like the other inventory endpoints. With ?format=csv it streams the
// inventory as a spreadsheet-friendly CSV (used by the console's "Export CSV"
// button); otherwise it returns the full report.Inventory JSON.
func (a *API) ReportInventory(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	f, err := reportFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid filter: %v", err)
		return
	}
	inv, err := report.BuildInventory(a.db, f, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build inventory: %v", err)
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		writeInventoryCSV(w, inv)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// writeInventoryCSV renders a certificate inventory as CSV. The column order is
// stable so downstream tooling can rely on it.
func writeInventoryCSV(w http.ResponseWriter, inv *report.Inventory) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=certificate-inventory.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"ca_id", "ca_subject", "serial", "common_name", "subject", "sans",
		"profile", "not_before", "not_after", "status", "revoked_at",
		"revocation_reason", "ct_status", "sct_count", "lint_verdict", "lint_findings",
	})
	for _, c := range inv.Certificates {
		revokedAt := ""
		if c.RevokedAt != nil {
			revokedAt = c.RevokedAt.UTC().Format(time.RFC3339)
		}
		reason := ""
		if c.RevocationText != "" {
			reason = c.RevocationText
		}
		_ = cw.Write([]string{
			c.CAID, c.CASubject, c.Serial, c.CommonName, c.Subject,
			strings.Join(c.SANs, " "), c.Profile,
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339),
			c.Status, revokedAt, reason, c.CTStatus, strconv.Itoa(c.SCTCount),
			c.LintVerdict, strings.Join(c.LintFindings, " "),
		})
	}
	cw.Flush()
}

// ReportCompliance returns the CA/Browser-Forum conformance evidence pack (lint
// pass/warn/blocked summary, per-CA metadata, profile breakdown, key-ceremony
// evidence, and the tamper-evident audit-chain verification). Read-gated.
func (a *API) ReportCompliance(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	f, err := reportFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid filter: %v", err)
		return
	}
	rep, err := report.BuildCompliance(a.db, f, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build compliance report: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// crlScopeStatus is the parsed metadata of a single (base or delta) CRL.
type crlScopeStatus struct {
	Available    bool       `json:"available"`
	Number       string     `json:"number,omitempty"`
	BaseCRLNumer string     `json:"base_crl_number,omitempty"`
	ThisUpdate   *time.Time `json:"this_update,omitempty"`
	NextUpdate   *time.Time `json:"next_update,omitempty"`
	Expired      bool       `json:"expired"`
	RevokedCount int        `json:"revoked_count"`
}

// crlStatusResponse is the CRL/delta-CRL status view backing the console.
type crlStatusResponse struct {
	CAID       string         `json:"ca_id"`
	Sharded    bool           `json:"sharded"`
	ShardCount int            `json:"shard_count"`
	Base       crlScopeStatus `json:"base"`
	Delta      crlScopeStatus `json:"delta"`
}

// CRLStatus returns the freshness and revocation-count metadata of a CA's
// complete (base) CRL and its delta CRL, by generating (or serving the cached)
// CRLs and parsing them. Read-gated: relying parties fetch the CRL bytes
// unauthenticated from /crl, but the operator status view is inventory data.
func (a *API) CRLStatus(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	caID := r.PathValue("id")
	mgr := ca.NewManager(a.db, a.keyProvider)

	resp := crlStatusResponse{
		CAID:       caID,
		Sharded:    ca.CRLShardCount() > 1,
		ShardCount: ca.CRLShardCount(),
	}

	baseDER, err := mgr.GetBaseCRL(r.Context(), caID, ca.FullScope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate CRL: %v", err)
		return
	}
	resp.Base = parseCRLStatus(baseDER)

	// The delta is best-effort: a CA with delta CRLs disabled still yields an
	// (empty) delta here, but any failure just leaves the delta section absent.
	if deltaDER, derr := mgr.GetDeltaCRL(r.Context(), caID, ca.FullScope); derr == nil {
		resp.Delta = parseCRLStatus(deltaDER)
	}

	writeJSON(w, http.StatusOK, resp)
}

// deltaCRLIndicatorOID is the RFC 5280 Delta CRL Indicator extension (2.5.29.27);
// its value is the base CRL number the delta is relative to.
var deltaCRLIndicatorOID = []int{2, 5, 29, 27}

// parseCRLStatus projects a CRL's DER into the status view. A parse failure
// yields an unavailable entry rather than an error, so one malformed scope does
// not sink the whole response.
func parseCRLStatus(der []byte) crlScopeStatus {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return crlScopeStatus{}
	}
	st := crlScopeStatus{
		Available:    true,
		RevokedCount: len(crl.RevokedCertificateEntries),
	}
	if crl.Number != nil {
		st.Number = crl.Number.String()
	}
	tu := crl.ThisUpdate
	st.ThisUpdate = &tu
	if !crl.NextUpdate.IsZero() {
		nu := crl.NextUpdate
		st.NextUpdate = &nu
		st.Expired = time.Now().After(nu)
	}
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(deltaCRLIndicatorOID) {
			if base, ok := parseASN1Integer(ext.Value); ok {
				st.BaseCRLNumer = base.String()
			}
		}
	}
	return st
}

// parseASN1Integer decodes a DER-encoded INTEGER (the Delta CRL Indicator's
// value) into a big.Int, best-effort.
func parseASN1Integer(der []byte) (*big.Int, bool) {
	// A DER INTEGER is: 0x02 <len> <big-endian bytes>. Keep this dependency-free
	// and tolerant: anything unexpected just yields no base number.
	if len(der) < 2 || der[0] != 0x02 {
		return nil, false
	}
	l := int(der[1])
	if l <= 0 || 2+l > len(der) {
		return nil, false
	}
	return new(big.Int).SetBytes(der[2 : 2+l]), true
}
