package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/certvalidate"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Certificate chain/path validation service (Task 123): POST /api/validate,
// mirrored on gRPC (ValidateChain) and by `secsy-ca validate-cert`.
//
// Given a supplied leaf (and optional intermediates) as PEM or DER, it builds and
// validates a certification path against a named CA's configured trust anchors
// and returns a structured verdict — whether a chain was built (with the resolved
// chain), the effective validity window, per-certificate live revocation status
// (CRL + OCSP store, including the reversible on-hold state), name-constraint and
// certificate-policy conformance, weak-key/weak-signature flags, and an overall
// pass/fail with human-readable reasons.
//
// The endpoint is a pure read: no HSM is touched, nothing is signed, no serial is
// allocated, and no audit event or metric is recorded. Authorization is the same
// tenant-scoped read standing a CA GET requires (canRead + tenant membership on
// the referenced CA), so an auditor can validate a chain without any issuing
// capability.

// ValidateChainRequest is the POST /api/validate body.
type ValidateChainRequest struct {
	// CA is the id or label of the CA whose configured trust anchors the path is
	// validated against (required). It also scopes the request to that CA's tenant.
	CA string `json:"ca"`
	// Certificate is the leaf to validate, PEM-encoded. A PEM bundle carrying the
	// leaf followed by intermediates is accepted — the first certificate is the
	// leaf and the remainder are treated as supplied intermediates.
	Certificate string `json:"certificate"`
	// Intermediates are additional intermediate CA certificates (PEM), each a
	// single certificate or a bundle, used to bridge the path when the caller did
	// not fold them into Certificate.
	Intermediates []string `json:"intermediates,omitempty"`
	// SkipRevocation disables the live per-certificate revocation lookups (CRL +
	// OCSP store). Revocation is checked by default.
	SkipRevocation bool `json:"skip_revocation,omitempty"`
}

// ValidateChainResponse is the POST /api/validate response: the structured
// certvalidate.Report flattened alongside the resolved CA identity.
type ValidateChainResponse struct {
	CAID    string `json:"ca_id"`
	CALabel string `json:"ca_label"`
	*certvalidate.Report
}

// ValidateChain handles POST /api/validate.
func (a *API) ValidateChain(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	var req ValidateChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if strings.TrimSpace(req.CA) == "" {
		writeError(w, http.StatusBadRequest, "ca (the trust-anchor CA id or label) is required")
		return
	}

	// Resolve the CA id-or-label, then enforce read + tenant membership. Tenant
	// scoping runs before any body validation so a cross-tenant caller gets a
	// non-disclosing 404 rather than a hint that the certificate was malformed.
	caID, ok := a.resolveCARefID(req.CA)
	if !ok {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	caModel, ok := a.authorizeCARead(w, r, caID)
	if !ok {
		return
	}

	if strings.TrimSpace(req.Certificate) == "" {
		writeError(w, http.StatusBadRequest, "certificate (the leaf to validate, PEM or DER) is required")
		return
	}

	intermediates := make([][]byte, 0, len(req.Intermediates))
	for _, im := range req.Intermediates {
		if strings.TrimSpace(im) == "" {
			continue
		}
		intermediates = append(intermediates, []byte(im))
	}

	report, err := a.RunChainValidation(r.Context(), caModel, []byte(req.Certificate), intermediates, req.SkipRevocation)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, ValidateChainResponse{CAID: caModel.ID, CALabel: caModel.Label, Report: report})
}

// resolveCARefID resolves a CA id-or-label to a CA id, without any authorization
// (the caller must still authorize the resolved id). It returns ok=false when no
// CA matches.
func (a *API) resolveCARefID(ref string) (string, bool) {
	if c, err := a.db.GetCA(ref); err == nil && c != nil {
		return c.ID, true
	}
	if c, err := a.db.GetCAByLabel(ref); err == nil && c != nil {
		return c.ID, true
	}
	return "", false
}

// RunChainValidation is the transport-agnostic core shared by the REST and gRPC
// surfaces. Given an already-resolved (and authorized) CA, it assembles that CA's
// trust anchors and a live revocation resolver, parses the supplied leaf and
// intermediates (PEM or DER), and runs the certvalidate engine. It performs no
// HSM operation and records nothing.
func (a *API) RunChainValidation(ctx context.Context, caModel *models.CA, leaf []byte, intermediates [][]byte, skipRevocation bool) (*certvalidate.Report, error) {
	leafCert, supplied, err := parseValidationInput(leaf, intermediates)
	if err != nil {
		return nil, err
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	roots, inter, err := mgr.TrustAnchorsFor(caModel.ID)
	if err != nil {
		return nil, fmt.Errorf("resolving trust anchors for CA %q: %w", caModel.Label, err)
	}
	opts := certvalidate.Options{
		Roots:            roots,
		Intermediates:    inter,
		TrustAnchorLabel: trustAnchorLabel(caModel),
	}
	if !skipRevocation {
		cas, err := a.db.ListCAsForTenant(caModel.TenantID)
		if err != nil {
			return nil, fmt.Errorf("loading tenant CAs for revocation checking: %w", err)
		}
		opts.Revocation = mgr.NewChainRevocationResolver(cas)
	}
	return certvalidate.Validate(opts, leafCert, supplied), nil
}

// trustAnchorLabel renders a human label for the CA the path is validated against.
func trustAnchorLabel(caModel *models.CA) string {
	if caModel.Subject != "" {
		return fmt.Sprintf("%s (%s)", caModel.Label, caModel.Subject)
	}
	return caModel.Label
}

// parseValidationInput parses the leaf (and any intermediates folded into the
// same blob) plus each supplied intermediate blob, tolerating both PEM (including
// multi-certificate bundles) and raw DER.
func parseValidationInput(leaf []byte, intermediates [][]byte) (*x509.Certificate, []*x509.Certificate, error) {
	leafAndChain, err := parseCertsFlexible(leaf)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing certificate: %w", err)
	}
	if len(leafAndChain) == 0 {
		return nil, nil, fmt.Errorf("no certificate found in the supplied leaf input")
	}
	leafCert := leafAndChain[0]
	supplied := append([]*x509.Certificate(nil), leafAndChain[1:]...)
	for i, im := range intermediates {
		certs, err := parseCertsFlexible(im)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing intermediate %d: %w", i+1, err)
		}
		supplied = append(supplied, certs...)
	}
	return leafCert, supplied, nil
}

// parseCertsFlexible decodes one or more certificates from PEM (a single cert or
// a bundle) or, when the input carries no PEM certificate block, a single raw DER
// certificate.
func parseCertsFlexible(b []byte) ([]*x509.Certificate, error) {
	certs, err := pki.ParseCertificateChainPEM(b)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		return certs, nil
	}
	// No PEM certificate block — try raw DER.
	cert, err := pki.ParseCertificatePEMOrDER(b)
	if err != nil {
		return nil, fmt.Errorf("input is neither a PEM certificate nor valid DER: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}
