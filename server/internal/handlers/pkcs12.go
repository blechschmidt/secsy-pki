package handlers

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pkcs12"
)

// ExportCertificatePKCS12 generates a subject keypair server-side, issues a leaf
// under a profile using the CA's HSM-held key, and returns a password-protected
// PKCS#12 bundle (subject key + leaf + full chain). Optionally the freshly
// generated subject key is escrowed under the configured M-of-N policy.
//
// Authorization mirrors issuance (the issue capability within the CA's tenant,
// or a per-CA SIGN_CERTIFICATE grant). The CA signing key never leaves the HSM;
// only the software-generated subject key is bundled.
func (a *API) ExportCertificatePKCS12(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("pkcs12", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertPKCS12, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.ExportPKCS12Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if len(req.Password) < pkcs12.MinPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be at least %d characters", pkcs12.MinPasswordLen)
		return
	}

	// Parse IP-address and URI SANs up front so a malformed value is a clean 400
	// rather than a downstream failure.
	ips := make([]net.IP, 0, len(req.IPAddresses))
	for _, s := range req.IPAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			writeError(w, http.StatusBadRequest, "invalid IP address SAN %q", s)
			return
		}
		ips = append(ips, ip)
	}
	uris := make([]*url.URL, 0, len(req.URIs))
	for _, s := range req.URIs {
		u, err := url.Parse(s)
		if err != nil || !u.IsAbs() {
			writeError(w, http.StatusBadRequest, "invalid URI SAN %q (must be an absolute URI)", s)
			return
		}
		uris = append(uris, u)
	}

	// Resolve the escrow policy and KEK ring up front when requested, so a
	// misconfiguration is reported before any key is generated or issued.
	var escrowSealer func(pkcs8 []byte, serial string) (*models.PKCS12EscrowInfo, error)
	if req.Escrow {
		sealer, err := a.pkcs12EscrowSealer(r)
		if err != nil {
			metrics.Certificates.Inc("pkcs12", metrics.ResultDenied)
			a.recordEvent(r, audit.ActionCertPKCS12, caID, "", audit.ResultError, err.Error())
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		escrowSealer = sealer
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := pkcs12.GenerateAndBundle(r.Context(), mgr, pkcs12.BundleRequest{
		CAID:           caID,
		Profile:        req.Profile,
		Subject:        subjectFromPKCS12Request(req),
		DNSNames:       req.DNSNames,
		IPAddresses:    ips,
		EmailAddresses: req.Emails,
		URIs:           uris,
		Key:            pkcs12.KeySpec{Type: req.KeyType, Bits: req.KeyBits},
		Validity:       daysToDuration(a.capValidityDays(req.ValidityDays)),
		Password:       req.Password,
		Encoder:        req.Encoder,
		RequestedBy:    user.Subject,
	})
	a.consumeHSMAuditLogs("")

	metrics.RecordCertificate("pkcs12", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertPKCS12, caID, "", audit.ResultError, err.Error())
		if writeTenantLimitError(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "failed to export PKCS#12: %v", err)
		return
	}
	// The freshly-generated subject key material is delivered only inside the
	// password-protected bundle; scrub the plaintext PKCS#8 copy once done.
	defer zeroBytes(result.PrivateKeyPKCS8)

	resp := models.ExportPKCS12Response{
		Serial:   result.Serial.String(),
		Profile:  result.Profile,
		NotAfter: result.Leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"),
		PKCS12:   base64.StdEncoding.EncodeToString(result.PKCS12),
		Chain:    string(result.ChainPEM),
		KeyType:  result.KeyType,
		Encoder:  result.Encoder,
	}
	if ct := result.CT; ct != nil && ct.Enabled {
		resp.CT = &models.CTResponse{Enabled: true, Embedded: ct.Embedded, SCTCount: ct.SCTCount}
	}

	detail := fmt.Sprintf("profile=%s key=%s encoder=%s", result.Profile, result.KeyType, result.Encoder)

	// Escrow the subject key when requested. This is fail-closed: if the operator
	// asked for escrow and it cannot be produced, the bundle is not returned (the
	// issued certificate remains in inventory and can be revoked).
	if escrowSealer != nil {
		info, err := escrowSealer(result.PrivateKeyPKCS8, result.Serial.String())
		if err != nil {
			a.recordEvent(r, audit.ActionSecretEscrow, caID, result.Serial.String(), audit.ResultError, err.Error())
			a.recordEvent(r, audit.ActionCertPKCS12, caID, result.Serial.String(), audit.ResultError, "escrow failed: "+err.Error())
			writeError(w, http.StatusInternalServerError, "certificate issued but key escrow failed: %v", err)
			return
		}
		resp.Escrow = info
		a.recordEvent(r, audit.ActionSecretEscrow, caID, result.Serial.String(),
			audit.ResultSuccess, fmt.Sprintf("pkcs12 subject key; threshold=%d agents=%d", info.Threshold, info.Agents))
		detail += fmt.Sprintf(" escrow=%d-of-%d", info.Threshold, info.Agents)
	}

	a.recordEvent(r, audit.ActionCertPKCS12, caID, result.Serial.String(), audit.ResultSuccess, detail)
	writeJSON(w, http.StatusCreated, resp)
}

// subjectFromPKCS12Request builds a pkix.Name from the request's subject fields
// by reusing the CA-subject conversion so DN handling matches the rest of the
// stack.
func subjectFromPKCS12Request(req models.ExportPKCS12Request) pkix.Name {
	return ca.PKIXName(models.CASubject{
		CommonName:         req.CommonName,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Country:            req.Country,
		Province:           req.Province,
		Locality:           req.Locality,
	})
}

// pkcs12EscrowSealer validates that escrow is available and returns a closure
// that seals the given PKCS#8 subject key under the configured M-of-N policy,
// binding the escrow to the certificate serial. The escrow envelope is sealed
// under the CA tenant's KEK (or the deployment KEK), matching how the tenant's
// secrets are protected, and returned to the caller for break-glass storage.
func (a *API) pkcs12EscrowSealer(r *http.Request) (func(pkcs8 []byte, serial string) (*models.PKCS12EscrowInfo, error), error) {
	if !a.secretEnabled() {
		return nil, fmt.Errorf("key escrow requested but no secret KEK is configured (secret.kek_label)")
	}
	if !a.escrowConfigured() {
		return nil, fmt.Errorf("key escrow requested but secret.escrow is not configured")
	}
	policy, err := a.escrowPolicyFor(r)
	if err != nil {
		return nil, fmt.Errorf("escrow policy unavailable: %v", err)
	}

	// Resolve the KEK family for the CA's tenant (set on the context by
	// canIssueOn); fall back to the deployment KEK.
	kekLabel := a.secretKEKLabel
	if tenantID := middleware.GetTenant(r.Context()); tenantID != "" {
		if t, terr := a.db.GetTenant(tenantID); terr == nil && t != nil && t.KEKLabel != "" {
			kekLabel = t.KEKLabel
		}
	}
	ring, err := a.secretRing(r, kekLabel)
	if err != nil {
		return nil, fmt.Errorf("secret service unavailable: %v", err)
	}

	return func(pkcs8 []byte, serial string) (*models.PKCS12EscrowInfo, error) {
		context := pkcs12.EscrowContext(serial)
		blob, err := ring.EncryptWithEscrowToJSON(pkcs8, []byte(context), policy)
		if err != nil {
			return nil, err
		}
		return &models.PKCS12EscrowInfo{
			Threshold: policy.Threshold(),
			Agents:    len(policy.Agents()),
			Context:   context,
			Envelope:  json.RawMessage(blob),
		}, nil
	}, nil
}
