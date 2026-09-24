package handlers

// REST counterparts of `secsy-ca signing-key` and `secsy-ca tsa-key` — minting
// the two signing credentials a deployment needs beyond its CAs (Task 198).
//
// Both commands do the same two things: put a key on the role's backend (reusing
// one already under that label, so a certificate reissue does not rotate the
// key) and issue that key a certificate under an existing CA. They differ in
// what the certificate must look like and in how it is issued:
//
//   - POST /api/sign/signers takes the ORDINARY issuance path through the CA
//     manager under the "code-signing" profile, so the pre-issuance lint gate and
//     any profile gates run and the certificate is recorded for renewal and
//     revocation like any other leaf (cmd/secsy-ca/sign.go, cmdSigningKey).
//   - POST /api/tsa/key hand-crafts its certificate, because RFC 3161 §2.3
//     requires id-kp-timeStamping to be the SOLE extended key usage and to be
//     marked critical, which no profile emits (cmd/secsy-ca/tsa.go, cmdTSAKey).
//
// Neither endpoint accepts or returns private key material: the key is generated
// inside the provider and only its certificate comes back. What they return is
// what the operator must put in configuration — tsa.key_label /
// tsa.certificate_file, signing.signers[].key_label / .certificate_file — so the
// console can complete the provisioning step it previously could not offer.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// maxProvisionBody bounds a provisioning request. It carries names, a key type
// and a validity — no key material, no certificate — so a few kilobytes is
// generous; the limit is applied for the same reason as everywhere else, not
// because this body is large.
const maxProvisionBody = 16 << 10

// Defaults mirroring the CLI flag defaults, so a console form left untouched
// provisions exactly what `secsy-ca tsa-key` / `secsy-ca signing-key` would.
const (
	defaultTSAKeyLabel      = "tsa"
	defaultTSAKeyType       = "rsa-2048"
	defaultTSACommonName    = "Time-Stamp Authority"
	defaultTSAValidityDays  = 1185
	defaultSignerKeyLabel   = "codesign"
	defaultSignerKeyType    = "ecdsa-p256"
	defaultSignerProfile    = "code-signing"
	tsaKeyRole              = "tsa"
	signerKeyRole           = "signing"
	tsaProvisionWhat        = "TSA key provisioning"
	signerProvisionWhat     = "signing-key provisioning"
	tsaCertBackdate         = 5 * time.Minute // clock-skew backdating, as the CLI does
	provisionRequestedByTag = "POST /api/sign/signers"
)

// Audit actions for the two provisioning operations. The CLI records neither
// directly — `tsa-key` records nothing at all and `signing-key` is recorded only
// as the cert.issue its CA-manager call produces — so these have no counterpart
// in internal/audit to reuse. Over REST they must be attributable: a credential
// that can countersign or code-sign on this deployment's behalf came into
// existence, at a caller's request. The strings follow the existing
// "<area>.<operation>" convention and belong in internal/audit/audit.go once
// this file is no longer required to be additive.
const (
	// actionTSAKeyProvision records a TSA signing credential being provisioned:
	// target is the issuing CA id, target-name the provider key label; the detail
	// carries the key type, whether the key was reused, the certificate serial and
	// the expiry. No key material exists outside the provider to log.
	actionTSAKeyProvision = "tsa.key_provision"
	// actionSignerProvision records a code-signing credential being provisioned,
	// with the same shape. The certificate itself is additionally recorded by the
	// ordinary issuance path as cert.issue.
	actionSignerProvision = "signing.key_provision"
)

// oidExtKeyUsage is the X.509 extended-key-usage extension OID (RFC 5280
// §4.2.1.12). Declared here for the same reason the CLI declares it
// (cmd/secsy-ca/tsa.go): crypto/x509 cannot emit a CRITICAL extKeyUsage, so the
// TSA extension is hand-built and supplied via ExtraExtensions.
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// provisionedKeyRef names the key a provisioning call put in place.
type provisionedKeyRef struct {
	// Label is the provider key label; the value for tsa.key_label /
	// signing.signers[].key_label.
	Label string `json:"label"`
	// KeyType is the canonical key type the key holds.
	KeyType string `json:"key_type"`
	// URI is the provider reference for the key, when the backend reports one.
	URI string `json:"uri,omitempty"`
	// Reused reports that a key already under this label was adopted rather than
	// a new one generated, which is what makes a certificate reissue idempotent
	// without rotating the key.
	Reused bool `json:"reused"`
	// Provider is the backend that holds the key.
	Provider string `json:"provider"`
	// Role is the key-provider role the key was filed under ("tsa"/"signing").
	Role string `json:"role"`
}

// provisionedCert describes the certificate a provisioning call issued.
type provisionedCert struct {
	Serial    string `json:"serial"`
	Subject   string `json:"subject"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	// CertificatePEM is the credential's certificate, followed by the issuer
	// chain when the request asked for it. This is the content of the file that
	// tsa.certificate_file / signing.signers[].certificate_file must point at.
	CertificatePEM string `json:"certificate_pem"`
	// CAID / CALabel identify the issuing CA that was actually used.
	CAID    string `json:"ca_id"`
	CALabel string `json:"ca_label"`
}

// TSAKeyRequest is the body of POST /api/tsa/key.
type TSAKeyRequest struct {
	// CA is the issuing CA id or label. Required.
	CA string `json:"ca"`
	// Label is the provider key label for the TSA signing key (default "tsa").
	Label string `json:"label,omitempty"`
	// KeyType must be RSA: "rsa-2048" (default) or "rsa-4096". `openssl ts
	// -verify` interop and the CMS signer both require RSA.
	KeyType string `json:"key_type,omitempty"`
	// CommonName is the certificate subject CN (default "Time-Stamp Authority").
	CommonName string `json:"common_name,omitempty"`
	// Organization is the certificate subject O (optional).
	Organization string `json:"organization,omitempty"`
	// ValidityDays is the certificate validity in days (default 1185).
	ValidityDays int `json:"validity_days,omitempty"`
	// Chain appends the issuing CA chain after the TSA certificate.
	Chain bool `json:"chain,omitempty"`
}

// TSAKeyResponse reports the provisioned TSA credential and the configuration it
// must be referenced from.
type TSAKeyResponse struct {
	Key         provisionedKeyRef `json:"key"`
	Certificate provisionedCert   `json:"certificate"`
	// ConfigHint restates, in one line, what to set in configuration — the
	// equivalent of the two stderr lines the CLI prints on success.
	ConfigHint string `json:"config_hint"`
}

// SignerProvisionRequest is the body of POST /api/sign/signers.
type SignerProvisionRequest struct {
	// CA is the issuing CA id or label. Required.
	CA string `json:"ca"`
	// Label is the provider key label for the signing key (default "codesign").
	Label string `json:"label,omitempty"`
	// KeyType is "ecdsa-p256" (default), "ecdsa-p384", "rsa-2048", or "rsa-4096";
	// the families the CMS signer supports.
	KeyType string `json:"key_type,omitempty"`
	// CommonName is the certificate subject CN (default: the key label).
	CommonName string `json:"common_name,omitempty"`
	// Organization is the certificate subject O (optional).
	Organization string `json:"organization,omitempty"`
	// ValidityDays is the certificate validity in days (0 = profile default).
	ValidityDays int `json:"validity_days,omitempty"`
	// Profile is the issuance profile, which must carry the codeSigning EKU
	// (default "code-signing").
	Profile string `json:"profile,omitempty"`
	// Chain appends the issuing CA chain after the signer certificate.
	Chain bool `json:"chain,omitempty"`
}

// SignerProvisionResponse reports the provisioned code-signing credential.
type SignerProvisionResponse struct {
	Key         provisionedKeyRef `json:"key"`
	Certificate provisionedCert   `json:"certificate"`
	// Profile is the profile the certificate was actually issued under.
	Profile string `json:"profile"`
	// ConfigHint restates what to add under signing.signers in configuration.
	ConfigHint string `json:"config_hint"`
}

// ProvisionTSAKey handles POST /api/tsa/key: generate (or reuse) the RFC 3161
// TSA signing key on the tsa-role backend and issue it a TSA certificate under
// an existing CA. The private key never leaves the provider.
//
// Gated on PLATFORM ca:manage, not on the issuing CA's tenant. The credential it
// mints is deployment infrastructure — the server reaches it through
// tsa.key_label, not through a tenant record — and it consumes a CA signing key
// to do so. A tenant admin who could call this would be provisioning, and could
// silently re-certify, the timestamp authority the whole deployment's signatures
// and audit anchors rely on.
func (a *API) ProvisionTSAKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, actionTSAKeyProvision, "", "", audit.ResultDenied, "platform ca:manage capability required")
		writeError(w, http.StatusForbidden, "platform ca:manage capability required to provision the TSA signing key")
		return
	}

	var req TSAKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProvisionBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.CA == "" {
		writeError(w, http.StatusBadRequest, "ca is required")
		return
	}
	label := defaultString(req.Label, defaultTSAKeyLabel)
	keyType, err := keyprovider.NormalizeKeyType(defaultString(req.KeyType, defaultTSAKeyType))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if keyType != keyprovider.KeyTypeRSA2048 && keyType != keyprovider.KeyTypeRSA4096 {
		writeError(w, http.StatusBadRequest,
			"TSA key must be RSA (got %q); openssl ts -verify interop and the CMS signer require RSA", keyType)
		return
	}
	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = defaultTSAValidityDays
	}

	caModel, caCert, ok := a.provisioningIssuer(w, req.CA)
	if !ok {
		return
	}
	middleware.SetTenant(r.Context(), caModel.TenantID)

	provider, release, ok := a.providerForRole(w, tsaKeyRole, tsaProvisionWhat)
	if !ok {
		return
	}
	defer release()

	// Reuse an existing key of this label (idempotent reissue) or generate one on
	// the TSA-role backend, exactly as tsaPublicKey does in cmd/secsy-ca/tsa.go.
	pub, keyInfo, reused, err := a.provisionKey(r.Context(), provider, label, keyType)
	if err != nil {
		a.recordEvent(r, actionTSAKeyProvision, caModel.ID, label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if _, isRSA := pub.(*rsa.PublicKey); !isRSA {
		writeError(w, http.StatusBadRequest,
			"existing key %q is %T, not RSA; choose a different label", label, pub)
		return
	}

	eku, err := timeStampingEKUExtension()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	notBefore := time.Now().Add(-tsaCertBackdate)
	notAfter := time.Now().Add(time.Duration(validityDays) * 24 * time.Hour)
	if notAfter.After(caCert.NotAfter) {
		writeError(w, http.StatusBadRequest,
			"requested validity (%s) exceeds issuing CA expiry (%s); lower validity_days",
			notAfter.Format(time.RFC3339), caCert.NotAfter.Format(time.RFC3339))
		return
	}
	serial, err := provisionSerial()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "allocating a serial: %v", err)
		return
	}

	a.consumeHSMAuditLogs("")
	caSigner, err := a.keyProvider.Signer(r.Context(), ca.KeyRefForCA(caModel))
	if err != nil {
		a.consumeHSMAuditLogs("")
		writeError(w, http.StatusInternalServerError, "opening issuing CA signer: %v", err)
		return
	}
	der, signErr := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: defaultString(req.CommonName, defaultTSACommonName), Organization: orgSlice(req.Organization)},
		PublicKey: pub,
		Serial:    serial,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		// EKU is carried critically via ExtraExtensions below, per RFC 3161 §2.3.
		ExtKeyUsage:     nil,
		ExtraExtensions: []pkix.Extension{eku},
	})
	_ = caSigner.Close()
	a.consumeHSMAuditLogs("")
	if signErr != nil {
		a.recordEvent(r, actionTSAKeyProvision, caModel.ID, label, audit.ResultError, signErr.Error())
		writeError(w, http.StatusBadRequest, "issuing TSA certificate: %v", signErr)
		return
	}

	// Sanity-check the freshly issued certificate against the same rules the
	// server enforces at startup, so provisioning fails loudly on a bad build.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "parsing issued TSA certificate: %v", err)
		return
	}
	if err := verifyTSACert(leaf); err != nil {
		a.recordEvent(r, actionTSAKeyProvision, caModel.ID, label, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "issued TSA certificate is not usable: %v", err)
		return
	}

	outPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if req.Chain {
		chain, err := a.provisioningChainPEM(caModel.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "%v", err)
			return
		}
		outPEM = append(outPEM, chain...)
	}

	a.recordEvent(r, actionTSAKeyProvision, caModel.ID, label, audit.ResultSuccess,
		fmt.Sprintf("provider=%s key_type=%s key_reused=%t serial=%s ca=%s not_after=%s",
			provider.Name(), keyType, reused, serial, caModel.Label, notAfter.UTC().Format(time.RFC3339)))

	writeJSON(w, http.StatusCreated, TSAKeyResponse{
		Key: provisionedKeyRef{
			Label: label, KeyType: keyType, URI: keyInfo.URI, Reused: reused,
			Provider: provider.Name(), Role: tsaKeyRole,
		},
		Certificate: provisionedCert{
			Serial:         serial.String(),
			Subject:        leaf.Subject.String(),
			NotBefore:      leaf.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:       leaf.NotAfter.UTC().Format(time.RFC3339),
			CertificatePEM: string(outPEM),
			CAID:           caModel.ID,
			CALabel:        caModel.Label,
		},
		ConfigHint: fmt.Sprintf("set tsa.key_label: %q and tsa.certificate_file to a file holding the returned certificate_pem", label),
	})
}

// ProvisionSigner handles POST /api/sign/signers: generate (or reuse) an artifact
// code-signing key on the signing-role backend and issue its certificate through
// the ordinary CA path under the lint-gated code-signing profile.
//
// Gated on PLATFORM ca:manage, for the same reason as the TSA key: the credential
// becomes an entry under signing.signers that every caller of POST /api/sign can
// then sign with, which is authority over the deployment rather than over a
// tenant's certificates.
func (a *API) ProvisionSigner(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, actionSignerProvision, "", "", audit.ResultDenied, "platform ca:manage capability required")
		writeError(w, http.StatusForbidden, "platform ca:manage capability required to provision a code-signing key")
		return
	}

	var req SignerProvisionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProvisionBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.CA == "" {
		writeError(w, http.StatusBadRequest, "ca is required")
		return
	}
	label := defaultString(req.Label, defaultSignerKeyLabel)
	keyType, err := keyprovider.NormalizeKeyType(defaultString(req.KeyType, defaultSignerKeyType))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	switch keyType {
	case keyprovider.KeyTypeECDSAP256, keyprovider.KeyTypeECDSAP384,
		keyprovider.KeyTypeRSA2048, keyprovider.KeyTypeRSA4096:
	default:
		writeError(w, http.StatusBadRequest,
			"signing key must be ECDSA or RSA (got %q); the CMS signer supports those families", keyType)
		return
	}
	profile := defaultString(req.Profile, defaultSignerProfile)

	caModel, _, ok := a.provisioningIssuer(w, req.CA)
	if !ok {
		return
	}
	middleware.SetTenant(r.Context(), caModel.TenantID)

	provider, release, ok := a.providerForRole(w, signerKeyRole, signerProvisionWhat)
	if !ok {
		return
	}
	defer release()

	pub, keyInfo, reused, err := a.provisionKey(r.Context(), provider, label, keyType)
	if err != nil {
		a.recordEvent(r, actionSignerProvision, caModel.ID, label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Issue through the ordinary CA path so the code-signing profile shapes the
	// certificate and the fail-closed pre-issuance lint gate runs on it.
	a.consumeHSMAuditLogs("")
	res, err := ca.NewManager(a.db, a.keyProvider).IssueCertificateFromTemplate(r.Context(), ca.TemplateIssueSpec{
		CAID:        caModel.ID,
		Subject:     pkix.Name{CommonName: defaultString(req.CommonName, label), Organization: orgSlice(req.Organization)},
		PublicKey:   pub,
		Profile:     profile,
		Validity:    time.Duration(req.ValidityDays) * 24 * time.Hour,
		RequestedBy: provisionRequestedByTag,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, actionSignerProvision, caModel.ID, label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "issuing signing certificate: %v", err)
		return
	}

	// Fail loudly if the chosen profile did not produce a usable code-signing
	// certificate — the same check the server and CLI signers apply.
	if err := signing.CheckCodeSigningCert(res.Certificate); err != nil {
		a.recordEvent(r, actionSignerProvision, caModel.ID, label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest,
			"issued certificate is not usable for code signing (profile %q): %v", profile, err)
		return
	}

	outPEM := append([]byte(nil), res.PEM...)
	if req.Chain {
		chain, err := a.provisioningChainPEM(caModel.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "%v", err)
			return
		}
		outPEM = append(outPEM, chain...)
	}

	a.recordEvent(r, actionSignerProvision, caModel.ID, label, audit.ResultSuccess,
		fmt.Sprintf("provider=%s key_type=%s key_reused=%t serial=%s profile=%s ca=%s not_after=%s",
			provider.Name(), keyType, reused, res.Serial, res.Profile, caModel.Label,
			res.Certificate.NotAfter.UTC().Format(time.RFC3339)))

	writeJSON(w, http.StatusCreated, SignerProvisionResponse{
		Key: provisionedKeyRef{
			Label: label, KeyType: keyType, URI: keyInfo.URI, Reused: reused,
			Provider: provider.Name(), Role: signerKeyRole,
		},
		Certificate: provisionedCert{
			Serial:         res.Serial.String(),
			Subject:        res.Certificate.Subject.String(),
			NotBefore:      res.Certificate.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:       res.Certificate.NotAfter.UTC().Format(time.RFC3339),
			CertificatePEM: string(outPEM),
			CAID:           caModel.ID,
			CALabel:        caModel.Label,
		},
		Profile:    res.Profile,
		ConfigHint: fmt.Sprintf("add a signing.signers entry with key_label: %q and certificate_file pointing at a file holding the returned certificate_pem", label),
	})
}

// provisioningIssuer resolves an id-or-label CA reference to a usable X.509
// issuer, writing the error response itself. Authorization is the caller's
// platform-wide capability check, already performed — this only establishes that
// the named CA exists and can sign.
func (a *API) provisioningIssuer(w http.ResponseWriter, ref string) (*models.CA, *x509.Certificate, bool) {
	caID, found := a.resolveCARefID(ref)
	if !found {
		writeError(w, http.StatusNotFound, "CA %q not found", ref)
		return nil, nil, false
	}
	caModel, err := a.db.GetCA(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "loading CA: %v", err)
		return nil, nil, false
	}
	if caModel == nil || caModel.Certificate == "" {
		writeError(w, http.StatusBadRequest, "CA %q has no certificate", ref)
		return nil, nil, false
	}
	caCert, err := pki.ParseCertificatePEM([]byte(caModel.Certificate))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "parsing CA certificate: %v", err)
		return nil, nil, false
	}
	return caModel, caCert, true
}

// provisionKey reuses the key already stored under label or generates a new one,
// returning its public half, its metadata and whether it was reused. Reuse is
// what makes a certificate reissue idempotent without rotating the key — the
// behaviour of tsaPublicKey / signingPublicKey in cmd/secsy-ca.
func (a *API) provisionKey(ctx context.Context, provider keyprovider.Provider, label, keyType string) (crypto.PublicKey, *keyprovider.KeyInfo, bool, error) {
	a.consumeHSMAuditLogs("")
	defer a.consumeHSMAuditLogs("")
	if info, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: label}); err == nil {
		return info.PublicKey, info, true, nil
	}
	gen, err := provider.GenerateKey(ctx, keyprovider.KeySpec{
		Label: label, KeyType: keyType, Usage: keyprovider.KeyUsageSign,
	})
	if err != nil {
		return nil, nil, false, fmt.Errorf("generating key %q: %w", label, err)
	}
	return gen.PublicKey, gen, false, nil
}

// provisioningChainPEM returns the issuer bundle appended when a request asks
// for the chain. It uses the manager's CombinedChainPEM — the same bundle
// /api/ca/{id}/chain serves — rather than the CLI's simpler parent walk, so a CA
// in a rollover overlap window or one signed by an external parent yields a
// bundle that actually validates the credential.
func (a *API) provisioningChainPEM(caID string) ([]byte, error) {
	chain, err := ca.NewManager(a.db, a.keyProvider).CombinedChainPEM(caID)
	if err != nil {
		return nil, fmt.Errorf("building the issuer chain: %w", err)
	}
	return chain, nil
}

// timeStampingEKUExtension builds a critical extended-key-usage extension whose
// sole usage is id-kp-timeStamping, as RFC 3161 §2.3 requires for a TSA cert.
// Mirrors the identically named helper in cmd/secsy-ca/tsa.go, which is in
// package main and so cannot be imported; the OID itself is shared from
// internal/tsa.
func timeStampingEKUExtension() (pkix.Extension, error) {
	val, err := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling extended key usage: %w", err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: val}, nil
}

// verifyTSACert re-checks that a certificate is a usable dedicated TSA
// credential: RSA key, and id-kp-timeStamping as the sole extended key usage.
// Mirrors verifyTSACert in cmd/secsy-ca/tsa.go.
func verifyTSACert(cert *x509.Certificate) error {
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return fmt.Errorf("public key is %T, want RSA", cert.PublicKey)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(cert.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("id-kp-timeStamping must be the sole extended key usage")
	}
	return nil
}

// provisionSerial returns a random, positive 128-bit certificate serial. The TSA
// certificate is minted outside the issuance ledger (it is not a recorded leaf),
// exactly as the CLI mints it, so it has no allocator to draw from; 128 random
// bits is the RFC 5280 / CA-Browser-Forum entropy answer to that.
func provisionSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// orgSlice wraps a non-empty organization name for a pkix.Name.
func orgSlice(o string) []string {
	if strings.TrimSpace(o) == "" {
		return nil
	}
	return []string{o}
}

// defaultString returns v, or def when v is empty after trimming.
func defaultString(v, def string) string {
	if s := strings.TrimSpace(v); s != "" {
		return s
	}
	return def
}
