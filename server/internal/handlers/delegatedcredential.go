package handlers

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/delegatedcred"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pkcs12"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// MintDelegatedCredential mints an RFC 9345 TLS delegated credential for a
// previously issued, delegation-eligible certificate.
//
// A delegated credential is signed by the end-entity certificate's PRIVATE key,
// which this CA does not hold for ordinary CSR-based issuance. This endpoint
// therefore serves only leaves whose subject key was generated server-side via a
// PKCS#12 export (Task 80) AND escrowed under the M-of-N recovery policy
// (Task 33): the caller presents the escrow envelope plus a quorum of recovery-
// agent IDs, the server recovers the leaf key just long enough to sign the
// credential, and the plaintext key is zeroized immediately. For a leaf whose key
// the operator already holds, the offline `secsy-ca delegated-credential mint`
// helper is the right tool — no key ever crosses the API.
//
// Authorization mirrors issuance (the issue capability within the CA's tenant, or
// a per-CA SIGN_CERTIFICATE grant). No HSM CA key is used; the HSM only unwraps
// the recovery-agent shares.
func (a *API) MintDelegatedCredential(w http.ResponseWriter, r *http.Request) {
	const label = "delegated_credential"
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc(label, metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertDelegatedCredential, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.MintDelegatedCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Serial == "" {
		writeError(w, http.StatusBadRequest, "serial is required")
		return
	}

	// Resolve the certificate under this CA and confirm it is delegation-eligible
	// before doing any recovery work.
	rec, err := a.db.GetIssuedCertificate(caID, req.Serial)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "certificate lookup failed: %v", err)
		return
	}
	if rec == nil {
		writeError(w, http.StatusNotFound, "no certificate with serial %q under this CA", req.Serial)
		return
	}
	leafCert, err := pki.ParseCertificatePEM([]byte(rec.Certificate))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "parsing stored certificate: %v", err)
		return
	}
	if err := delegatedcred.CheckEligible(leafCert); err != nil {
		a.recordEvent(r, audit.ActionCertDelegatedCredential, caID, rec.Serial, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Recover the escrowed leaf key. This is the only way the system can obtain the
	// leaf private key; a leaf issued without server-side keygen + escrow cannot be
	// served here.
	leafKey, recoverErr := a.recoverEscrowedLeafKey(r, rec.Serial, req)
	if recoverErr != nil {
		metrics.Certificates.Inc(label, metrics.ResultError)
		a.recordEvent(r, audit.ActionSecretRecover, caID, rec.Serial, audit.ResultError, recoverErr.Error())
		writeError(w, recoverErr.status, "%s", recoverErr.msg)
		return
	}
	a.recordEvent(r, audit.ActionSecretRecover, caID, rec.Serial, audit.ResultSuccess,
		fmt.Sprintf("delegated-credential leaf key; agents=%d", len(req.RecoveryAgents)))

	// Resolve the delegated public key: use the supplied SPKI, or generate one.
	dcPub, generated, err := resolveDelegatedPublicKey(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Resolve optional scheme overrides.
	var algorithm, expected delegatedcred.SignatureScheme
	if req.SignatureScheme != "" {
		if algorithm, err = delegatedcred.SchemeFromName(req.SignatureScheme); err != nil {
			writeError(w, http.StatusBadRequest, "signature_scheme: %v", err)
			return
		}
	}
	if req.ExpectedCertVerifyAlgorithm != "" {
		if expected, err = delegatedcred.SchemeFromName(req.ExpectedCertVerifyAlgorithm); err != nil {
			writeError(w, http.StatusBadRequest, "expected_cert_verify_algorithm: %v", err)
			return
		}
	}

	endpoint := delegatedcred.ServerEndpoint
	endpointName := "server"
	if req.Client {
		endpoint = delegatedcred.ClientEndpoint
		endpointName = "client"
	}
	validFor := 24 * time.Hour
	if req.ValidForSeconds > 0 {
		validFor = time.Duration(req.ValidForSeconds) * time.Second
	}

	res, err := delegatedcred.Mint(delegatedcred.MintRequest{
		LeafCert:                    leafCert,
		LeafKey:                     leafKey,
		DCPublicKey:                 dcPub,
		ValidFor:                    validFor,
		Endpoint:                    endpoint,
		Algorithm:                   algorithm,
		ExpectedCertVerifyAlgorithm: expected,
	})
	metrics.RecordCertificate(label, err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertDelegatedCredential, caID, rec.Serial, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "minting delegated credential: %v", err)
		return
	}

	resp := models.MintDelegatedCredentialResponse{
		Serial:                      rec.Serial,
		DelegatedCredential:         base64.StdEncoding.EncodeToString(res.Wire),
		ValidTimeSeconds:            res.ValidTime,
		NotAfter:                    res.NotAfter.UTC().Format(time.RFC3339),
		Endpoint:                    endpointName,
		Algorithm:                   res.Algorithm.String(),
		ExpectedCertVerifyAlgorithm: res.ExpectedCertVerifyAlgorithm.String(),
		DCPublicKeyPEM:              string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: res.DelegatedCredential.SubjectPublicKeyInfo()})),
	}
	if generated != nil {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(generated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encoding delegated private key: %v", err)
			return
		}
		resp.DCPrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	}

	a.recordEvent(r, audit.ActionCertDelegatedCredential, caID, rec.Serial, audit.ResultSuccess,
		fmt.Sprintf("endpoint=%s valid_time=%ds alg=%s expected=%s", endpointName, res.ValidTime, res.Algorithm, res.ExpectedCertVerifyAlgorithm))
	writeJSON(w, http.StatusCreated, resp)
}

// dcError carries an HTTP status alongside a message so the recovery helper can
// report the right code without the caller re-classifying the failure.
type dcError struct {
	status int
	msg    string
}

func (e *dcError) Error() string { return e.msg }

// recoverEscrowedLeafKey recovers the certificate's escrowed subject key via the
// Task 33 M-of-N recovery ceremony, binding the recovery context to the
// certificate serial exactly as the PKCS#12 escrow path sealed it. The returned
// key must be used and discarded promptly; the plaintext PKCS#8 is zeroized here.
func (a *API) recoverEscrowedLeafKey(r *http.Request, serial string, req models.MintDelegatedCredentialRequest) (crypto.Signer, *dcError) {
	if len(req.EscrowEnvelope) == 0 {
		return nil, &dcError{http.StatusBadRequest, "escrow_envelope is required: this endpoint serves only leaves whose key was escrowed at PKCS#12 export (Task 33)"}
	}
	if len(req.RecoveryAgents) == 0 {
		return nil, &dcError{http.StatusBadRequest, "recovery_agents is required (a quorum of escrow recovery-agent IDs)"}
	}
	env, err := secret.Unmarshal(req.EscrowEnvelope)
	if err != nil {
		return nil, &dcError{http.StatusBadRequest, fmt.Sprintf("invalid escrow_envelope: %v", err)}
	}
	rs, err := secret.NewRecoveryService(a.keyProvider)
	if err != nil {
		return nil, &dcError{http.StatusBadRequest, fmt.Sprintf("escrow recovery unavailable: %v", err)}
	}
	a.consumeHSMAuditLogs("")
	pkcs8, err := rs.Recover(r.Context(), env, req.RecoveryAgents, []byte(pkcs12.EscrowContext(serial)))
	a.consumeHSMAuditLogs("")
	if err != nil {
		return nil, &dcError{http.StatusBadRequest, fmt.Sprintf("escrow recovery failed: %v", err)}
	}
	defer zeroBytes(pkcs8)
	leafKey, err := delegatedcred.ParsePrivateKeyDER(pkcs8)
	if err != nil {
		return nil, &dcError{http.StatusInternalServerError, fmt.Sprintf("parsing recovered leaf key: %v", err)}
	}
	return leafKey, nil
}

// resolveDelegatedPublicKey returns the delegated public key, either decoded from
// a supplied base64 SPKI or freshly generated (in which case the signer is
// returned so its private half can be delivered in the response).
func resolveDelegatedPublicKey(req models.MintDelegatedCredentialRequest) (crypto.PublicKey, crypto.Signer, error) {
	if req.DCPublicKey != "" {
		der, err := base64.StdEncoding.DecodeString(req.DCPublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("dc_public_key is not valid base64: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, nil, fmt.Errorf("dc_public_key is not a valid SubjectPublicKeyInfo: %v", err)
		}
		return pub, nil, nil
	}
	generated, err := delegatedcred.GenerateKey(req.DCKeyType)
	if err != nil {
		return nil, nil, err
	}
	return generated.Public(), generated, nil
}
