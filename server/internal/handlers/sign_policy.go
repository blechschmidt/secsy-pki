package handlers

// Wiring for the CEL signing-restriction gate (Task 224) on the API surface.
//
// Most signing paths are gated inside the service that owns the key — the SSH
// authority, the artifact-signing service, the named-key signing primitive —
// because that is where every transport converges. Two endpoints have no such
// service: the legacy /api/keys/{id}/sign and /api/keys/{id}/sign-x509, which
// hand a CA key straight to the pki package. They are gated here, against the
// same rule sets, because "it predates the service layer" is not a policy
// exemption: an endpoint that signs with a CA key and consults no rule is a way
// around every rule.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/signpolicy"
)

// signingPolicyGate builds the signing-restriction gate over the API's store.
// It is constructed per call rather than held on the API: the gate is two
// pointers and no state, and building it where it is used keeps the one thing
// that matters obvious — it always reads the live rule table.
func (a *API) signingPolicyGate() celpolicy.SigningChecker {
	if a.db == nil {
		return nil
	}
	return signpolicy.NewGate(a.db, a.db)
}

// checkLegacySSHSignPolicy gates the legacy SSH-certificate signing endpoint.
// The facts describe the certificate that would be signed, resolved exactly as
// the endpoint resolves it, so a rule written against /api/ssh/cas/{id}/sign
// means the same thing here.
func (a *API) checkLegacySSHSignPolicy(r *http.Request, caRec *models.CA, cert *ssh.Certificate, purpose string) error {
	gate := a.signingPolicyGate()
	if gate == nil || cert == nil {
		return nil
	}
	facts := celpolicy.SigningRequest{
		Operation:   celpolicy.OpSignSSHCert,
		Tenant:      caRec.TenantID,
		RequestedBy: userSubject(middleware.GetUserInfo(r.Context())),
		Purpose:     purpose,
		Key: celpolicy.SigningKeyInfo{
			Name:     caRec.Label,
			Label:    caRec.Label,
			Ref:      caRec.PKCS11URI,
			Type:     caRec.KeyType,
			Provider: a.keyProviderName(),
			Tenant:   caRec.TenantID,
		},
		SSH: celpolicy.SSHCertInfo{
			Present:              true,
			CertType:             legacySSHCertTypeName(cert.CertType),
			KeyID:                cert.KeyId,
			Principals:           append([]string{}, cert.ValidPrincipals...),
			PrincipalCount:       len(cert.ValidPrincipals),
			Extensions:           celpolicy.SortedKeys(cert.Extensions),
			CriticalOptions:      celpolicy.SortedKeys(cert.CriticalOptions),
			CriticalOptionValues: cert.CriticalOptions,
			Serial:               strconv.FormatUint(cert.Serial, 10),
			ValidAfter:           time.Unix(int64(cert.ValidAfter), 0).UTC(),
			ValidBefore:          time.Unix(int64(cert.ValidBefore), 0).UTC(),
			PublicKey: celpolicy.SSHKeyInfo{
				Type:           keyType(cert.Key),
				Fingerprint:    keyFingerprint(cert.Key),
				HardwareBacked: strings.HasPrefix(keyType(cert.Key), "sk-"),
			},
			CA: celpolicy.CAInfo{ID: caRec.ID, Label: caRec.Label, Tenant: caRec.TenantID, Subject: caRec.Subject},
		},
	}
	facts.SSH.Validity = facts.SSH.ValidBefore.Sub(facts.SSH.ValidAfter)
	facts.SSH.ValidityDays = int(facts.SSH.Validity / (24 * time.Hour))
	return gate.CheckSigning(r.Context(), facts)
}

func legacySSHCertTypeName(t uint32) string {
	if t == ssh.HostCert {
		return "host"
	}
	return "user"
}

func keyType(pub ssh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return pub.Type()
}

func keyFingerprint(pub ssh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// keyProviderName names the configured key backend for a policy fact, tolerating
// a server built without one (a test).
func (a *API) keyProviderName() string {
	if a.keyProvider == nil {
		return ""
	}
	return a.keyProvider.Name()
}

// checkRawX509SignPolicy gates the legacy raw X.509 CSR-signing endpoint
// against the *certificate* rules, not the signing ones.
//
// That is deliberate. What this endpoint produces is a certificate, and its
// facts are a certificate's facts — a subject, SANs, a key, a validity window.
// An operator who wrote "no wildcards" or "RSA must be at least 3072 bits"
// meant it about certificates this PKI signs, and before Task 224 this endpoint
// was simply a way around that: it hands the CA key to pki.SignX509Certificate
// without passing through any of buildLeaf's gates. Routing it through the
// certificate rules closes the hole with the rules the operator already wrote.
//
// The request carries no issuance profile, so `request.profile` is empty and a
// profile-scoped rule does not apply — only the unscoped and CA-scoped ones do,
// which is the honest reading: there is no profile here to have been scoped to.
func (a *API) checkRawX509SignPolicy(r *http.Request, caRec *models.CA, csrPEM []byte, notAfter time.Time) error {
	if a.db == nil || caRec == nil {
		return nil
	}
	rules, err := a.db.ActiveCELPolicyRules(caRec.TenantID)
	if err != nil {
		// Fail closed, as everywhere else: without the rule set we cannot show
		// the request is permitted.
		return fmt.Errorf("pre-signing policy check failed: loading restriction rules: %w: %w", celpolicy.ErrUnavailable, err)
	}
	if len(rules) == 0 {
		return nil
	}
	csr, err := pki.ParseCSRPEM(csrPEM)
	if err != nil {
		return fmt.Errorf("parsing CSR: %w", err)
	}
	facts := celpolicy.FromCSR(csr)
	facts.Source = celpolicy.SourceRawSign
	facts.Operation = celpolicy.OpIssue
	facts.RequestedBy = userSubject(middleware.GetUserInfo(r.Context()))
	facts.NotBefore = time.Now().UTC()
	facts.NotAfter = notAfter.UTC()
	facts.Validity = facts.NotAfter.Sub(facts.NotBefore)
	facts.ValidityDays = int(facts.Validity / (24 * time.Hour))
	facts.CA = celpolicy.CAInfo{ID: caRec.ID, Label: caRec.Label, Tenant: caRec.TenantID, Subject: caRec.Subject}
	if caRec.NotAfter != nil {
		facts.CA.NotAfter = caRec.NotAfter.UTC()
	}
	in := celpolicy.FromContext(r.Context()).Input(facts)
	decision := celpolicy.Shared().Evaluate(rules, in)
	a.recordRawSignPolicyOutcome(r, caRec, in, decision)
	if decision.Allowed {
		return nil
	}
	return &celpolicy.DenyError{Decision: decision}
}

// recordRawSignPolicyOutcome mirrors ca.Manager's own accounting for the gate:
// every evaluation is metered, and any finding — blocking or monitor-mode — is
// written to the audit log with the reasons the requester was given.
func (a *API) recordRawSignPolicyOutcome(r *http.Request, caRec *models.CA, in celpolicy.Input, d celpolicy.Decision) {
	ca.RecordPolicyMetrics(d)
	if len(d.Violations) == 0 {
		return
	}
	result := audit.ResultError
	if d.Allowed {
		result = audit.ResultSuccess
	}
	a.recordEvent(r, audit.ActionCertPolicy, caRec.ID, caRec.Label, result, ca.PolicyDetail(in, d, ""))
}

// writeSignPolicyDenied answers a request the signing policy refused — a rule
// said no (422 with the reasons), or the rules could not be evaluated at all
// (503, because that is the server's fault and is worth retrying). It returns
// false when err is neither, so a caller falls through to its own mapping.
//
// The full detail of a gate failure stays in the audit event the caller writes:
// a client has no use for the store's error, and some of them name hosts.
func writeSignPolicyDenied(w http.ResponseWriter, err error) bool {
	var deny *celpolicy.DenyError
	if errors.As(err, &deny) {
		return writePolicyDenyError(w, err)
	}
	if errors.Is(err, celpolicy.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable,
			"the signing policy could not be evaluated, so the request was refused; retry shortly")
		return true
	}
	return false
}
