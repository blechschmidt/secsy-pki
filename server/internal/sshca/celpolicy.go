package sshca

// The CEL signing-restriction gate for OpenSSH certificates (Task 224).
//
// An OpenSSH certificate is the most authority-dense thing this PKI signs: a
// single line that says which accounts a key may log in as, on which hosts,
// with which forwarding permitted, under which forced command, for how long.
// The profile bounds those (principal patterns, permitted extensions, a
// validity maximum) and the CA's own ceiling bounds the lifetime — but none of
// them can express a relationship between the certificate and the *caller*:
// "only a token from the production pipeline may ask for a host certificate",
// "nobody gets a certificate for root", "force-command is not negotiable",
// "a user certificate is only signed for a FIDO-resident key".
//
// So the same engine runs here, against the `signing` vocabulary. The facts come
// from the fully resolved ssh.Certificate — after the profile has applied its
// defaults and the CA its ceiling, with the serial allocated — so a rule is true
// of the certificate that would be signed rather than of the request that asked
// for it. That is the same choice the certificate gate makes in buildLeaf, and
// for the same reason: a rule must not be satisfiable by a request whose
// resolution turns it into something else.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// checkPolicy runs the signing rules against the resolved certificate. It
// returns a *celpolicy.DenyError when an enforcing rule refused, whose message
// carries the operator's own wording all the way back to the requester.
func (a *Authority) checkPolicy(ctx context.Context, cert *ssh.Certificate, ca *models.CA, profile Profile, requestedBy, purpose string) error {
	return celpolicy.Check(ctx, a.policy, a.policyFacts(cert, ca, profile, requestedBy, purpose))
}

// policyFacts assembles the signing facts of one OpenSSH certificate.
func (a *Authority) policyFacts(cert *ssh.Certificate, ca *models.CA, profile Profile, requestedBy, purpose string) celpolicy.SigningRequest {
	req := celpolicy.SigningRequest{
		Operation:   celpolicy.OpSignSSHCert,
		RequestedBy: requestedBy,
		Purpose:     purpose,
		SSH:         sshCertFacts(cert, profile),
	}
	if ca != nil {
		req.Tenant = ca.TenantID
		req.Key = celpolicy.SigningKeyInfo{
			Name:      ca.Label,
			Label:     keyRefForCA(ca).Label,
			Ref:       ca.PKCS11URI,
			Type:      ca.KeyType,
			Algorithm: caKeyAlgorithm(ca),
			Provider:  a.provider.Name(),
			Tenant:    ca.TenantID,
		}
		if req.Key.Label == "" {
			req.Key.Label = ca.Label
		}
		req.SSH.CA = celpolicy.CAInfo{
			ID:      ca.ID,
			Label:   ca.Label,
			Tenant:  ca.TenantID,
			Subject: ca.Subject,
		}
		if ca.NotAfter != nil {
			req.SSH.CA.NotAfter = ca.NotAfter.UTC()
		}
	}
	// The payload of an OpenSSH certificate signature is the certificate's own
	// to-be-signed encoding — never a caller-supplied digest, which is why
	// prehashed is false here and always will be. Its byte length is left at
	// zero: x/crypto/ssh does not expose the to-be-signed encoding before the
	// signature exists, and every fact a rule could want from it is already
	// spelled out under signing.ssh.
	req.Payload = celpolicy.PayloadInfo{
		Present:         true,
		DigestAlgorithm: sshSignatureDigest(cert.Key),
	}
	return req
}

// sshCertFacts reads the facts off a resolved certificate.
func sshCertFacts(cert *ssh.Certificate, profile Profile) celpolicy.SSHCertInfo {
	out := celpolicy.SSHCertInfo{
		Present:              true,
		CertType:             certTypeName(cert.CertType),
		KeyID:                cert.KeyId,
		Principals:           append([]string{}, cert.ValidPrincipals...),
		PrincipalCount:       len(cert.ValidPrincipals),
		Extensions:           celpolicy.SortedKeys(cert.Extensions),
		CriticalOptions:      celpolicy.SortedKeys(cert.CriticalOptions),
		CriticalOptionValues: copyStringMap(cert.CriticalOptions),
		Profile:              profile.Name,
		Serial:               strconv.FormatUint(cert.Serial, 10),
		PublicKey:            sshKeyFacts(cert.Key),
	}
	// ValidAfter/ValidBefore are seconds since the epoch, with the maximum value
	// meaning "forever"; rendering that as a timestamp 584 billion years out
	// would make a lifetime comparison nonsense, so it is reported as the zero
	// time and a zero validity, which `signing.ssh.valid_before == timestamp(0)`
	// can test for.
	if cert.ValidAfter != ssh.CertTimeInfinity {
		out.ValidAfter = time.Unix(int64(cert.ValidAfter), 0).UTC()
	}
	if cert.ValidBefore != ssh.CertTimeInfinity {
		out.ValidBefore = time.Unix(int64(cert.ValidBefore), 0).UTC()
	}
	if !out.ValidAfter.IsZero() && !out.ValidBefore.IsZero() {
		out.Validity = out.ValidBefore.Sub(out.ValidAfter)
		out.ValidityDays = int(out.Validity / (24 * time.Hour))
	}
	return out
}

// certTypeName names an OpenSSH certificate type the way a profile and the API
// name it.
func certTypeName(t uint32) string {
	switch t {
	case ssh.UserCert:
		return CertTypeUser
	case ssh.HostCert:
		return CertTypeHost
	}
	return "unknown"
}

// sshKeyFacts describes the public key being certified.
func sshKeyFacts(pub ssh.PublicKey) celpolicy.SSHKeyInfo {
	if pub == nil {
		return celpolicy.SSHKeyInfo{}
	}
	out := celpolicy.SSHKeyInfo{
		Type:        pub.Type(),
		Fingerprint: ssh.FingerprintSHA256(pub),
		// An "sk-" key type is an OpenSSH FIDO/U2F credential: its private half
		// lives on a security key and cannot be copied off it. That is the one
		// thing about where a private key lives that its public half proves, and
		// an enterprise that mandates hardware-backed SSH keys needs exactly it.
		HardwareBacked: strings.HasPrefix(pub.Type(), "sk-"),
	}
	out.Bits = keyBits(pub)
	return out
}

// keyBits is the key size in bits where the notion applies. A key type whose
// Go representation is not reachable (a FIDO credential, an unknown type)
// reports 0 rather than a guess.
func keyBits(pub ssh.PublicKey) int {
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch key := cpk.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		if key.Curve != nil {
			return key.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

// sshSignatureDigest names the hash the CA's signature over this certificate
// uses. OpenSSH fixes it per CA key algorithm rather than letting the caller
// choose, so it is derived rather than reported.
func sshSignatureDigest(pub ssh.PublicKey) string {
	if pub == nil {
		return celpolicy.HashName(crypto.SHA256)
	}
	switch pub.Type() {
	case ssh.KeyAlgoECDSA384:
		return celpolicy.HashName(crypto.SHA384)
	case ssh.KeyAlgoECDSA521:
		return celpolicy.HashName(crypto.SHA512)
	case ssh.KeyAlgoED25519:
		// Ed25519 hashes internally as part of the scheme (SHA-512), so there is
		// no externally selected message hash.
		return ""
	}
	return celpolicy.HashName(crypto.SHA256)
}

// caKeyAlgorithm names the CA key's algorithm family the way the certificate
// vocabulary names a key algorithm, so one rule can speak about both.
func caKeyAlgorithm(ca *models.CA) string {
	kt := strings.ToLower(strings.TrimSpace(ca.KeyType))
	switch {
	case strings.HasPrefix(kt, "rsa"):
		return "RSA"
	case strings.HasPrefix(kt, "ecdsa"):
		return "ECDSA"
	case strings.HasPrefix(kt, "ed25519"):
		return "Ed25519"
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey)); err == nil {
		switch pub.Type() {
		case ssh.KeyAlgoRSA:
			return "RSA"
		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			return "ECDSA"
		case ssh.KeyAlgoED25519:
			return "Ed25519"
		}
	}
	return ""
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
