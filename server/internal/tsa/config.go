package tsa

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// LoadAuthorityConfig assembles an Authority Config from the operator
// configuration: it loads the TSA signing certificate (and any inline chain)
// from the configured PEM file, appends the issuing CA's stored chain from the
// database when the file carries only the leaf and a CA is named, and parses
// the policy OID, signature digest, and accepted message-imprint hashes. It is
// shared by the server (/tsa endpoint, artifact-signing countersignatures) and
// the secsy-ca CLI (audit-chain anchoring) so every consumer constructs an
// identical authority from the same config block.
func LoadAuthorityConfig(db *database.DB, tc config.TSAConfig) (Config, error) {
	certPEM, err := os.ReadFile(tc.CertificateFile)
	if err != nil {
		return Config{}, fmt.Errorf("reading tsa.certificate_file %q: %w", tc.CertificateFile, err)
	}
	chain, err := parseChainPEM(certPEM)
	if err != nil {
		return Config{}, fmt.Errorf("parsing tsa.certificate_file: %w", err)
	}
	if len(chain) == 0 {
		return Config{}, fmt.Errorf("tsa.certificate_file %q contains no certificates", tc.CertificateFile)
	}

	// If the file holds only the TSA leaf, append the issuing CA's chain from the
	// database so certReq responses carry a verifiable path.
	if len(chain) == 1 && (tc.CAID != "" || tc.CALabel != "") {
		caID, err := resolveTSACAID(db, tc.CAID, tc.CALabel)
		if err != nil {
			return Config{}, err
		}
		issuers, err := caChain(db, caID)
		if err != nil {
			return Config{}, err
		}
		chain = append(chain, issuers...)
	}

	cfg := Config{
		Path:            tc.Path,
		KeyLabel:        tc.KeyLabel,
		Certificate:     chain[0],
		Chain:           chain,
		Accuracy:        Accuracy{Seconds: tc.AccuracySeconds, Millis: tc.AccuracyMillis, Micros: tc.AccuracyMicros},
		Ordering:        tc.Ordering,
		SignatureDigest: hashByName(tc.SignatureDigest),
		IncludeTSAName:  tc.IncludeTSAName,
	}
	if tc.PolicyOID != "" {
		oid, err := parseDottedOID(tc.PolicyOID)
		if err != nil {
			return Config{}, fmt.Errorf("tsa.policy_oid: %w", err)
		}
		cfg.PolicyOID = oid
	}
	for _, name := range tc.AcceptedHashes {
		if h := hashByName(name); h != 0 {
			cfg.AcceptedHashes = append(cfg.AcceptedHashes, h)
		}
	}
	return cfg, nil
}

// resolveTSACAID resolves the configured issuing-CA reference (id or label) to
// its canonical id, requiring it to exist and be an X.509 issuer.
func resolveTSACAID(db *database.DB, caID, caLabel string) (string, error) {
	if caID == "" && caLabel != "" {
		found, err := db.GetCAByLabel(caLabel)
		if err != nil {
			return "", fmt.Errorf("looking up tsa CA by label %q: %w", caLabel, err)
		}
		if found == nil {
			return "", fmt.Errorf("tsa CA with label %q not found", caLabel)
		}
		caID = found.ID
	}
	if caID == "" {
		return "", fmt.Errorf("no tsa issuing CA configured (set ca_id or ca_label)")
	}
	issuer, err := db.GetCA(caID)
	if err != nil {
		return "", fmt.Errorf("looking up tsa CA %q: %w", caID, err)
	}
	if issuer == nil {
		return "", fmt.Errorf("tsa CA %q not found", caID)
	}
	if issuer.Certificate == "" {
		return "", fmt.Errorf("tsa CA %q is not an X.509 issuer (no certificate)", issuer.Label)
	}
	return caID, nil
}

// caChain returns the certificate chain for caID: the CA certificate followed
// by its parents up to the root.
//
// cas.parent_id is a self-referencing foreign key, so a corrupt hierarchy can
// contain a cycle (a CA pointing at itself, or two pointing at each other). The
// walk therefore stops at the first CA it has already visited: without that
// guard this loops forever while appending a certificate each iteration, and
// since LoadAuthorityConfig runs at server startup the process would hang
// there. The same guard protects the other parent-chain walks (see
// ca.Manager.issuerChainDER and database.GetCAAncestors).
func caChain(db *database.DB, caID string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	seen := make(map[string]bool)
	id := caID
	for id != "" && !seen[id] {
		seen[id] = true
		m, err := db.GetCA(id)
		if err != nil {
			return nil, fmt.Errorf("loading CA %q: %w", id, err)
		}
		if m == nil || m.Certificate == "" {
			break
		}
		cert, err := pki.ParseCertificatePEM([]byte(m.Certificate))
		if err != nil {
			return nil, fmt.Errorf("parsing CA %q certificate: %w", id, err)
		}
		chain = append(chain, cert)
		if m.ParentID == nil {
			break
		}
		id = *m.ParentID
	}
	return chain, nil
}

// parseChainPEM parses one or more concatenated PEM CERTIFICATE blocks.
func parseChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// hashByName maps a config hash name to a crypto.Hash (0 when empty/unknown).
func hashByName(name string) crypto.Hash {
	switch name {
	case "sha1":
		return crypto.SHA1
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return 0
	}
}

// parseDottedOID parses a dotted-decimal OID into an asn1.ObjectIdentifier.
//
// It rejects anything that cannot be DER-encoded, not merely anything that is
// not a number. The configured policy OID is asserted verbatim in every token
// this TSA signs, and encoding/asn1 is unhelpful in both directions here: it
// refuses an out-of-range leading arc pair (X.690 §8.19 packs the first two
// arcs into one subidentifier, so arc1 must be 0..2 and arc2 < 40 unless
// arc1 == 2) only at marshal time — which would turn every /tsa request into an
// internal error — and it does not refuse a NEGATIVE arc at all, silently
// emitting a zero-length OBJECT IDENTIFIER that no verifier can decode. Both
// failures are caught here so a bad policy_oid stops the server at startup.
func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component %q", p)
		}
		if n < 0 {
			return nil, fmt.Errorf("invalid OID component %q: components must not be negative", p)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("OID %q has fewer than two components", s)
	}
	if _, err := asn1.Marshal(oid); err != nil {
		return nil, fmt.Errorf("OID %q cannot be DER-encoded: %w", s, err)
	}
	return oid, nil
}
