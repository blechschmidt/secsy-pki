// Package dnsrecords generates DNS pinning records for the key material this PKI
// issues, in standard zone-file presentation format.
//
// Two record families are supported:
//
//   - DANE TLSA (RFC 6698): for a TLS service reachable at host:port, records
//     that pin the end-entity certificate (usage DANE-EE) and/or its issuing CA
//     (usages PKIX-CA and DANE-TA), across both selectors (full certificate and
//     SubjectPublicKeyInfo) and both practical matching types (SHA-256 and the
//     verbatim, un-hashed content).
//   - SSHFP (RFC 4255, extended by RFC 6594 and RFC 7479): for an SSH host key —
//     supplied directly or extracted from an OpenSSH host certificate — records
//     that pin the host key under both defined fingerprint types (SHA-1 and
//     SHA-256), matching the output of "ssh-keygen -r".
//
// The package depends only on the standard library and golang.org/x/crypto/ssh,
// both already vendored. Association data / fingerprints are emitted as lowercase
// hexadecimal, matching RFC 6698's presentation-format examples and ssh-keygen.
package dnsrecords

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// TLSA certificate-usage field values (RFC 6698 §2.1.1).
const (
	// TLSAUsagePKIXTA ("PKIX-CA") asserts a CA in the chain that must also pass
	// the relying party's normal PKIX validation to a public trust anchor.
	TLSAUsagePKIXTA = 0
	// TLSAUsagePKIXEE ("PKIX-EE") asserts the end-entity certificate, still
	// subject to PKIX validation.
	TLSAUsagePKIXEE = 1
	// TLSAUsageDANETA ("DANE-TA") asserts a CA as a trust anchor in its own
	// right; it need not chain to a public root.
	TLSAUsageDANETA = 2
	// TLSAUsageDANEEE ("DANE-EE") asserts the end-entity certificate directly,
	// bypassing PKIX chain validation entirely.
	TLSAUsageDANEEE = 3
)

// TLSA selector field values (RFC 6698 §2.1.2).
const (
	// TLSASelectorFullCert selects the full DER-encoded certificate.
	TLSASelectorFullCert = 0
	// TLSASelectorSPKI selects the DER-encoded SubjectPublicKeyInfo, so the
	// record survives certificate renewal as long as the key is reused.
	TLSASelectorSPKI = 1
)

// TLSA matching-type field values (RFC 6698 §2.1.3).
const (
	// TLSAMatchingFull stores the selected content verbatim (no hash).
	TLSAMatchingFull = 0
	// TLSAMatchingSHA256 stores the SHA-256 digest of the selected content.
	TLSAMatchingSHA256 = 1
	// TLSAMatchingSHA512 stores the SHA-512 digest of the selected content.
	TLSAMatchingSHA512 = 2
)

// SSHFP algorithm field values (RFC 4255 §3.2, extended by RFC 6594 and 7479).
const (
	SSHFPAlgoRSA     = 1
	SSHFPAlgoDSA     = 2
	SSHFPAlgoECDSA   = 3
	SSHFPAlgoEd25519 = 4
)

// SSHFP fingerprint-type field values (RFC 4255 §3.2, extended by RFC 6594).
const (
	SSHFPTypeSHA1   = 1
	SSHFPTypeSHA256 = 2
)

// TLSARecord is one RFC 6698 DANE TLSA resource record, ready for both structured
// (JSON/API) consumption and zone-file presentation.
type TLSARecord struct {
	Name         string `json:"name"` // owner FQDN, e.g. "_443._tcp.host.example.com."
	Usage        int    `json:"usage"`
	Selector     int    `json:"selector"`
	MatchingType int    `json:"matching_type"`
	Data         string `json:"data"` // lowercase-hex certificate-association data
	Zone         string `json:"zone"` // full presentation-format line
}

// SSHFPRecord is one RFC 4255 SSHFP resource record.
type SSHFPRecord struct {
	Name      string `json:"name"` // owner FQDN, e.g. "host.example.com."
	Algorithm int    `json:"algorithm"`
	FPType    int    `json:"fptype"`
	Data      string `json:"data"` // lowercase-hex fingerprint
	Zone      string `json:"zone"` // full presentation-format line
}

// fqdn returns name as an absolute domain name (exactly one trailing dot), which
// is what a zone-file presentation-format owner field requires.
func fqdn(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return name + "."
}

// TLSAOwnerName builds the DANE owner name "_<port>._<protocol>.<host>." for a
// TLS service (RFC 6698 §3). protocol defaults to "tcp" when empty; a leading
// underscore in protocol is tolerated.
func TLSAOwnerName(host string, port int, protocol string) string {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	protocol = strings.TrimPrefix(protocol, "_")
	return fmt.Sprintf("_%d._%s.%s", port, protocol, fqdn(host))
}

// selectorContent returns the DER bytes selected by a TLSA selector.
func selectorContent(selector int, cert *x509.Certificate) ([]byte, error) {
	switch selector {
	case TLSASelectorFullCert:
		return cert.Raw, nil
	case TLSASelectorSPKI:
		return cert.RawSubjectPublicKeyInfo, nil
	default:
		return nil, fmt.Errorf("unknown TLSA selector %d", selector)
	}
}

// tlsaAssociation returns the lowercase-hex certificate-association data for the
// given selector and matching type (RFC 6698 §2.1).
func tlsaAssociation(selector, matchingType int, cert *x509.Certificate) (string, error) {
	selected, err := selectorContent(selector, cert)
	if err != nil {
		return "", err
	}
	switch matchingType {
	case TLSAMatchingFull:
		return hex.EncodeToString(selected), nil
	case TLSAMatchingSHA256:
		sum := sha256.Sum256(selected)
		return hex.EncodeToString(sum[:]), nil
	case TLSAMatchingSHA512:
		sum := sha512.Sum512(selected)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unknown TLSA matching type %d", matchingType)
	}
}

func (r TLSARecord) zoneLine() string {
	return fmt.Sprintf("%s IN TLSA %d %d %d %s", r.Name, r.Usage, r.Selector, r.MatchingType, r.Data)
}

// NewTLSARecord builds one TLSA record for cert at the given owner name and
// (usage, selector, matchingType) tuple.
func NewTLSARecord(owner string, usage, selector, matchingType int, cert *x509.Certificate) (TLSARecord, error) {
	if cert == nil {
		return TLSARecord{}, fmt.Errorf("nil certificate")
	}
	data, err := tlsaAssociation(selector, matchingType, cert)
	if err != nil {
		return TLSARecord{}, err
	}
	r := TLSARecord{
		Name:         owner,
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Data:         data,
	}
	r.Zone = r.zoneLine()
	return r, nil
}

// tlsaGrid ordering: selector 1 (SPKI) before 0 (full cert), and within each,
// matching type 1 (SHA-256) before 0 (verbatim). This lists the compact,
// renewal-resilient "1 1" record first and the verbose full-content records last.
var (
	tlsaSelectors     = []int{TLSASelectorSPKI, TLSASelectorFullCert}
	tlsaMatchingTypes = []int{TLSAMatchingSHA256, TLSAMatchingFull}
)

// tlsaGrid returns the selector×matching-type grid of records for one usage.
func tlsaGrid(owner string, usage int, cert *x509.Certificate) ([]TLSARecord, error) {
	out := make([]TLSARecord, 0, len(tlsaSelectors)*len(tlsaMatchingTypes))
	for _, sel := range tlsaSelectors {
		for _, mt := range tlsaMatchingTypes {
			r, err := NewTLSARecord(owner, usage, sel, mt, cert)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// LeafTLSARecords returns the DANE-EE(3) records for a leaf certificate served at
// owner, pinning the end-entity certificate directly across both selectors and
// the SHA-256 and verbatim matching types.
func LeafTLSARecords(owner string, leaf *x509.Certificate) ([]TLSARecord, error) {
	if leaf == nil {
		return nil, fmt.Errorf("nil leaf certificate")
	}
	return tlsaGrid(owner, TLSAUsageDANEEE, leaf)
}

// IssuerTLSARecords returns the issuing-CA records for owner: both PKIX-CA(0) —
// the CA must appear in a chain that also validates through the public PKIX
// hierarchy — and DANE-TA(2) — the CA is asserted as a trust anchor on its own.
// Publishing both lets a relying party choose either validation mode.
func IssuerTLSARecords(owner string, issuer *x509.Certificate) ([]TLSARecord, error) {
	if issuer == nil {
		return nil, fmt.Errorf("nil issuer certificate")
	}
	out := make([]TLSARecord, 0, 2*len(tlsaSelectors)*len(tlsaMatchingTypes))
	for _, usage := range []int{TLSAUsagePKIXTA, TLSAUsageDANETA} {
		g, err := tlsaGrid(owner, usage, issuer)
		if err != nil {
			return nil, err
		}
		out = append(out, g...)
	}
	return out, nil
}

// ParseSSHPublicKey parses an SSH public key — or an OpenSSH certificate — from
// authorized_keys presentation format.
func ParseSSHPublicKey(authorizedKey []byte) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH public key: %w", err)
	}
	return key, nil
}

// underlyingKey returns the plain host public key. When key is an OpenSSH
// certificate (as issued by the SSH CA), the SSHFP fingerprint is taken over the
// certified host key, not the certificate blob.
func underlyingKey(key ssh.PublicKey) ssh.PublicKey {
	if cert, ok := key.(*ssh.Certificate); ok {
		return cert.Key
	}
	return key
}

// sshfpAlgorithm maps an SSH public-key algorithm name to its SSHFP algorithm
// number (RFC 4255 §3.2, RFC 6594, RFC 7479).
func sshfpAlgorithm(keyType string) (int, error) {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return SSHFPAlgoRSA, nil
	case ssh.InsecureKeyAlgoDSA: //nolint:staticcheck // SA1019: recognising the legacy "ssh-dss" key type is required to emit its SSHFP record (RFC 4255 algorithm 2); nothing here generates or accepts a DSA key.
		return SSHFPAlgoDSA, nil
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return SSHFPAlgoECDSA, nil
	case ssh.KeyAlgoED25519:
		return SSHFPAlgoEd25519, nil
	default:
		return 0, fmt.Errorf("unsupported SSH key type %q for SSHFP", keyType)
	}
}

func (r SSHFPRecord) zoneLine() string {
	return fmt.Sprintf("%s IN SSHFP %d %d %s", r.Name, r.Algorithm, r.FPType, r.Data)
}

// sshfpTypes is the emission order: SHA-1 (RFC 4255) then SHA-256 (RFC 6594),
// matching "ssh-keygen -r".
var sshfpTypes = []int{SSHFPTypeSHA1, SSHFPTypeSHA256}

// SSHFPRecords returns the SSHFP records for an SSH host key at owner host,
// covering both defined fingerprint types (SHA-1 and SHA-256). When key is an
// OpenSSH certificate the fingerprint is taken over the certified host key.
func SSHFPRecords(host string, key ssh.PublicKey) ([]SSHFPRecord, error) {
	if key == nil {
		return nil, fmt.Errorf("nil public key")
	}
	pk := underlyingKey(key)
	if pk == nil {
		return nil, fmt.Errorf("certificate carries no public key")
	}
	algo, err := sshfpAlgorithm(pk.Type())
	if err != nil {
		return nil, err
	}
	blob := pk.Marshal()
	owner := fqdn(host)
	out := make([]SSHFPRecord, 0, len(sshfpTypes))
	for _, ft := range sshfpTypes {
		var data string
		switch ft {
		case SSHFPTypeSHA1:
			sum := sha1.Sum(blob)
			data = hex.EncodeToString(sum[:])
		case SSHFPTypeSHA256:
			sum := sha256.Sum256(blob)
			data = hex.EncodeToString(sum[:])
		default:
			return nil, fmt.Errorf("unknown SSHFP fingerprint type %d", ft)
		}
		r := SSHFPRecord{Name: owner, Algorithm: algo, FPType: ft, Data: data}
		r.Zone = r.zoneLine()
		out = append(out, r)
	}
	return out, nil
}

// TLSAZoneLines returns the presentation-format lines of the given TLSA records.
func TLSAZoneLines(records []TLSARecord) []string {
	lines := make([]string, len(records))
	for i, r := range records {
		lines[i] = r.Zone
	}
	return lines
}

// SSHFPZoneLines returns the presentation-format lines of the given SSHFP records.
func SSHFPZoneLines(records []SSHFPRecord) []string {
	lines := make([]string, len(records))
	for i, r := range records {
		lines[i] = r.Zone
	}
	return lines
}

// Zone joins zone-file record lines into a single presentation-format block: one
// record per line, no trailing newline.
func Zone(lines []string) string {
	return strings.Join(lines, "\n")
}

// Bundle is a generated set of DNS records plus the combined zone-file text,
// suitable for direct JSON serialization by the CLI and REST API. The Zone field
// is the copy-and-paste block an operator adds to their zone file.
type Bundle struct {
	TLSA  []TLSARecord  `json:"tlsa,omitempty"`
	SSHFP []SSHFPRecord `json:"sshfp,omitempty"`
	Zone  string        `json:"zone"`
}

// NewBundle assembles a Bundle from TLSA and/or SSHFP records, computing the
// combined zone text (TLSA lines first, then SSHFP lines) in the order given.
func NewBundle(tlsa []TLSARecord, sshfp []SSHFPRecord) Bundle {
	lines := make([]string, 0, len(tlsa)+len(sshfp))
	lines = append(lines, TLSAZoneLines(tlsa)...)
	lines = append(lines, SSHFPZoneLines(sshfp)...)
	return Bundle{TLSA: tlsa, SSHFP: sshfp, Zone: Zone(lines)}
}
