// Package ers implements RFC 4998 Evidence Record Syntax (ERS), a long-term
// preservation layer for the tamper-evident audit chain (internal/audit) and
// signed artifacts (the CAdES-LT signing path). It closes the LTANS / eIDAS
// preservation gap left open by RFC 3161 audit-chain anchoring (internal/anchor,
// Task 64): an anchor proves a chain head existed at a point in time, but a
// single RFC 3161 token becomes worthless once its hash or signature algorithm
// is broken. An Evidence Record instead carries a *renewable* chain of archive
// timestamps so a protected data object's existence survives both time-stamp
// certificate expiry (time-stamp renewal) and hash/signature-algorithm
// obsolescence (hash-tree renewal), driven by the internal/fips crypto policy.
//
// An EvidenceRecord binds a set of protected data objects into a Merkle hash
// tree, obtains an RFC 3161 ArchiveTimeStamp over the tree root from the
// deployment's internal HSM-backed TSA (internal/tsa, reusing
// tsa.LoadAuthorityConfig), and stores, for each object, the reduced hash tree
// (the authentication path) needed to recompute the root. Renewal appends:
//
//   - Time-stamp renewal — a fresh ArchiveTimeStamp over the previous
//     timestamp token, appended to the same ArchiveTimeStampChain, before the
//     current TSA certificate expires. Same hash algorithm.
//
//   - Hash-tree renewal — the protected data objects and the entire prior
//     ArchiveTimeStampSequence are re-hashed with a stronger algorithm and a
//     new ArchiveTimeStampChain is appended to the ArchiveTimeStampSequence,
//     when the current algorithm is deprecated. New hash algorithm.
//
// The wire structures follow RFC 4998's ASN.1 module (IMPLICIT tags, matching
// the BouncyCastle/DSS encoding). All signing flows through the shared
// Timestamper abstraction so private key material never leaves the HSM.
package ers

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"

	// Register the hash implementations the tree/timestamp digests use so a
	// plain import of this package guarantees they are linked in.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Version is the only EvidenceRecord version defined by RFC 4998 (v1).
const Version = 1

// Object identifiers from RFC 4998 §6 (evidence-record CMS attributes) and the
// digest algorithms used in the hash tree / message imprints.
var (
	// OIDEvidenceRecord is id-aa-er-internal, the CMS unsigned attribute that
	// carries an EvidenceRecord alongside the data it protects (RFC 4998 §6). We
	// emit standalone EvidenceRecords, but expose the OID for callers embedding
	// one in a CMS structure.
	OIDEvidenceRecord = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 49}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// ---- RFC 4998 ASN.1 wire structures ---------------------------------------
//
// RFC 4998's module uses IMPLICIT tags, so the context-tagged optional fields
// replace (not wrap) the tagged type's universal tag. Go's encoding/asn1
// defaults a `tag:N` struct tag to IMPLICIT, which matches; the distinct tag
// numbers ([0]/[1]/[2]) let the decoder dispatch the optionals unambiguously.

// evidenceRecord is RFC 4998 EvidenceRecord.
//
//	EvidenceRecord ::= SEQUENCE {
//	   version                   INTEGER { v1(1) },
//	   digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
//	   cryptoInfos               [0] CryptoInfos OPTIONAL,
//	   encryptionInfo            [1] EncryptionInfo OPTIONAL,
//	   archiveTimeStampSequence  ArchiveTimeStampSequence }
type evidenceRecord struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier
	CryptoInfos      asn1.RawValue `asn1:"optional,tag:0"`
	EncryptionInfo   asn1.RawValue `asn1:"optional,tag:1"`
	// ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain, and
	// ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp.
	ArchiveTimeStampSequence []archiveTimeStampChain
}

// archiveTimeStampChain is RFC 4998 ArchiveTimeStampChain (SEQUENCE OF
// ArchiveTimeStamp). All ArchiveTimeStamps within one chain share a hash
// algorithm; a new chain begins on hash-tree renewal.
type archiveTimeStampChain []archiveTimeStamp

// archiveTimeStamp is RFC 4998 ArchiveTimeStamp.
//
//	ArchiveTimeStamp ::= SEQUENCE {
//	   digestAlgorithm [0] AlgorithmIdentifier OPTIONAL,
//	   attributes      [1] Attributes OPTIONAL,
//	   reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
//	   timeStamp       ContentInfo }
type archiveTimeStamp struct {
	DigestAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,tag:0"`
	Attributes      asn1.RawValue            `asn1:"optional,tag:1"`
	ReducedHashtree []partialHashtree        `asn1:"optional,tag:2"`
	// TimeStamp is a ContentInfo (an RFC 3161 TimeStampToken), embedded verbatim.
	TimeStamp asn1.RawValue
}

// partialHashtree is RFC 4998 PartialHashtree (SEQUENCE OF OCTET STRING): the
// set of hash values sharing one parent node in the reduced hash tree.
type partialHashtree [][]byte

// ---- digest algorithm mapping ---------------------------------------------

// digestForOID maps a digest-algorithm OID to its crypto.Hash, reporting false
// for an algorithm this package does not implement.
func digestForOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// oidForDigest is the inverse of digestForOID.
func oidForDigest(h crypto.Hash) (asn1.ObjectIdentifier, bool) {
	switch h {
	case crypto.SHA256:
		return oidSHA256, true
	case crypto.SHA384:
		return oidSHA384, true
	case crypto.SHA512:
		return oidSHA512, true
	default:
		return nil, false
	}
}

// algorithmIdentifier builds a DER AlgorithmIdentifier for a hash, with the
// absent-parameters encoding conventional for the SHA-2 family.
func algorithmIdentifier(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	oid, ok := oidForDigest(h)
	if !ok {
		return pkix.AlgorithmIdentifier{}, &UnsupportedHashError{Hash: h}
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
}

// HashName renders a crypto.Hash as the lowercase config/JSON name used across
// the codebase ("sha256", ...); it returns "unknown" for unsupported hashes.
func HashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return "unknown"
	}
}

// HashByName maps a config/CLI hash name to a crypto.Hash (0 for empty/unknown).
func HashByName(name string) crypto.Hash {
	switch name {
	case "sha256", "sha-256", "SHA256", "SHA-256":
		return crypto.SHA256
	case "sha384", "sha-384", "SHA384", "SHA-384":
		return crypto.SHA384
	case "sha512", "sha-512", "SHA512", "SHA-512":
		return crypto.SHA512
	default:
		return 0
	}
}
