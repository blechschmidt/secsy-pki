package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// logEntryTypePrecert is the RFC 6962 LogEntryType for a precertificate entry.
const logEntryTypePrecert = 1

// signatureTypeCertificateTimestamp is the RFC 6962 SignatureType covering an
// SCT (as opposed to a signed tree head).
const signatureTypeCertificateTimestamp = 0

// TLS SignatureAndHashAlgorithm codes used by CT logs (RFC 5246 §7.4.1.4.1).
const (
	hashAlgSHA256 = 4
	sigAlgRSA     = 1
	sigAlgECDSA   = 3
)

// addChainResponse is the JSON body returned by add-chain / add-pre-chain
// (RFC 6962 §4.2).
type addChainResponse struct {
	SCTVersion uint8  `json:"sct_version"`
	ID         string `json:"id"`
	Timestamp  uint64 `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

// parseSCTResponse decodes an add-pre-chain JSON response into an SCT.
func parseSCTResponse(body []byte) (*SCT, error) {
	var r addChainResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decoding SCT response: %w", err)
	}
	id, err := base64.StdEncoding.DecodeString(r.ID)
	if err != nil {
		return nil, fmt.Errorf("decoding log id: %w", err)
	}
	if len(id) != 32 {
		return nil, fmt.Errorf("log id has length %d, want 32", len(id))
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding SCT signature: %w", err)
	}
	var ext []byte
	if r.Extensions != "" {
		if ext, err = base64.StdEncoding.DecodeString(r.Extensions); err != nil {
			return nil, fmt.Errorf("decoding SCT extensions: %w", err)
		}
	}
	sct := &SCT{
		Version:    r.SCTVersion,
		Timestamp:  r.Timestamp,
		Extensions: ext,
		Signature:  sig,
	}
	copy(sct.LogID[:], id)
	return sct, nil
}

// marshal serialises the SCT into the TLS SignedCertificateTimestamp structure
// used inside an SCT list (RFC 6962 §3.2).
func (s *SCT) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(s.Version)
	b.AddBytes(s.LogID[:])
	b.AddUint64(s.Timestamp)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		c.AddBytes(s.Extensions)
	})
	// The digitally-signed structure (algorithm + length-prefixed signature) is
	// stored verbatim and appended as-is.
	b.AddBytes(s.Signature)
	return b.Bytes()
}

// SCTListExtension builds the non-critical SCT list extension embedding the
// given SCTs (RFC 6962 §3.3). The extension value is a DER OCTET STRING wrapping
// the TLS-encoded SignedCertificateTimestampList.
func SCTListExtension(scts []*SCT) (pkix.Extension, error) {
	if len(scts) == 0 {
		return pkix.Extension{}, fmt.Errorf("cannot build an SCT list from zero SCTs")
	}
	serialized := make([][]byte, len(scts))
	for i, s := range scts {
		sb, err := s.marshal()
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("serialising SCT %d: %w", i, err)
		}
		serialized[i] = sb
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, sb := range serialized {
			list.AddUint16LengthPrefixed(func(e *cryptobyte.Builder) {
				e.AddBytes(sb)
			})
		}
	})
	tlsList, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding SCT list: %w", err)
	}
	value, err := asn1.Marshal(tlsList) // wrap the TLS list in an OCTET STRING
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("wrapping SCT list: %w", err)
	}
	return pkix.Extension{Id: OIDSCTList, Value: value}, nil
}

// ParseSCTListExtension decodes the value of an SCT list extension (the
// pkix.Extension.Value, i.e. the inner OCTET STRING wrapping the TLS list) into
// its SCTs. It is the inverse of SCTListExtension and is used to inspect or
// verify the SCTs embedded in an issued certificate.
func ParseSCTListExtension(extnValue []byte) ([]*SCT, error) {
	var tlsList []byte
	rest, err := asn1.Unmarshal(extnValue, &tlsList)
	if err != nil {
		return nil, fmt.Errorf("unwrapping SCT list OCTET STRING: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes after SCT list OCTET STRING")
	}
	return parseSCTList(tlsList)
}

// parseSCTList decodes a TLS SignedCertificateTimestampList.
func parseSCTList(tlsList []byte) ([]*SCT, error) {
	input := cryptobyte.String(tlsList)
	var list cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&list) || !input.Empty() {
		return nil, fmt.Errorf("malformed SCT list framing")
	}
	var out []*SCT
	for !list.Empty() {
		var item cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&item) {
			return nil, fmt.Errorf("malformed SCT list entry")
		}
		sct, err := parseSCT(item)
		if err != nil {
			return nil, err
		}
		out = append(out, sct)
	}
	return out, nil
}

// parseSCT decodes a single TLS SignedCertificateTimestamp.
func parseSCT(s cryptobyte.String) (*SCT, error) {
	sct := &SCT{}
	var logID, ext cryptobyte.String
	if !s.ReadUint8(&sct.Version) ||
		!s.ReadBytes((*[]byte)(&logID), 32) ||
		!s.ReadUint64(&sct.Timestamp) ||
		!s.ReadUint16LengthPrefixed(&ext) {
		return nil, fmt.Errorf("malformed SCT structure")
	}
	copy(sct.LogID[:], logID)
	sct.Extensions = append([]byte(nil), ext...)
	// The remainder is the digitally-signed structure, kept verbatim.
	sct.Signature = append([]byte(nil), s...)
	return sct, nil
}

// Verify checks the SCT's signature against the log's public key over the
// precertificate entry for the given issuer and TBSCertificate. tbs must be the
// certificate's TBS with the SCT list (or poison) extension removed — obtain it
// with TBSWithoutExtension.
func (s *SCT) Verify(pub crypto.PublicKey, issuer *x509.Certificate, tbs []byte) error {
	return s.verify(pub, issuerKeyHash(issuer), tbs)
}

// issuerKeyHash returns the SHA-256 of the issuer's SubjectPublicKeyInfo, which
// binds an SCT to the issuing key (RFC 6962 §3.2).
func issuerKeyHash(issuer *x509.Certificate) [32]byte {
	return sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
}

// signatureInput reconstructs the CertificateTimestamp structure a CT log signs
// over for a precertificate entry (RFC 6962 §3.2). tbs is the precertificate's
// TBSCertificate with the poison extension removed.
func (s *SCT) signatureInput(issuerKeyHash [32]byte, tbs []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(s.Version)
	b.AddUint8(signatureTypeCertificateTimestamp)
	b.AddUint64(s.Timestamp)
	b.AddUint16(logEntryTypePrecert)
	// PreCert = issuer_key_hash[32] || tbs_certificate<1..2^24-1>.
	b.AddBytes(issuerKeyHash[:])
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
		c.AddBytes(tbs)
	})
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		c.AddBytes(s.Extensions)
	})
	return b.Bytes()
}

// verify checks the SCT's signature against the log's public key, over the
// precertificate entry described by issuerKeyHash and tbs. It returns nil when
// the signature is valid.
func (s *SCT) verify(pub crypto.PublicKey, issuerKeyHash [32]byte, tbs []byte) error {
	input, err := s.signatureInput(issuerKeyHash, tbs)
	if err != nil {
		return err
	}

	sig := cryptobyte.String(s.Signature)
	var hashAlg, sigAlg uint8
	var sigBytes cryptobyte.String
	if !sig.ReadUint8(&hashAlg) || !sig.ReadUint8(&sigAlg) ||
		!sig.ReadUint16LengthPrefixed(&sigBytes) || !sig.Empty() {
		return fmt.Errorf("malformed SCT digitally-signed structure")
	}
	if hashAlg != hashAlgSHA256 {
		return fmt.Errorf("unsupported SCT hash algorithm %d (only SHA-256 supported)", hashAlg)
	}
	digest := sha256.Sum256(input)

	switch sigAlg {
	case sigAlgECDSA:
		epub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("SCT declares ECDSA but log key is %T", pub)
		}
		if !ecdsa.VerifyASN1(epub, digest[:], sigBytes) {
			return fmt.Errorf("SCT ECDSA signature verification failed")
		}
	case sigAlgRSA:
		rpub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("SCT declares RSA but log key is %T", pub)
		}
		if err := rsa.VerifyPKCS1v15(rpub, crypto.SHA256, digest[:], sigBytes); err != nil {
			return fmt.Errorf("SCT RSA signature verification failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported SCT signature algorithm %d", sigAlg)
	}
	return nil
}

// TBSWithoutExtension returns the DER TBSCertificate of a certificate with the
// extension identified by oid removed. It is used to derive the exact bytes a CT
// log signs over: the precertificate's TBSCertificate with the poison extension
// stripped, which — because the poison and SCT list extensions are the only
// difference between the precertificate and final certificate — equals the
// final certificate's TBS with the SCT list stripped.
func TBSWithoutExtension(certDER []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	input := cryptobyte.String(certDER)
	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed certificate: no outer SEQUENCE")
	}
	var tbs cryptobyte.String
	if !cert.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed certificate: no TBSCertificate")
	}

	// The extensions field is [3] EXPLICIT and always last. Copy every earlier
	// field verbatim, then rewrite the extensions with the target OID filtered
	// out. Definite-length (DER) re-encoding of copied elements is what makes
	// the result byte-identical to a verifier's reconstruction.
	var prefix []byte
	var extensionsField cryptobyte.String
	found := false
	for !tbs.Empty() {
		var element cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1Element(&element, &tag) {
			return nil, fmt.Errorf("malformed TBSCertificate field")
		}
		if tag == cbasn1.Tag(3).Constructed().ContextSpecific() {
			extensionsField = element
			found = true
			break
		}
		prefix = append(prefix, element...)
	}
	if !found {
		return nil, fmt.Errorf("certificate has no extensions field")
	}

	filtered, err := filterExtensions(extensionsField, oid)
	if err != nil {
		return nil, err
	}

	var out cryptobyte.Builder
	out.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(prefix)
		b.AddBytes(filtered)
	})
	return out.Bytes()
}

// filterExtensions parses the [3] EXPLICIT extensions field and returns a
// re-encoded [3] field with the extension matching oid removed.
func filterExtensions(field cryptobyte.String, oid asn1.ObjectIdentifier) ([]byte, error) {
	// Unwrap [3] EXPLICIT, then the inner SEQUENCE OF Extension.
	var explicit cryptobyte.String
	if !field.ReadASN1(&explicit, cbasn1.Tag(3).Constructed().ContextSpecific()) {
		return nil, fmt.Errorf("malformed extensions [3] wrapper")
	}
	var extensions cryptobyte.String
	if !explicit.ReadASN1(&extensions, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed extensions SEQUENCE")
	}

	var kept [][]byte
	for !extensions.Empty() {
		var ext cryptobyte.String
		if !extensions.ReadASN1Element(&ext, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("malformed extension entry")
		}
		// Peek the OID without consuming the element we intend to copy.
		body := ext
		var seq cryptobyte.String
		var extOID asn1.ObjectIdentifier
		if !body.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&extOID) {
			return nil, fmt.Errorf("malformed extension OID")
		}
		if extOID.Equal(oid) {
			continue // drop
		}
		kept = append(kept, append([]byte(nil), ext...))
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(wrap *cryptobyte.Builder) {
		wrap.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
			for _, e := range kept {
				seq.AddBytes(e)
			}
		})
	})
	return b.Bytes()
}
