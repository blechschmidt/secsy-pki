package cmp

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// protector produces the message-protection algorithm identifier and the
// protection bits (with any accompanying extraCerts) for a response.
type protector interface {
	algorithm() (pkix.AlgorithmIdentifier, error)
	protect(protectedPart []byte) (sig []byte, extraCerts [][]byte, err error)
}

// pbmProtector protects a response with a shared secret (PasswordBasedMac),
// mirroring a MAC-protected request.
type pbmProtector struct {
	secret []byte
	params pbmParameter
}

func (p pbmProtector) algorithm() (pkix.AlgorithmIdentifier, error) {
	return pbmProtectionAlg(p.params)
}

func (p pbmProtector) protect(protectedPart []byte) ([]byte, [][]byte, error) {
	mac, err := computePBM(p.secret, protectedPart, p.params)
	return mac, nil, err
}

// sigProtector protects a response with a signature from the CA key, embedding
// the CA certificate chain as extraCerts so the client can verify it.
type sigProtector struct {
	signer crypto.Signer
	alg    pkix.AlgorithmIdentifier
	hash   crypto.Hash
	eddsa  bool
	chain  [][]byte
}

func (p sigProtector) algorithm() (pkix.AlgorithmIdentifier, error) { return p.alg, nil }

func (p sigProtector) protect(protectedPart []byte) ([]byte, [][]byte, error) {
	sig, err := signData(p.signer, protectedPart, p.hash, p.eddsa)
	if err != nil {
		return nil, nil, err
	}
	return sig, p.chain, nil
}

// buildResponse assembles a protected PKIMessage: it fixes the protection
// algorithm in the header, reconstructs the protected part (SEQUENCE { header,
// body }), computes the protection over it, and appends the protection and any
// extraCerts.
func buildResponse(h headerFields, bodyTag int, bodyContent []byte, p protector) ([]byte, error) {
	alg, err := p.algorithm()
	if err != nil {
		return nil, err
	}
	h.ProtectionAlg = &alg
	headerDER, err := buildHeaderDER(h)
	if err != nil {
		return nil, err
	}
	body := explicitTLV(bodyTag, bodyContent)
	protectedPart := wrapSequence(concat(headerDER, body))

	sig, extraCerts, err := p.protect(protectedPart)
	if err != nil {
		return nil, err
	}
	bsDER, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	if err != nil {
		return nil, err
	}
	parts := [][]byte{headerDER, body, explicitTLV(0, bsDER)}
	if len(extraCerts) > 0 {
		parts = append(parts, explicitTLV(1, wrapSequence(concat(extraCerts...))))
	}
	return wrapSequence(concat(parts...)), nil
}

// buildUnprotected assembles a PKIMessage with no protection field. It is used
// for error responses to messages that could not be authenticated (RFC 4210
// permits unprotected error messages).
func buildUnprotected(h headerFields, bodyTag int, bodyContent []byte) ([]byte, error) {
	h.ProtectionAlg = nil
	headerDER, err := buildHeaderDER(h)
	if err != nil {
		return nil, err
	}
	body := explicitTLV(bodyTag, bodyContent)
	return wrapSequence(concat(headerDER, body)), nil
}

// ---- body content builders ------------------------------------------------

// buildPKIStatusInfo encodes a PKIStatusInfo. When failBit >= 0 a failInfo
// BIT STRING with that bit set is included; statusString is included when text
// is non-empty.
func buildPKIStatusInfo(status int, text string, failBit int) ([]byte, error) {
	statusDER, err := asn1.Marshal(status)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{statusDER}
	if text != "" {
		utf8DER, err := asn1.MarshalWithParams(text, "utf8")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapSequence(utf8DER)) // PKIFreeText SEQUENCE OF UTF8String
	}
	if failBit >= 0 {
		fi, err := failInfoBitString(failBit)
		if err != nil {
			return nil, err
		}
		parts = append(parts, fi)
	}
	return wrapSequence(concat(parts...)), nil
}

// failInfoBitString encodes a PKIFailureInfo BIT STRING with a single bit set.
func failInfoBitString(bit int) ([]byte, error) {
	byteLen := bit/8 + 1
	b := make([]byte, byteLen)
	b[bit/8] |= 1 << uint(7-bit%8)
	return asn1.Marshal(asn1.BitString{Bytes: b, BitLength: bit + 1})
}

// buildCertResponse encodes a CertResponse granting a certificate for a request.
func buildCertResponse(certReqID int, certDER []byte) ([]byte, error) {
	statusInfo, err := buildPKIStatusInfo(statusAccepted, "", -1)
	if err != nil {
		return nil, err
	}
	idDER, err := asn1.Marshal(certReqID)
	if err != nil {
		return nil, err
	}
	// CertifiedKeyPair { certOrEncCert: certificate [0] CMPCertificate }.
	// CMPCertificate is a CHOICE, so the [0] tag is explicit around the cert.
	ckp := wrapSequence(explicitTLV(0, certDER))
	return wrapSequence(concat(idDER, statusInfo, ckp)), nil
}

// buildCertRepMessage encodes a CertRepMessage carrying one CertResponse.
func buildCertRepMessage(certResponse []byte) []byte {
	response := wrapSequence(certResponse) // SEQUENCE OF CertResponse
	return wrapSequence(response)
}

// buildRevRepContent encodes a RevRepContent with a single PKIStatusInfo.
func buildRevRepContent(status int) ([]byte, error) {
	statusInfo, err := buildPKIStatusInfo(status, "", -1)
	if err != nil {
		return nil, err
	}
	statusSeq := wrapSequence(statusInfo) // SEQUENCE OF PKIStatusInfo
	return wrapSequence(statusSeq), nil
}

// buildErrorContent encodes an ErrorMsgContent with the given rejection status,
// human-readable text, and failure-info bit.
func buildErrorContent(text string, failBit int) ([]byte, error) {
	statusInfo, err := buildPKIStatusInfo(statusRejection, text, failBit)
	if err != nil {
		return nil, fmt.Errorf("building error content: %w", err)
	}
	return wrapSequence(statusInfo), nil
}
