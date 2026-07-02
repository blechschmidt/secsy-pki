// Package scep implements the SCEP (Simple Certificate Enrollment Protocol,
// RFC 8894) server operations — GetCACaps, GetCACert and PKIOperation — on top
// of the HSM-backed ca.Manager issuance layer. Network devices, MDM systems and
// IoT clients enroll by wrapping a PKCS#10 request in a PKCS#7 pkiMessage; the
// CA private key never leaves its provider (all signing and the enveloped-data
// key unwrap flow through crypto.Signer / crypto.Decrypter).
package scep

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// SCEP authenticated-attribute OIDs (RFC 8894 §3.2, in the
// 2.16.840.1.113733.1.9 arc historically assigned by VeriSign).
var (
	oidSCEPMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// SCEP message types (RFC 8894 §3.2.1.2).
const (
	msgTypePKCSReq        = "19" // PKCS#10 enrollment (initial or renewal)
	msgTypeCertRep        = "3"  // certificate response
	msgTypeGetCertInitial = "20" // poll for a pending enrollment
	msgTypeGetCert        = "21"
	msgTypeGetCRL         = "22"
)

// SCEP pkiStatus values (RFC 8894 §3.2.1.3).
const (
	pkiStatusSuccess = "0"
	pkiStatusFailure = "2"
	pkiStatusPending = "3"
)

// SCEP failInfo values (RFC 8894 §3.2.1.4).
const (
	failInfoBadAlg          = "0"
	failInfoBadMessageCheck = "1"
	failInfoBadRequest      = "2"
	failInfoBadTime         = "3"
	failInfoBadCertID       = "4"
)

// pkiMessage is a decoded SCEP pkiMessage. For a request, CSR holds the
// decrypted PKCS#10 and SignerCert the (self-signed or previously issued)
// certificate that signed the request.
type pkiMessage struct {
	TransactionID string
	MessageType   string
	SenderNonce   []byte

	SignerCert *x509.Certificate
	CSR        *x509.CertificateRequest
}

// parseRequest decodes and verifies an inbound SCEP pkiMessage. The enveloped
// payload is decrypted with the CA's key through dec (HSM-backed), so the CA
// private key never leaves the provider. caCert is the recipient the client
// encrypted to.
func parseRequest(der []byte, caCert *x509.Certificate, dec crypto.Decrypter) (*pkiMessage, error) {
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, err
	}
	if err := sd.Verify(); err != nil {
		return nil, err
	}

	msg := &pkiMessage{SignerCert: sd.SignerCertificate()}

	var perr error
	if msg.TransactionID, perr = stringAttr(sd, oidSCEPTransactionID); perr != nil {
		return nil, fmt.Errorf("scep: transactionID: %w", perr)
	}
	if msg.MessageType, perr = stringAttr(sd, oidSCEPMessageType); perr != nil {
		return nil, fmt.Errorf("scep: messageType: %w", perr)
	}
	if msg.SenderNonce, perr = octetAttr(sd, oidSCEPSenderNonce); perr != nil {
		return nil, fmt.Errorf("scep: senderNonce: %w", perr)
	}

	switch msg.MessageType {
	case msgTypePKCSReq:
		env, err := cms.ParseEnvelopedData(sd.Content)
		if err != nil {
			return nil, err
		}
		csrDER, err := env.Decrypt(caCert, dec)
		if err != nil {
			return nil, err
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, fmt.Errorf("scep: parsing enveloped CSR: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("scep: CSR signature invalid: %w", err)
		}
		msg.CSR = csr
	case msgTypeGetCertInitial, msgTypeGetCert, msgTypeGetCRL:
		// These are recognized but not serviced by this server; the caller maps
		// them to an appropriate failInfo.
	default:
		return nil, fmt.Errorf("scep: unsupported messageType %q", msg.MessageType)
	}
	return msg, nil
}

// certRepArgs parameterizes a CertRep (success or failure) response.
type certRepArgs struct {
	transactionID  string
	recipientNonce []byte // echo of the request's senderNonce
	senderNonce    []byte // fresh nonce
	// Success path:
	issued    *x509.Certificate
	chain     []*x509.Certificate // certs to return (leaf first)
	recipient *x509.Certificate   // client cert to encrypt the response to
	// Failure path:
	failInfo string // non-empty selects the FAILURE status

	// CA signing identity (HSM-backed).
	caCert *x509.Certificate
	signer crypto.Signer
}

// buildCertRep assembles a signed SCEP CertRep. On success the issued
// certificate chain is wrapped in a degenerate certs-only SignedData, enveloped
// to the requester, and signed by the CA with pkiStatus=SUCCESS. On failure a
// signed response with pkiStatus=FAILURE and the given failInfo is returned.
func buildCertRep(a certRepArgs) ([]byte, error) {
	attrs := []cms.Attribute{
		{Type: oidSCEPTransactionID, Value: a.transactionID},
		{Type: oidSCEPMessageType, Value: msgTypeCertRep},
		{Type: oidSCEPSenderNonce, Value: a.senderNonce},
		{Type: oidSCEPRecipientNonce, Value: a.recipientNonce},
	}

	var content []byte
	if a.failInfo != "" {
		attrs = append(attrs,
			cms.Attribute{Type: oidSCEPPKIStatus, Value: pkiStatusFailure},
			cms.Attribute{Type: oidSCEPFailInfo, Value: a.failInfo},
		)
	} else {
		degenerate, err := cms.DegenerateCertsOnly(a.chain)
		if err != nil {
			return nil, err
		}
		enveloped, err := cms.BuildEnvelopedData(degenerate, a.recipient)
		if err != nil {
			return nil, err
		}
		content = enveloped
		attrs = append(attrs, cms.Attribute{Type: oidSCEPPKIStatus, Value: pkiStatusSuccess})
	}

	return cms.BuildSignedData(cms.SignedDataOpts{
		Content:      content,
		SignerCert:   a.caCert,
		Signer:       a.signer,
		Digest:       crypto.SHA256,
		Certificates: []*x509.Certificate{a.caCert},
		ExtraAttrs:   attrs,
	})
}

// stringAttr extracts a PrintableString/UTF8String SCEP attribute.
func stringAttr(sd *cms.ParsedSignedData, oid asn1.ObjectIdentifier) (string, error) {
	raw, ok := sd.AuthenticatedAttribute(oid)
	if !ok {
		return "", fmt.Errorf("attribute %v not present", oid)
	}
	var s string
	if _, err := asn1.Unmarshal(raw.FullBytes, &s); err != nil {
		return "", err
	}
	return s, nil
}

// octetAttr extracts an OCTET STRING SCEP attribute.
func octetAttr(sd *cms.ParsedSignedData, oid asn1.ObjectIdentifier) ([]byte, error) {
	raw, ok := sd.AuthenticatedAttribute(oid)
	if !ok {
		return nil, fmt.Errorf("attribute %v not present", oid)
	}
	var b []byte
	if _, err := asn1.Unmarshal(raw.FullBytes, &b); err != nil {
		return nil, err
	}
	return b, nil
}
