package cmp

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"time"
)

// RequestOptions carries optional per-request fields. Zero values are filled
// with fresh random transaction id / sender nonce and the current time.
type RequestOptions struct {
	TransactionID   []byte
	SenderNonce     []byte
	ImplicitConfirm bool
	Now             time.Time
	// SANs to place in the request template.
	DNSNames    []string
	IPAddresses []net.IP
	Emails      []string
	URIs        []string
}

func (o RequestOptions) filled() RequestOptions {
	if len(o.TransactionID) == 0 {
		o.TransactionID = randomBytes(16)
	}
	if len(o.SenderNonce) == 0 {
		o.SenderNonce = randomBytes(16)
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	return o
}

// BuildInitializationRequest builds a MAC-protected ir PKIMessage requesting a
// certificate for subject/key, authenticated by a shared secret.
func BuildInitializationRequest(reference, secret string, subject pkix.Name, key crypto.Signer, opts RequestOptions) ([]byte, error) {
	return buildMACCertRequest(bodyIR, reference, secret, subject, key, opts)
}

// BuildCertificationRequest builds a MAC-protected cr PKIMessage.
func BuildCertificationRequest(reference, secret string, subject pkix.Name, key crypto.Signer, opts RequestOptions) ([]byte, error) {
	return buildMACCertRequest(bodyCR, reference, secret, subject, key, opts)
}

// buildMACCertRequest builds a MAC-protected ir/cr request.
func buildMACCertRequest(bodyTag int, reference, secret string, subject pkix.Name, key crypto.Signer, opts RequestOptions) ([]byte, error) {
	opts = opts.filled()
	bodyContent, err := buildCertReqBody(subject, key, opts)
	if err != nil {
		return nil, err
	}
	params, err := clientPBM()
	if err != nil {
		return nil, err
	}
	hdr := headerFields{
		Pvno:            pvnoCMP2000,
		Sender:          generalNameDirectory(pkix.Name{CommonName: reference}),
		Recipient:       generalNameDirectory(pkix.Name{}),
		MessageTime:     opts.Now,
		SenderKID:       []byte(reference),
		TransactionID:   opts.TransactionID,
		SenderNonce:     opts.SenderNonce,
		ImplicitConfirm: opts.ImplicitConfirm,
	}
	return buildResponse(hdr, bodyTag, bodyContent, pbmProtector{secret: []byte(secret), params: params})
}

// BuildKeyUpdateRequest builds a signature-protected kur PKIMessage: the message
// is signed by the existing certificate's key (oldKey), and the CertRequest is
// rekeyed to newKey with a proof of possession over newKey.
func BuildKeyUpdateRequest(oldCert *x509.Certificate, oldKey crypto.Signer, subject pkix.Name, newKey crypto.Signer, opts RequestOptions) ([]byte, error) {
	opts = opts.filled()
	bodyContent, err := buildCertReqBody(subject, newKey, opts)
	if err != nil {
		return nil, err
	}
	alg, hash, eddsa, err := signatureAlgForKey(oldKey.Public())
	if err != nil {
		return nil, err
	}
	hdr := headerFields{
		Pvno:            pvnoCMP2000,
		Sender:          generalNameDirectory(oldCert.Subject),
		Recipient:       generalNameDirectory(oldCert.Issuer),
		MessageTime:     opts.Now,
		TransactionID:   opts.TransactionID,
		SenderNonce:     opts.SenderNonce,
		ImplicitConfirm: opts.ImplicitConfirm,
	}
	prot := sigProtector{signer: oldKey, alg: alg, hash: hash, eddsa: eddsa, chain: [][]byte{oldCert.Raw}}
	return buildResponse(hdr, bodyKUR, bodyContent, prot)
}

// BuildRevocationRequest builds a signature-protected rr PKIMessage revoking the
// signer's own certificate.
func BuildRevocationRequest(cert *x509.Certificate, key crypto.Signer, opts RequestOptions) ([]byte, error) {
	opts = opts.filled()
	template, err := buildRevTemplate(revIssuerName(cert), cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	revDetails := wrapSequence(template)    // RevDetails { certDetails }
	bodyContent := wrapSequence(revDetails) // RevReqContent SEQUENCE OF RevDetails
	alg, hash, eddsa, err := signatureAlgForKey(key.Public())
	if err != nil {
		return nil, err
	}
	hdr := headerFields{
		Pvno:          pvnoCMP2000,
		Sender:        generalNameDirectory(cert.Subject),
		Recipient:     generalNameDirectory(cert.Issuer),
		MessageTime:   opts.Now,
		TransactionID: opts.TransactionID,
		SenderNonce:   opts.SenderNonce,
	}
	prot := sigProtector{signer: key, alg: alg, hash: hash, eddsa: eddsa, chain: [][]byte{cert.Raw}}
	return buildResponse(hdr, bodyRR, bodyContent, prot)
}

// BuildRevocationRequestMAC builds a MAC-protected rr PKIMessage revoking a
// certificate identified by issuer and serial, authenticated by a shared secret.
func BuildRevocationRequestMAC(reference, secret string, issuer pkix.Name, serial *big.Int, opts RequestOptions) ([]byte, error) {
	opts = opts.filled()
	template, err := buildRevTemplate(issuer, serial)
	if err != nil {
		return nil, err
	}
	bodyContent := wrapSequence(wrapSequence(template))
	params, err := clientPBM()
	if err != nil {
		return nil, err
	}
	hdr := headerFields{
		Pvno:          pvnoCMP2000,
		Sender:        generalNameDirectory(pkix.Name{CommonName: reference}),
		Recipient:     generalNameDirectory(issuer),
		MessageTime:   opts.Now,
		SenderKID:     []byte(reference),
		TransactionID: opts.TransactionID,
		SenderNonce:   opts.SenderNonce,
	}
	return buildResponse(hdr, bodyRR, bodyContent, pbmProtector{secret: []byte(secret), params: params})
}

// buildCertReqBody builds a CertReqMessages body carrying one CertReqMsg with a
// signature proof of possession over the request.
func buildCertReqBody(subject pkix.Name, key crypto.Signer, opts RequestOptions) ([]byte, error) {
	tmpl, err := buildCertTemplate(templateParams{
		subject:   subject,
		publicKey: key.Public(),
		dnsNames:  opts.DNSNames,
		ips:       opts.IPAddresses,
		emails:    opts.Emails,
		uris:      opts.URIs,
	})
	if err != nil {
		return nil, err
	}
	idDER, err := asn1.Marshal(0) // certReqId
	if err != nil {
		return nil, err
	}
	certReq := wrapSequence(concat(idDER, tmpl))

	alg, hash, eddsa, err := signatureAlgForKey(key.Public())
	if err != nil {
		return nil, err
	}
	sig, err := signData(key, certReq, hash, eddsa)
	if err != nil {
		return nil, fmt.Errorf("computing proof of possession: %w", err)
	}
	algDER, err := asn1.Marshal(alg)
	if err != nil {
		return nil, err
	}
	bsDER, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	if err != nil {
		return nil, err
	}
	// ProofOfPossession signature [1] POPOSigningKey (IMPLICIT retag of the
	// POPOSigningKey SEQUENCE, which holds the algorithm id and the signature).
	popo := explicitTLV(1, concat(algDER, bsDER))
	certReqMsg := wrapSequence(concat(certReq, popo))
	return wrapSequence(certReqMsg), nil
}

// Result is a parsed CMP response.
type Result struct {
	BodyTag     int
	Status      int
	Certificate *x509.Certificate
	StatusText  string
	FailInfo    []byte
}

// Accepted reports whether the response granted the request.
func (r *Result) Accepted() bool {
	return r.Status == statusAccepted || r.Status == statusGrantedWithMods
}

// ParseResponse decodes a CMP response PKIMessage, extracting the status and any
// issued certificate.
func ParseResponse(der []byte) (*Result, error) {
	msg, err := parseMessage(der)
	if err != nil {
		return nil, err
	}
	res := &Result{BodyTag: msg.bodyTag}
	switch msg.bodyTag {
	case bodyIP, bodyCP, bodyKUP:
		status, cert, text, err := parseCertRepMessage(msg.bodyContent)
		if err != nil {
			return nil, err
		}
		res.Status = status
		res.Certificate = cert
		res.StatusText = text
	case bodyRP:
		status, text, err := parseRevRepContent(msg.bodyContent)
		if err != nil {
			return nil, err
		}
		res.Status = status
		res.StatusText = text
	case bodyError:
		status, text, err := parseErrorContent(msg.bodyContent)
		if err != nil {
			return nil, err
		}
		res.Status = status
		res.StatusText = text
	default:
		return nil, fmt.Errorf("unexpected response body type %d", msg.bodyTag)
	}
	return res, nil
}

// parseCertRepMessage extracts the status and certificate from an ip/cp/kup body.
func parseCertRepMessage(bodyContent []byte) (int, *x509.Certificate, string, error) {
	top, err := seqElements(bodyContent)
	if err != nil {
		return 0, nil, "", err
	}
	var respSeq *asn1.RawValue
	for i := range top {
		if top[i].Class == asn1.ClassUniversal && top[i].Tag == asn1.TagSequence {
			respSeq = &top[i]
		}
	}
	if respSeq == nil {
		return 0, nil, "", fmt.Errorf("CertRepMessage has no response sequence")
	}
	responses, err := walkSequence(respSeq.Bytes)
	if err != nil {
		return 0, nil, "", err
	}
	if len(responses) == 0 {
		return 0, nil, "", fmt.Errorf("CertRepMessage has no CertResponse")
	}
	fields, err := walkSequence(responses[0].Bytes)
	if err != nil {
		return 0, nil, "", err
	}
	if len(fields) < 2 {
		return 0, nil, "", fmt.Errorf("CertResponse missing status")
	}
	status, text, err := parsePKIStatusInfo(fields[1].FullBytes)
	if err != nil {
		return 0, nil, "", err
	}
	var cert *x509.Certificate
	if len(fields) >= 3 {
		cert, err = parseCertifiedKeyPair(fields[2].Bytes)
		if err != nil {
			return 0, nil, "", err
		}
	}
	return status, cert, text, nil
}

// parseCertifiedKeyPair extracts the certificate from a CertifiedKeyPair.
func parseCertifiedKeyPair(content []byte) (*x509.Certificate, error) {
	fields, err := walkSequence(content)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty CertifiedKeyPair")
	}
	// certOrEncCert: certificate [0] CMPCertificate (explicit around Certificate).
	cofe := fields[0]
	if cofe.Class != asn1.ClassContextSpecific || cofe.Tag != 0 {
		return nil, fmt.Errorf("unexpected certOrEncCert form")
	}
	return x509.ParseCertificate(cofe.Bytes)
}

func parseRevRepContent(bodyContent []byte) (int, string, error) {
	fields, err := seqElements(bodyContent)
	if err != nil {
		return 0, "", err
	}
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("empty RevRepContent")
	}
	statuses, err := walkSequence(fields[0].Bytes)
	if err != nil {
		return 0, "", err
	}
	if len(statuses) == 0 {
		return 0, "", fmt.Errorf("RevRepContent has no status")
	}
	return parsePKIStatusInfo(statuses[0].FullBytes)
}

func parseErrorContent(bodyContent []byte) (int, string, error) {
	fields, err := seqElements(bodyContent)
	if err != nil {
		return 0, "", err
	}
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("empty ErrorMsgContent")
	}
	return parsePKIStatusInfo(fields[0].FullBytes)
}

// parsePKIStatusInfo decodes a PKIStatusInfo, returning the status and the first
// status-string line (if any).
func parsePKIStatusInfo(fullDER []byte) (int, string, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(fullDER, &raw); err != nil {
		return 0, "", err
	}
	fields, err := walkSequence(raw.Bytes)
	if err != nil {
		return 0, "", err
	}
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("empty PKIStatusInfo")
	}
	var status int
	if _, err := asn1.Unmarshal(fields[0].FullBytes, &status); err != nil {
		return 0, "", err
	}
	text := ""
	for _, f := range fields[1:] {
		if f.Class == asn1.ClassUniversal && f.Tag == asn1.TagSequence {
			lines, err := walkSequence(f.Bytes)
			if err == nil && len(lines) > 0 {
				text = string(lines[0].Bytes)
			}
			break
		}
	}
	return status, text, nil
}

// revIssuerName returns the issuer name to place in a revocation template. The
// certificate's RawIssuer is authoritative; fall back to the parsed Issuer.
func revIssuerName(cert *x509.Certificate) pkix.Name {
	return cert.Issuer
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// clientPBM returns PBM parameters for a client-originated MAC-protected request.
func clientPBM() (pbmParameter, error) {
	return defaultPBM()
}
