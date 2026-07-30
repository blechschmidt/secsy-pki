package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// resolveSearchFingerprint resolves a `--by-public-key` value to the canonical
// "SHA256:<base64>" SubjectPublicKeyInfo fingerprint stored in the certificate
// inventory, so a key-compromise search matches the recorded value. It is shared
// by `list-certs` and `revoke-bulk` (Task 154). The value is one of:
//
//   - a raw SPKI SHA-256 digest — hex (with or without the colon separators
//     openssl and browsers print) or the canonical "SHA256:<base64>" form; or
//   - "@path" (or "@-" for stdin): a PEM/DER certificate, PKCS#10 CSR, or bare
//     SubjectPublicKeyInfo public key, which is fingerprinted locally so an
//     operator holding only the leaked artifact need not compute the digest by
//     hand — the fingerprint is derived with the exact keycheck.Fingerprint the
//     inventory records at issuance.
func resolveSearchFingerprint(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("empty --by-public-key value")
	}
	if strings.HasPrefix(v, "@") {
		pub, err := publicKeyFromAnyFile(strings.TrimPrefix(v, "@"))
		if err != nil {
			return "", err
		}
		fp, err := keycheck.Fingerprint(pub)
		if err != nil {
			return "", fmt.Errorf("fingerprinting public key: %w", err)
		}
		return fp, nil
	}
	return keycheck.NormalizeFingerprint(v)
}

// publicKeyFromAnyFile reads a PEM or DER file (or stdin for "-") and extracts a
// public key, accepting a certificate, a PKCS#10 CSR, or a bare
// SubjectPublicKeyInfo — the forms an operator is likely to have on hand for a
// leaked key. It tries each parse in turn rather than requiring the operator to
// declare which one they hold.
func publicKeyFromAnyFile(path string) (crypto.PublicKey, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, fmt.Errorf("reading public-key file: %w", err)
	}
	// A certificate is the most common leaked artifact; try it first (PEM or DER).
	if cert, err := pki.ParseCertificatePEMOrDER(data); err == nil {
		return cert.PublicKey, nil
	}
	// Otherwise decode a single PEM block (if any) and try a CSR, then a raw SPKI.
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		return csr.PublicKey, nil
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return pub, nil
	}
	return nil, fmt.Errorf("%s: not a PEM/DER certificate, CSR, or SubjectPublicKeyInfo public key", path)
}
