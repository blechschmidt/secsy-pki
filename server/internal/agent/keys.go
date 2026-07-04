package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
)

// keyGenerator mints a fresh private key of the configured type.
type keyGenerator func() (crypto.Signer, error)

// parseKeyType maps a CertSpec.KeyType string to a generator. The names are
// the client-side conventions (certbot/lego style) rather than the server's
// PKCS#11 mechanism names, since these keys live on the host.
func parseKeyType(name string) (keyGenerator, error) {
	switch name {
	case "ecdsa-p256":
		return func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }, nil
	case "ecdsa-p384":
		return func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }, nil
	case "rsa-2048":
		return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }, nil
	case "rsa-3072":
		return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }, nil
	case "rsa-4096":
		return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 4096) }, nil
	default:
		return nil, fmt.Errorf("unsupported key_type %q (want ecdsa-p256, ecdsa-p384, rsa-2048, rsa-3072, or rsa-4096)", name)
	}
}

// autoKeyType is the sentinel key_type that defers the choice to the EST server's
// /csrattrs advertisement, falling back to defaultKeyType.
const autoKeyType = "auto"

// isAutoKeyType reports whether a spec defers its key type to the server's
// /csrattrs advertisement (or, absent one, the default).
func isAutoKeyType(keyType string) bool {
	return keyType == "" || keyType == autoKeyType
}

// resolveKeyType collapses the unset/"auto" sentinel to the concrete default.
func resolveKeyType(keyType string) string {
	return chooseKeyType(keyType, "")
}

// chooseKeyType decides the key type to generate. An explicit spec type is
// authoritative; the unset/"auto" sentinel adopts the server-advertised hint (an
// EST /csrattrs key-type advertisement) and, absent one, the default.
func chooseKeyType(specKeyType, hint string) string {
	if !isAutoKeyType(specKeyType) {
		return specKeyType
	}
	if hint != "" {
		return hint
	}
	return defaultKeyType
}

// generateKey creates the spec's private key locally. It never leaves the
// host: enrollment sends only a CSR.
func generateKey(spec *CertSpec) (crypto.Signer, error) {
	return generateKeyOfType(resolveKeyType(spec.KeyType))
}

// generateKeyOfType mints a fresh private key of the named type. It is used when
// the effective key type is resolved dynamically (e.g. honoring an EST
// /csrattrs key-type hint) rather than taken verbatim from the spec.
func generateKeyOfType(keyType string) (crypto.Signer, error) {
	gen, err := parseKeyType(keyType)
	if err != nil {
		return nil, err
	}
	key, err := gen()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", keyType, err)
	}
	return key, nil
}

// buildCSR creates a PKCS#10 request carrying the spec's subject and SANs, plus
// any extra extensions (e.g. an extended key usage advertised by the EST server
// at /csrattrs), signed by key.
func buildCSR(spec *CertSpec, key crypto.Signer, extraExts ...pkix.Extension) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: spec.CommonName},
		DNSNames:        append([]string(nil), spec.DNSNames...),
		ExtraExtensions: extraExts,
	}
	for _, raw := range spec.IPAddresses {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip address %q", raw)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	return der, nil
}

// encodeKeyPEM serializes a private key as PKCS#8 PEM.
func encodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parseKeyPEM loads a PKCS#8 (or legacy EC/RSA) PEM private key.
func parseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key file holds a %T, which cannot sign", key)
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("key file is not a parseable private key")
}

// encodeCertPEM serializes one certificate as PEM.
func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// encodeChainPEM serializes certificates as concatenated PEM.
func encodeChainPEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, encodeCertPEM(c.Raw)...)
	}
	return out
}

// parseCertsPEM parses every CERTIFICATE block in data.
func parseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

// publicKeysMatch reports whether the certificate was issued for key.
func publicKeysMatch(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := cert.PublicKey.(equaler)
	if !ok {
		return false
	}
	return pub.Equal(key.Public())
}
