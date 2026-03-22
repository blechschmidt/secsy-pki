package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// X509KeyUsageFromString converts a string key usage to the x509 constant.
var X509KeyUsageFromString = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"certSign":          x509.KeyUsageCertSign,
	"crlSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

// X509ExtKeyUsageFromString converts a string ext key usage to the x509 constant.
var X509ExtKeyUsageFromString = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
	"ocspSigning":     x509.ExtKeyUsageOCSPSigning,
}

// SignX509Certificate signs a CSR with the CA's private key via PKCS#11.
// All certificate parameters (subject, SANs, extensions) are taken from the CSR.
func SignX509Certificate(signer crypto.Signer, csrPEM []byte, validBefore time.Time) ([]byte, string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", fmt.Errorf("invalid PEM: expected CERTIFICATE REQUEST")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("CSR signature verification failed: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              validBefore,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		ExtraExtensions:       csr.Extensions,
	}

	// Create CA certificate template for the issuer
	caPub := signer.Public()
	if caPub == nil {
		return nil, "", fmt.Errorf("CA public key not available")
	}

	issuer := &x509.Certificate{
		PublicKey: caPub,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, csr.PublicKey, signer)
	if err != nil {
		return nil, "", fmt.Errorf("signing certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return certPEM, serial.String(), nil
}

// ParseSANs extracts DNS names, IPs, and emails from a comma-separated list.
func ParseSANs(sans string) (dnsNames []string, ips []net.IP, emails []string) {
	for _, san := range strings.Split(sans, ",") {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else if strings.Contains(san, "@") {
			emails = append(emails, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	return
}

// FormatSubject creates a pkix.Name from key=value pairs.
func FormatSubject(fields map[string]string) pkix.Name {
	name := pkix.Name{}
	for k, v := range fields {
		switch strings.ToUpper(k) {
		case "CN":
			name.CommonName = v
		case "O":
			name.Organization = []string{v}
		case "OU":
			name.OrganizationalUnit = []string{v}
		case "C":
			name.Country = []string{v}
		case "ST":
			name.Province = []string{v}
		case "L":
			name.Locality = []string{v}
		}
	}
	return name
}
