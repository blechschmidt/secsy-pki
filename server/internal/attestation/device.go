package attestation

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
)

// Vendor-specific object identifiers used to recognize and describe attestation
// certificates.
var (
	// YubiKey PIV attestation extensions (Yubico private arc 1.3.6.1.4.1.41482.3).
	oidYubicoFirmware   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidYubicoSerial     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidYubicoPinTouch   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	oidYubicoFormfactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}

	// TPM subject-alternative-name directoryName attributes (TCG, 2.23.133.2.x)
	// carried on EK/platform certificates.
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}

	// oidTCGKpAIKCertificate is the TCG "id-tcg-kp-AIKCertificate" extended key
	// usage marking a TPM attestation identity key certificate.
	oidTCGKpAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

	// oidAttestationBundle is a secsy-pki private extension OID (under the
	// project's reserved experimental arc) used to carry an attestation
	// certificate chain inside a PKCS#10 CSR as a certs-only CMS. Clients that
	// cannot attest natively over EST/SCEP bundle their hardware attestation
	// certificate (and its manufacturer intermediate) under this OID.
	oidAttestationBundle = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58270, 1, 1}
)

// describeAttestationCert classifies an attestation leaf certificate and
// populates the vendor-specific fields of a Result (format, manufacturer,
// serial). It never fails: an unrecognized-but-trusted attestation cert is
// still valid, just labeled generically.
func describeAttestationCert(cert *x509.Certificate, res *Result) {
	switch {
	case hasExtension(cert, oidYubicoFirmware) || hasExtension(cert, oidYubicoPinTouch):
		res.Format = FormatYubiKeyPIV
		res.Manufacturer = "YubiKey"
		if s := yubicoSerial(cert); s != "" {
			res.Serial = s
		}
		if fw := yubicoFirmware(cert); fw != "" {
			res.Reason = strings.TrimSpace(res.Reason + " firmware=" + fw)
		}
	case hasEKU(cert, oidTCGKpAIKCertificate) || hasExtensionSAN(cert, oidTPMManufacturer):
		res.Format = FormatTPM
		if m := tpmManufacturer(cert); m != "" {
			res.Manufacturer = "TPM:" + m
		} else {
			res.Manufacturer = "TPM"
		}
	default:
		if res.Format == "" {
			res.Format = FormatCertChain
		}
		if res.Manufacturer == "" {
			res.Manufacturer = strings.TrimSpace(cert.Issuer.CommonName)
		}
	}
}

func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func extensionValue(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

func hasEKU(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, u := range cert.UnknownExtKeyUsage {
		if u.Equal(oid) {
			return true
		}
	}
	return false
}

// hasExtensionSAN reports whether the certificate's SAN extension carries a
// directoryName relative distinguished name using the given attribute OID —
// used to detect TPM EK certificates, which place the TPM vendor/model/version
// in a directoryName SAN.
func hasExtensionSAN(cert *x509.Certificate, attr asn1.ObjectIdentifier) bool {
	return tpmSANAttr(cert, attr) != ""
}

// yubicoSerial decodes the YubiKey device serial (an INTEGER) from the PIV
// attestation serial extension.
func yubicoSerial(cert *x509.Certificate) string {
	raw, ok := extensionValue(cert, oidYubicoSerial)
	if !ok {
		return ""
	}
	var serial int64
	if _, err := asn1.Unmarshal(raw, &serial); err != nil {
		// Some firmware encodes it as a big INTEGER; fall back.
		var bi big.Int
		if _, err2 := asn1.Unmarshal(raw, &bi); err2 == nil {
			return bi.String()
		}
		return ""
	}
	return fmt.Sprintf("%d", serial)
}

// yubicoFirmware decodes the 3-byte firmware-version OCTET STRING (major, minor,
// patch) from the PIV attestation firmware extension.
func yubicoFirmware(cert *x509.Certificate) string {
	raw, ok := extensionValue(cert, oidYubicoFirmware)
	if !ok {
		return ""
	}
	// The extension value is an OCTET STRING wrapping 3 raw bytes.
	var v []byte
	if _, err := asn1.Unmarshal(raw, &v); err == nil && len(v) == 3 {
		return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
	}
	if len(raw) == 3 {
		return fmt.Sprintf("%d.%d.%d", raw[0], raw[1], raw[2])
	}
	return ""
}

// tpmManufacturer returns the TPM vendor id from an EK certificate's SAN
// directoryName (2.23.133.2.1), e.g. "id:53544D20" (STMicroelectronics).
func tpmManufacturer(cert *x509.Certificate) string {
	return tpmSANAttr(cert, oidTPMManufacturer)
}

// tpmSANAttr extracts a single directoryName attribute value from the SAN
// extension by OID. It performs a shallow, defensive parse of the SAN so a
// malformed extension never panics.
func tpmSANAttr(cert *x509.Certificate, attr asn1.ObjectIdentifier) string {
	raw, ok := extensionValue(cert, asn1.ObjectIdentifier{2, 5, 29, 17}) // subjectAltName
	if !ok {
		return ""
	}
	// SAN ::= SEQUENCE OF GeneralName. directoryName is [4] EXPLICIT Name.
	var general asn1.RawValue
	rest := raw
	for len(rest) > 0 {
		var err error
		rest, err = asn1.Unmarshal(rest, &general)
		if err != nil {
			return ""
		}
		if general.Class == asn1.ClassContextSpecific && general.Tag == 4 {
			if val := parseDirNameAttr(general.Bytes, attr); val != "" {
				return val
			}
		}
	}
	return ""
}

// parseDirNameAttr walks a directoryName (an RDNSequence) DER blob and returns
// the string value of the first attribute matching attr.
func parseDirNameAttr(der []byte, attr asn1.ObjectIdentifier) string {
	type attributeTypeAndValue struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	var rdnSeq []asn1.RawValue // SEQUENCE OF RelativeDistinguishedName (SET OF ATV)
	if _, err := asn1.Unmarshal(der, &rdnSeq); err != nil {
		// The [4] content is the Name directly (a SEQUENCE); try unwrapping once.
		var name asn1.RawValue
		if _, err2 := asn1.Unmarshal(der, &name); err2 != nil {
			return ""
		}
		if _, err2 := asn1.Unmarshal(name.FullBytes, &rdnSeq); err2 != nil {
			return ""
		}
	}
	for _, rdn := range rdnSeq {
		var atvs []attributeTypeAndValue
		if _, err := asn1.Unmarshal(rdn.FullBytes, &atvs); err != nil {
			continue
		}
		for _, atv := range atvs {
			if atv.Type.Equal(attr) {
				return strings.TrimSpace(string(atv.Value.Bytes))
			}
		}
	}
	return ""
}
