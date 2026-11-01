package pki

import (
	"crypto/x509"
	"sort"
	"strconv"
)

// Reverse name lookups for the key-usage bitmask and the extended-key-usage
// enum. X509KeyUsageFromString and X509ExtKeyUsageFromString map an operator's
// word onto crypto/x509's representation; these map it back, so a surface that
// has only the template — the CEL restriction engine (internal/celpolicy), a
// preview response, an audit detail — can name the usages the certificate would
// carry using exactly the vocabulary the profile was written in.
//
// The tables are derived from the forward maps rather than re-typed, so a usage
// added to one is immediately nameable by the other.

// keyUsageNames is the inverse of X509KeyUsageFromString. A key usage is a
// single bit, so the inverse is unambiguous.
var keyUsageNames = func() map[x509.KeyUsage]string {
	m := make(map[x509.KeyUsage]string, len(X509KeyUsageFromString))
	for name, bit := range X509KeyUsageFromString {
		m[bit] = name
	}
	return m
}()

// extKeyUsageNames is the inverse of X509ExtKeyUsageFromString.
var extKeyUsageNames = func() map[x509.ExtKeyUsage]string {
	m := make(map[x509.ExtKeyUsage]string, len(X509ExtKeyUsageFromString))
	for name, eku := range X509ExtKeyUsageFromString {
		m[eku] = name
	}
	return m
}()

// KeyUsageNames decomposes a key-usage bitmask into the usage names a profile
// lists, in a stable (sorted) order so a policy rule, an audit record and a
// preview never disagree about the order. A bit with no name — crypto/x509
// defines none beyond decipherOnly — is omitted rather than rendered as a
// number: the caller is naming usages, not dumping a bitmask.
func KeyUsageNames(ku x509.KeyUsage) []string {
	if ku == 0 {
		return nil
	}
	var out []string
	for bit, name := range keyUsageNames {
		if ku&bit != 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ExtKeyUsageNames names a set of extended key usages, preserving the order the
// profile assigned them (EKU order is meaningful to some relying parties, and
// the template's order is what the certificate will carry). An EKU outside the
// named set — crypto/x509 knows several this PKI's profiles never assign — is
// rendered as "eku(<n>)" so it is visible to a rule rather than silently
// dropped, which for a restriction engine would be the dangerous direction.
func ExtKeyUsageNames(ekus []x509.ExtKeyUsage) []string {
	if len(ekus) == 0 {
		return nil
	}
	out := make([]string, 0, len(ekus))
	for _, eku := range ekus {
		if name, ok := extKeyUsageNames[eku]; ok {
			out = append(out, name)
			continue
		}
		out = append(out, unnamedEKU(eku))
	}
	return out
}

// unnamedEKU renders an extended key usage this PKI's vocabulary does not name.
func unnamedEKU(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsecEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsecTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsecUser"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "microsoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "netscapeServerGatedCrypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "microsoftCommercialCodeSigning"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "microsoftKernelCodeSigning"
	}
	return "eku(" + strconv.Itoa(int(eku)) + ")"
}
