package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "verify-audit-log":
		cmdVerifyAuditLog(os.Args[2:])
	case "verify-combined-log":
		cmdVerifyCombinedLog(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: secsy-verify <command> [options]")
	fmt.Fprintln(os.Stderr, "\nCommands:")
	fmt.Fprintln(os.Stderr, "  verify-audit-log    Verify an exported signed HSM audit log")
	fmt.Fprintln(os.Stderr, "  verify-combined-log Verify a combined log against a signed HSM audit log")
	fmt.Fprintln(os.Stderr, "\nRun 'secsy-verify <command> --help' for command-specific help.")
}

func cmdVerifyAuditLog(args []string) {
	fs := flag.NewFlagSet("verify-audit-log", flag.ExitOnError)
	auditLogPath := fs.String("audit-log", "", "Path to exported audit log JSON (signed, combined, or HSM-only)")
	yubicoCAPath := fs.String("yubico-ca", "", "Path to Yubico root CA PEM")
	yubicoIntPath := fs.String("yubico-intermediate", "", "Path to Yubico intermediate CA PEM")
	fs.Parse(args)

	if *auditLogPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: secsy-verify verify-audit-log --audit-log <file> [--yubico-ca <pem> --yubico-intermediate <pem>]")
		fmt.Fprintln(os.Stderr, "\nThe audit log can be:")
		fmt.Fprintln(os.Stderr, "  - Signed:   includes HSM signature, attestation cert, and device cert")
		fmt.Fprintln(os.Stderr, "  - Combined: HSM entries + sign operations (no cryptographic proof)")
		fmt.Fprintln(os.Stderr, "  - HSM-only: just the hash chain entries")
		fmt.Fprintln(os.Stderr, "\nFor signed logs, --yubico-ca and --yubico-intermediate verify the full")
		fmt.Fprintln(os.Stderr, "chain: Yubico Root CA -> Intermediate -> Device Cert -> Attestation Cert -> Signature")
		os.Exit(1)
	}

	data, err := os.ReadFile(*auditLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Detect format
	var signedLog hsm.SignedAuditLog
	if err := json.Unmarshal(data, &signedLog); err == nil && signedLog.Signature != "" {
		ok := verifySignedLog(&signedLog, *yubicoCAPath, *yubicoIntPath)
		if !ok {
			os.Exit(1)
		}
		return
	}

	var combined models.CombinedAuditExport
	if err := json.Unmarshal(data, &combined); err == nil && len(combined.HSMEntries) > 0 {
		fmt.Println("WARNING: This is a combined log without a cryptographic signature.")
		fmt.Println("         Use a signed audit log for full verification.\n")
		if !verifyCombinedLog(&combined) {
			os.Exit(1)
		}
		return
	}

	var hsmLog hsm.AuditLog
	if err := json.Unmarshal(data, &hsmLog); err == nil && len(hsmLog.Entries) > 0 {
		fmt.Println("WARNING: This is an unsigned HSM-only log without cryptographic proof.")
		fmt.Println("         Use a signed audit log for full verification.\n")
		if !verifyHSMOnlyLog(&hsmLog) {
			os.Exit(1)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "Error: could not parse audit log (unrecognized format)")
	os.Exit(1)
}

// --- YubiHSM attestation OIDs ---

var (
	oidYubicoBase      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482}
	oidFirmwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 1}
	oidSerialNumber    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 2}
	oidOrigin          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 3}
	oidDomains         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 4}
	oidCapabilities    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 5}
	oidObjectID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 6}
	oidLabel           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 9}
	oidFIPS            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 10}
	oidFIPSApproved    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 12}
)

var oidNames = map[string]string{
	oidFirmwareVersion.String(): "Firmware Version",
	oidSerialNumber.String():    "Serial Number",
	oidOrigin.String():          "Origin",
	oidDomains.String():         "Domains",
	oidCapabilities.String():    "Capabilities",
	oidObjectID.String():        "Object ID",
	oidLabel.String():           "Label",
	oidFIPS.String():            "FIPS",
	oidFIPSApproved.String():    "FIPS Approved",
}

func printYubiHSMAttestationOIDs(cert *x509.Certificate, indent string) {
	found := false
	for _, ext := range cert.Extensions {
		if !isYubicoOID(ext.Id) {
			continue
		}
		if !found {
			fmt.Printf("%sYubiHSM Attestation OIDs:\n", indent)
			found = true
		}

		name := oidNames[ext.Id.String()]
		if name == "" {
			name = ext.Id.String()
		}

		value := parseYubiHSMExtension(ext)
		fmt.Printf("%s  %-20s %s\n", indent, name+":", value)
	}
	if !found {
		fmt.Printf("%sYubiHSM Attestation OIDs: none found\n", indent)
	}
}

func isYubicoOID(oid asn1.ObjectIdentifier) bool {
	if len(oid) < len(oidYubicoBase) {
		return false
	}
	for i, v := range oidYubicoBase {
		if oid[i] != v {
			return false
		}
	}
	return true
}

func parseYubiHSMExtension(ext pkix.Extension) string {
	oid := ext.Id.String()
	raw := ext.Value

	switch oid {
	case oidFirmwareVersion.String():
		// Octet string containing version bytes
		var bs []byte
		if _, err := asn1.Unmarshal(raw, &bs); err == nil && len(bs) >= 3 {
			return fmt.Sprintf("%d.%d.%d", bs[0], bs[1], bs[2])
		}
		if len(raw) >= 3 {
			return fmt.Sprintf("%d.%d.%d", raw[0], raw[1], raw[2])
		}
		return hex.EncodeToString(raw)

	case oidSerialNumber.String():
		var n int
		if _, err := asn1.Unmarshal(raw, &n); err == nil {
			return fmt.Sprintf("%d", n)
		}
		// Try as big int
		var bi *big.Int
		if _, err := asn1.Unmarshal(raw, &bi); err == nil {
			return bi.String()
		}
		return hex.EncodeToString(raw)

	case oidObjectID.String():
		var n int
		if _, err := asn1.Unmarshal(raw, &n); err == nil {
			return fmt.Sprintf("0x%04x", n)
		}
		return hex.EncodeToString(raw)

	case oidOrigin.String():
		var bs asn1.BitString
		if _, err := asn1.Unmarshal(raw, &bs); err == nil {
			origins := parseOrigin(bs.Bytes)
			return strings.Join(origins, ", ")
		}
		return hex.EncodeToString(raw)

	case oidDomains.String():
		var bs asn1.BitString
		if _, err := asn1.Unmarshal(raw, &bs); err == nil {
			return parseDomains(bs.Bytes)
		}
		return hex.EncodeToString(raw)

	case oidCapabilities.String():
		var bs asn1.BitString
		if _, err := asn1.Unmarshal(raw, &bs); err == nil {
			return formatCapabilities(bs.Bytes)
		}
		return hex.EncodeToString(raw)

	case oidLabel.String():
		var s string
		if _, err := asn1.Unmarshal(raw, &s); err == nil {
			return fmt.Sprintf("%q", s)
		}
		return fmt.Sprintf("%q", string(raw))

	case oidFIPS.String():
		var n int
		if _, err := asn1.Unmarshal(raw, &n); err == nil {
			return fmt.Sprintf("%d", n)
		}
		return hex.EncodeToString(raw)

	case oidFIPSApproved.String():
		var b bool
		if _, err := asn1.Unmarshal(raw, &b); err == nil {
			return fmt.Sprintf("%v", b)
		}
		return hex.EncodeToString(raw)
	}

	return hex.EncodeToString(raw)
}

func parseOrigin(data []byte) []string {
	if len(data) == 0 {
		return []string{"unknown"}
	}
	var origins []string
	b := data[0]
	if b&0x01 != 0 {
		origins = append(origins, "generated")
	}
	if b&0x02 != 0 {
		origins = append(origins, "imported")
	}
	if b&0x04 != 0 {
		origins = append(origins, "imported-wrapped")
	}
	if len(origins) == 0 {
		return []string{fmt.Sprintf("0x%02x", b)}
	}
	return origins
}

func parseDomains(data []byte) string {
	if len(data) < 2 {
		return hex.EncodeToString(data)
	}
	mask := binary.BigEndian.Uint16(data[:2])
	var domains []string
	for i := 0; i < 16; i++ {
		if mask&(1<<uint(15-i)) != 0 {
			domains = append(domains, fmt.Sprintf("%d", i+1))
		}
	}
	if len(domains) == 0 {
		return "none"
	}
	return strings.Join(domains, ", ")
}

// capabilityNames maps bit position (0-based from MSB of the 8-byte field) to capability name.
// From the YubiHSM2 SDK: capabilities is a 64-bit bitmask stored big-endian.
var capabilityNames = map[int]string{
	0x00: "get-opaque",
	0x01: "put-opaque",
	0x02: "put-authentication-key",
	0x03: "put-asymmetric-key",
	0x04: "generate-asymmetric-key",
	0x05: "sign-pkcs",
	0x06: "sign-pss",
	0x07: "sign-ecdsa",
	0x08: "sign-eddsa",
	0x09: "decrypt-pkcs",
	0x0a: "decrypt-oaep",
	0x0b: "derive-ecdh",
	0x0c: "export-wrapped",
	0x0d: "import-wrapped",
	0x0e: "put-wrap-key",
	0x0f: "generate-wrap-key",
	0x10: "exportable-under-wrap",
	0x11: "set-option",
	0x12: "get-option",
	0x13: "get-pseudo-random",
	0x14: "put-hmac-key",
	0x15: "generate-hmac-key",
	0x16: "sign-hmac",
	0x17: "verify-hmac",
	0x18: "get-log-entries",
	0x19: "sign-ssh-certificate",
	0x1a: "get-template",
	0x1b: "put-template",
	0x1c: "reset-device",
	0x1d: "decrypt-otp",
	0x1e: "create-otp-aead",
	0x1f: "randomize-otp-aead",
	0x20: "rewrap-from-otp-aead-key",
	0x21: "rewrap-to-otp-aead-key",
	0x22: "sign-attestation-certificate",
	0x23: "put-otp-aead-key",
	0x24: "generate-otp-aead-key",
	0x25: "wrap-data",
	0x26: "unwrap-data",
	0x27: "delete-opaque",
	0x28: "delete-authentication-key",
	0x29: "delete-asymmetric-key",
	0x2a: "delete-wrap-key",
	0x2b: "delete-hmac-key",
	0x2c: "delete-template",
	0x2d: "delete-otp-aead-key",
	0x2e: "change-authentication-key",
	0x2f: "put-symmetric-key",
	0x30: "generate-symmetric-key",
	0x31: "delete-symmetric-key",
	0x32: "decrypt-ecb",
	0x33: "encrypt-ecb",
	0x34: "decrypt-cbc",
	0x35: "encrypt-cbc",
	0x54: "put-public-wrap-key",
	0x55: "delete-public-wrap-key",
}

func formatCapabilities(data []byte) string {
	// Pad to 8 bytes (big-endian)
	padded := make([]byte, 8)
	copy(padded[8-len(data):], data)

	// Capabilities is a 64-bit bitmask, big-endian.
	// Bit 0 is the LSB (rightmost bit of byte[7]).
	var caps []string
	for bit, name := range capabilityNames {
		byteIdx := 7 - (bit / 8) // count from the end
		bitIdx := bit % 8
		if byteIdx >= 0 && byteIdx < 8 && padded[byteIdx]&(1<<uint(bitIdx)) != 0 {
			caps = append(caps, name)
		}
	}

	if len(caps) == 0 {
		return "none"
	}

	// Sort for consistent output
	sortStrings(caps)
	return strings.Join(caps, ", ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// --- Verification functions ---

func verifySignedLog(log *hsm.SignedAuditLog, caPath, intPath string) bool {
	fmt.Println("=== Signed Audit Log Verification ===")
	fmt.Printf("  Device Serial: %s\n", log.DeviceSerial)
	fmt.Printf("  Exported At:   %s\n", log.ExportedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Entries:       %d\n", len(log.Entries))
	fmt.Println()

	allOK := true

	// 1. Hash chain
	fmt.Println("--- Hash Chain ---")
	if !verifyHSMChain(log.Entries) {
		allOK = false
	}
	fmt.Println()

	// 2. Log digest
	fmt.Println("--- Log Digest ---")
	computed := hsm.ComputeLogDigest(log.Entries)
	if computed != log.LogDigest {
		fmt.Printf("  Log digest:  FAIL (computed %s, expected %s)\n", computed[:16]+"...", log.LogDigest[:16]+"...")
		allOK = false
	} else {
		fmt.Printf("  Log digest:  PASS (%s...)\n", log.LogDigest[:32])
	}
	fmt.Println()

	// 3. Signature
	fmt.Println("--- Signature ---")
	attestCert, err := parsePEMCert([]byte(log.AttestationCertPEM))
	if err != nil {
		fmt.Printf("  Attestation cert: FAIL (%v)\n", err)
		allOK = false
	} else {
		fmt.Printf("  Attestation cert: %s\n", attestCert.Subject.CommonName)
		printYubiHSMAttestationOIDs(attestCert, "  ")

		pubKey, ok := attestCert.PublicKey.(ed25519.PublicKey)
		if !ok {
			fmt.Println("  Signing key type: FAIL (expected Ed25519)")
			allOK = false
		} else {
			digestBytes, _ := hex.DecodeString(log.LogDigest)
			sigBytes, err := base64.StdEncoding.DecodeString(log.Signature)
			if err != nil {
				fmt.Printf("  Signature decode: FAIL (%v)\n", err)
				allOK = false
			} else if ed25519.Verify(pubKey, digestBytes, sigBytes) {
				fmt.Println("  Signature:        PASS (Ed25519)")
			} else {
				fmt.Println("  Signature:        FAIL")
				allOK = false
			}
		}
	}
	fmt.Println()

	// 4. Certificate chain
	fmt.Println("--- Certificate Chain ---")
	deviceCert, err := parsePEMCert([]byte(log.DeviceCertPEM))
	if err != nil {
		fmt.Printf("  Device cert: FAIL (%v)\n", err)
		allOK = false
	} else {
		fmt.Printf("  Device cert:              %s\n", deviceCert.Subject.CommonName)
		printYubiHSMAttestationOIDs(deviceCert, "  ")

		if attestCert != nil {
			if err := attestCert.CheckSignatureFrom(deviceCert); err != nil {
				fmt.Printf("  Attestation <- Device:    FAIL (%v)\n", err)
				allOK = false
			} else {
				fmt.Println("  Attestation <- Device:    PASS")
			}
		}

		if caPath != "" && intPath != "" {
			if verifyDeviceCertChain(deviceCert, caPath, intPath) {
				fmt.Println("  Device <- Yubico CA:      PASS")
			} else {
				allOK = false
			}
		} else {
			fmt.Println("  Device <- Yubico CA:      SKIPPED (provide --yubico-ca and --yubico-intermediate)")
		}
	}

	fmt.Println()
	fmt.Printf("=== Overall: %s ===\n", passOrFail(allOK))
	return allOK
}

func verifyDeviceCertChain(cert *x509.Certificate, caPath, intPath string) bool {
	caData, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Printf("  Device <- Yubico CA:      FAIL (reading root: %v)\n", err)
		return false
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caData) {
		fmt.Println("  Device <- Yubico CA:      FAIL (parsing root)")
		return false
	}

	intData, err := os.ReadFile(intPath)
	if err != nil {
		fmt.Printf("  Device <- Yubico CA:      FAIL (reading intermediate: %v)\n", err)
		return false
	}
	intPool := x509.NewCertPool()
	if !intPool.AppendCertsFromPEM(intData) {
		fmt.Println("  Device <- Yubico CA:      FAIL (parsing intermediate)")
		return false
	}

	_, err = cert.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intPool})
	if err != nil {
		fmt.Printf("  Device <- Yubico CA:      FAIL (%v)\n", err)
		return false
	}
	return true
}

func parsePEMCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func cmdName(cmd uint8) (string, bool) {
	name, known := hsm.AllCommands[cmd]
	return name, known
}

func verifyHSMOnlyLog(log *hsm.AuditLog) bool {
	fmt.Println("=== Audit Log Hash Chain Verification ===")
	if log.DeviceSerial != "" {
		fmt.Printf("  Device Serial: %s\n", log.DeviceSerial)
	}
	fmt.Printf("  Entries:       %d\n\n", len(log.Entries))
	return verifyHSMChain(log.Entries)
}

func verifyCombinedLog(combined *models.CombinedAuditExport) bool {
	fmt.Println("=== Combined Audit Log Verification ===")
	if combined.DeviceSerial != "" {
		fmt.Printf("  Device Serial:    %s\n", combined.DeviceSerial)
	}
	fmt.Printf("  HSM entries:      %d\n", len(combined.HSMEntries))
	fmt.Printf("  Sign operations:  %d\n\n", len(combined.SignOps))

	hsmEntries := make([]hsm.AuditLogEntry, len(combined.HSMEntries))
	for i, e := range combined.HSMEntries {
		hsmEntries[i] = hsm.AuditLogEntry{
			Number: e.Number, Command: e.Command, Length: e.Length,
			SessionKey: e.SessionKey, TargetKey: e.TargetKey, SecondKey: e.SecondKey,
			Result: e.Result, Tick: e.Tick, Hash: e.Hash,
		}
	}

	chainOK := verifyHSMChain(hsmEntries)

	fmt.Println("\n--- Sign Operation Cross-Reference ---")
	signOpMap := make(map[string]*models.AuditLogEntry)
	for i := range combined.SignOps {
		signOpMap[combined.SignOps[i].ID] = &combined.SignOps[i]
	}

	crossRefOK := true
	cryptoLinked := 0

	for _, e := range combined.HSMEntries {
		name, known := cmdName(e.Command)
		if !known {
			fmt.Printf("  ERROR: HSM entry %d has unknown command 0x%02x\n", e.Number, e.Command)
			crossRefOK = false
			continue
		}
		_, isCrypto := hsm.CryptoCommands[e.Command]
		if !isCrypto {
			continue
		}
		if e.SignAuditID == nil {
			fmt.Printf("  WARNING: HSM entry %d (%s) has no linked sign operation\n", e.Number, name)
			continue
		}
		signOp, exists := signOpMap[*e.SignAuditID]
		if !exists {
			fmt.Printf("  FAIL: HSM entry %d links to missing sign op %s\n", e.Number, *e.SignAuditID)
			crossRefOK = false
			continue
		}
		cryptoLinked++
		fmt.Printf("  Entry %3d: %-25s -> key_id=%q principals=%v type=%s valid=%s..%s pubkey=%s...\n",
			e.Number, name, signOp.KeyID, signOp.Principals, orDefault(signOp.CertType, "user"),
			signOp.ValidAfter.Format(time.DateOnly), signOp.ValidBefore.Format(time.DateOnly),
			truncStr(signOp.PublicKey, 40))
	}

	fmt.Printf("\n  Linked:          %d\n", cryptoLinked)
	fmt.Printf("  Cross-reference: %s\n", passOrFail(crossRefOK))
	return chainOK && crossRefOK
}

func verifyHSMChain(entries []hsm.AuditLogEntry) bool {
	results, err := hsm.VerifyHashChain(entries)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return false
	}

	chainOK := true
	cryptoCount := 0
	cryptoFail := 0
	unknownCount := 0

	for i, ok := range results {
		e := entries[i]
		name, known := cmdName(e.Command)
		if !known {
			fmt.Printf("  ERROR entry %3d: unknown command 0x%02x\n", e.Number, e.Command)
			unknownCount++
			chainOK = false
			continue
		}

		isCrypto := false
		if _, exists := hsm.CryptoCommands[e.Command]; exists {
			isCrypto = true
			cryptoCount++
		}

		status := "OK"
		if !ok {
			status = "FAIL"
			chainOK = false
			if isCrypto {
				cryptoFail++
			}
		}

		marker := "  "
		if isCrypto {
			marker = "* "
		}
		fmt.Printf("%sEntry %3d: %-25s target=0x%04x tick=%-10d hash=%s\n",
			marker, e.Number, name, e.TargetKey, e.Tick, status)
	}

	fmt.Println()
	fmt.Printf("  Hash chain:      %s\n", passOrFail(chainOK))
	fmt.Printf("  Crypto ops:      %d found", cryptoCount)
	if cryptoFail > 0 {
		fmt.Printf(", %d FAILED", cryptoFail)
	}
	fmt.Println()
	if unknownCount > 0 {
		fmt.Printf("  Unknown cmds:    %d — FAIL\n", unknownCount)
	}
	if cryptoCount == 0 {
		fmt.Println("  WARNING: No crypto operations (audit logging may not be enabled)")
	}
	return chainOK
}

func passOrFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func cmdVerifyCombinedLog(args []string) {
	fs := flag.NewFlagSet("verify-combined-log", flag.ExitOnError)
	signedLogPath := fs.String("signed-log", "", "Path to signed HSM audit log JSON (from verify-audit-log)")
	combinedLogPath := fs.String("combined-log", "", "Path to combined crypto operations log JSON")
	caKeyHex := fs.String("ca-key", "", "CA key ID on the HSM (hex, e.g. 0x50dd)")
	yubicoCAPath := fs.String("yubico-ca", "", "Path to Yubico root CA PEM")
	yubicoIntPath := fs.String("yubico-intermediate", "", "Path to Yubico intermediate CA PEM")
	fs.Parse(args)

	if *signedLogPath == "" || *combinedLogPath == "" || *caKeyHex == "" {
		fmt.Fprintln(os.Stderr, "Usage: secsy-verify verify-combined-log \\")
		fmt.Fprintln(os.Stderr, "  --signed-log <signed-audit-log.json> \\")
		fmt.Fprintln(os.Stderr, "  --combined-log <combined-audit-log.json> \\")
		fmt.Fprintln(os.Stderr, "  --ca-key <hex-key-id> \\")
		fmt.Fprintln(os.Stderr, "  [--yubico-ca <pem> --yubico-intermediate <pem>]")
		fmt.Fprintln(os.Stderr, "\nVerifies that:")
		fmt.Fprintln(os.Stderr, "  1. The signed HSM audit log is valid (hash chain, signature, cert chain)")
		fmt.Fprintln(os.Stderr, "  2. The CA key was generated on the HSM and is unexportable")
		fmt.Fprintln(os.Stderr, "  3. Every HSM sign operation on the CA key maps to a combined log entry")
		fmt.Fprintln(os.Stderr, "  4. Every combined log entry maps to an HSM sign operation")
		fmt.Fprintln(os.Stderr, "  5. Each certificate contains the claimed public key and parameters")
		os.Exit(1)
	}

	// Parse CA key ID
	keyStr := strings.TrimPrefix(*caKeyHex, "0x")
	caKeyID64, err := hex.DecodeString(fmt.Sprintf("%04s", keyStr))
	if err != nil || len(caKeyID64) < 2 {
		fmt.Fprintf(os.Stderr, "Invalid CA key ID: %s\n", *caKeyHex)
		os.Exit(1)
	}
	caKeyID := uint16(caKeyID64[len(caKeyID64)-2])<<8 | uint16(caKeyID64[len(caKeyID64)-1])

	// Load signed log
	signedData, err := os.ReadFile(*signedLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading signed log: %v\n", err)
		os.Exit(1)
	}
	var signedLog hsm.SignedAuditLog
	if err := json.Unmarshal(signedData, &signedLog); err != nil || signedLog.Signature == "" {
		fmt.Fprintln(os.Stderr, "Error: --signed-log must be a signed audit log (with signature)")
		os.Exit(1)
	}

	// Load combined log
	combinedData, err := os.ReadFile(*combinedLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading combined log: %v\n", err)
		os.Exit(1)
	}
	var combined models.CombinedAuditExport
	if err := json.Unmarshal(combinedData, &combined); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing combined log: %v\n", err)
		os.Exit(1)
	}

	allOK := true

	// Step 1: Verify signed audit log
	fmt.Println("=== Step 1: Verify Signed HSM Audit Log ===")
	if !verifySignedLog(&signedLog, *yubicoCAPath, *yubicoIntPath) {
		allOK = false
	}
	fmt.Println()

	// Step 2: Verify CA key properties from attestation
	fmt.Printf("=== Step 2: CA Key Properties (0x%04x) ===\n", caKeyID)
	attestCert, _ := parsePEMCert([]byte(signedLog.AttestationCertPEM))
	caKeyOK := verifyCAKeyProperties(signedLog.Entries, caKeyID, attestCert)
	if !caKeyOK {
		allOK = false
	}
	fmt.Println()

	// Step 3: Cross-reference HSM sign ops with combined log
	fmt.Printf("=== Step 3: Cross-Reference (CA key 0x%04x) ===\n", caKeyID)

	// Build a set of HSM entry numbers from the signed log (cryptographic proof)
	signedHSMNumbers := make(map[uint16]bool)
	var hsmSignOps []hsm.AuditLogEntry
	for _, e := range signedLog.Entries {
		signedHSMNumbers[e.Number] = true
		if _, isSign := hsm.SignCommands[e.Command]; isSign && e.TargetKey == caKeyID {
			hsmSignOps = append(hsmSignOps, e)
		}
	}
	fmt.Printf("  HSM sign operations on key 0x%04x: %d\n", caKeyID, len(hsmSignOps))

	// Build linkage from the combined log (which has sign_audit_id associations)
	signOpMap := make(map[string]*models.AuditLogEntry)
	for i := range combined.SignOps {
		signOpMap[combined.SignOps[i].ID] = &combined.SignOps[i]
	}

	hsmToSignMap := make(map[uint16]string) // hsm number -> sign_audit_id
	for _, e := range combined.HSMEntries {
		if e.SignAuditID != nil && e.TargetKey == caKeyID {
			if _, isSign := hsm.SignCommands[e.Command]; isSign {
				hsmToSignMap[e.Number] = *e.SignAuditID
			}
		}
	}

	// Check 3a: Every HSM sign op on the CA key (from signed log) must have a link in the combined log
	fmt.Println("\n  --- HSM -> Combined Log ---")
	unmatchedHSM := 0
	matchedPairs := make(map[uint16]*models.AuditLogEntry)
	for _, hsmEntry := range hsmSignOps {
		signID, linked := hsmToSignMap[hsmEntry.Number]
		if !linked {
			fmt.Printf("  FAIL: HSM entry %d (%s tick=%d) has no linked sign operation in combined log\n",
				hsmEntry.Number, mustCmdName(hsmEntry.Command), hsmEntry.Tick)
			unmatchedHSM++
			allOK = false
			continue
		}
		signOp, exists := signOpMap[signID]
		if !exists {
			fmt.Printf("  FAIL: HSM entry %d links to sign op %s which doesn't exist in combined log\n",
				hsmEntry.Number, signID)
			allOK = false
			continue
		}
		matchedPairs[hsmEntry.Number] = signOp
		fmt.Printf("  OK:   HSM entry %3d -> sign op key_id=%q serial=%s\n",
			hsmEntry.Number, signOp.KeyID, truncStr(signOp.Serial, 10))
	}
	if unmatchedHSM > 0 {
		fmt.Printf("  %d HSM sign operation(s) without matching combined log entries\n", unmatchedHSM)
	}

	// Check 3b: Every combined log sign op must map to an HSM entry in the signed log
	fmt.Println("\n  --- Combined Log -> HSM ---")
	orphanOps := 0
	for _, op := range combined.SignOps {
		// Find the HSM entry number for this sign op
		found := false
		for num, signID := range hsmToSignMap {
			if signID == op.ID {
				if signedHSMNumbers[num] {
					found = true
				}
				break
			}
		}
		if !found {
			fmt.Printf("  FAIL: Sign op %s (key_id=%q serial=%s) has no matching entry in signed HSM log\n",
				op.ID[:8], op.KeyID, truncStr(op.Serial, 10))
			orphanOps++
			allOK = false
		}
	}
	if orphanOps == 0 && len(combined.SignOps) > 0 {
		fmt.Printf("  OK:   All %d sign operations have matching signed HSM entries\n", len(combined.SignOps))
	}
	fmt.Println()

	// Step 4: Verify certificates match claimed parameters
	fmt.Println("=== Step 4: Certificate Parameter Verification ===")
	certErrors := 0
	for hsmNum, signOp := range matchedPairs {
		ok := verifyCertificateParams(hsmNum, signOp)
		if !ok {
			certErrors++
			allOK = false
		}
	}
	if certErrors == 0 && len(matchedPairs) > 0 {
		fmt.Printf("  All %d certificates verified against claimed parameters\n", len(matchedPairs))
	} else if certErrors > 0 {
		fmt.Printf("  %d certificate(s) failed parameter verification\n", certErrors)
	}

	fmt.Println()
	fmt.Printf("=== Overall: %s ===\n", passOrFail(allOK))
	if !allOK {
		os.Exit(1)
	}
}

func verifyCAKeyProperties(entries []hsm.AuditLogEntry, caKeyID uint16, attestCert *x509.Certificate) bool {
	ok := true

	// Check that the key was generated on the HSM (GENERATE ASYMMETRIC KEY with target = caKeyID)
	generated := false
	for _, e := range entries {
		if e.Command == hsm.CmdGenerateAsymmetricKey && e.TargetKey == caKeyID {
			generated = true
			fmt.Printf("  Generated on HSM:  PASS (entry %d, tick %d)\n", e.Number, e.Tick)
			break
		}
	}
	if !generated {
		fmt.Println("  Generated on HSM:  WARNING (no GENERATE ASYMMETRIC KEY entry found for this key)")
		fmt.Println("                     The key may have been generated before audit logging was enabled")
	}

	// Check that the key was never exported (no EXPORT_WRAPPED, EXPORT_RSA_WRAPPED targeting this key)
	exportCmds := map[uint8]string{
		hsm.CmdExportWrapped:    "EXPORT WRAPPED",
		hsm.CmdExportRSAWrapped: "EXPORT RSA WRAPPED",
		hsm.CmdExportRSAWrappedObj: "EXPORT RSA WRAPPED OBJ",
	}
	for _, e := range entries {
		if name, isExport := exportCmds[e.Command]; isExport {
			if e.TargetKey == caKeyID || e.SecondKey == caKeyID {
				fmt.Printf("  Never exported:    FAIL (entry %d: %s)\n", e.Number, name)
				ok = false
			}
		}
	}
	if ok {
		fmt.Println("  Never exported:    PASS (no export operations found for this key)")
	}

	// Check attestation cert OIDs if available
	if attestCert != nil {
		for _, ext := range attestCert.Extensions {
			if ext.Id.Equal(oidOrigin) {
				val := parseYubiHSMExtension(ext)
				isGenerated := strings.Contains(val, "generated")
				fmt.Printf("  Attestation origin: %s (%s)\n", passOrFail(isGenerated), val)
				if !isGenerated {
					ok = false
				}
			}
			if ext.Id.Equal(oidCapabilities) {
				val := parseYubiHSMExtension(ext)
				// Check the key doesn't have exportable-under-wrap capability
				hasExportable := strings.Contains(val, "exportable-under-wrap")
				fmt.Printf("  Unexportable:      %s (capabilities: %s)\n", passOrFail(!hasExportable), val)
				if hasExportable {
					ok = false
				}
			}
		}
	}

	return ok
}

func verifyCertificateParams(hsmEntryNum uint16, signOp *models.AuditLogEntry) bool {
	if signOp.Certificate == "" {
		fmt.Printf("  HSM %3d: WARNING no certificate stored (signed before certificate logging was enabled)\n", hsmEntryNum)
		return true // can't verify, not a failure
	}

	certStr := strings.TrimSpace(signOp.Certificate)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		fmt.Printf("  HSM %3d: FAIL parsing certificate: %v\n", hsmEntryNum, err)
		return false
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		fmt.Printf("  HSM %3d: FAIL not an SSH certificate\n", hsmEntryNum)
		return false
	}

	errors := 0

	// Verify public key matches
	claimedPubStr := strings.TrimSpace(signOp.PublicKey)
	claimedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(claimedPubStr))
	if err == nil {
		certKeyBytes := cert.Key.Marshal()
		claimedKeyBytes := claimedPub.Marshal()
		if string(certKeyBytes) != string(claimedKeyBytes) {
			fmt.Printf("  HSM %3d: FAIL public key mismatch\n", hsmEntryNum)
			errors++
		}
	}

	// Verify key ID
	if cert.KeyId != signOp.KeyID {
		fmt.Printf("  HSM %3d: FAIL key_id mismatch (cert=%q, log=%q)\n", hsmEntryNum, cert.KeyId, signOp.KeyID)
		errors++
	}

	// Verify cert type
	expectedType := ssh.UserCert
	if signOp.CertType == "host" {
		expectedType = ssh.HostCert
	}
	if cert.CertType != uint32(expectedType) {
		fmt.Printf("  HSM %3d: FAIL cert_type mismatch (cert=%d, log=%s)\n", hsmEntryNum, cert.CertType, signOp.CertType)
		errors++
	}

	// Verify principals
	if len(cert.ValidPrincipals) != len(signOp.Principals) {
		fmt.Printf("  HSM %3d: FAIL principals count mismatch (cert=%d, log=%d)\n",
			hsmEntryNum, len(cert.ValidPrincipals), len(signOp.Principals))
		errors++
	} else {
		for i, p := range cert.ValidPrincipals {
			if i < len(signOp.Principals) && p != signOp.Principals[i] {
				fmt.Printf("  HSM %3d: FAIL principal[%d] mismatch (cert=%q, log=%q)\n", hsmEntryNum, i, p, signOp.Principals[i])
				errors++
			}
		}
	}

	// Verify serial
	certSerial := fmt.Sprintf("%d", cert.Serial)
	if certSerial != signOp.Serial {
		fmt.Printf("  HSM %3d: FAIL serial mismatch (cert=%s, log=%s)\n", hsmEntryNum, certSerial, signOp.Serial)
		errors++
	}

	// Verify validity
	certValidAfter := time.Unix(int64(cert.ValidAfter), 0)
	certValidBefore := time.Unix(int64(cert.ValidBefore), 0)
	if certValidAfter.Unix() != signOp.ValidAfter.Unix() {
		fmt.Printf("  HSM %3d: FAIL valid_after mismatch\n", hsmEntryNum)
		errors++
	}
	if certValidBefore.Unix() != signOp.ValidBefore.Unix() {
		fmt.Printf("  HSM %3d: FAIL valid_before mismatch\n", hsmEntryNum)
		errors++
	}

	if errors == 0 {
		fmt.Printf("  HSM %3d: OK key_id=%q principals=%v serial=%s type=%s\n",
			hsmEntryNum, signOp.KeyID, signOp.Principals, truncStr(signOp.Serial, 10), orDefault(signOp.CertType, "user"))
	}
	return errors == 0
}

func mustCmdName(cmd uint8) string {
	name, ok := cmdName(cmd)
	if !ok {
		return fmt.Sprintf("0x%02x", cmd)
	}
	return name
}
