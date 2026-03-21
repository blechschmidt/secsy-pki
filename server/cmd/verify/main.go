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
	fmt.Fprintln(os.Stderr, "  verify-audit-log  Verify an exported HSM audit log")
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
			return hex.EncodeToString(bs.Bytes)
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
