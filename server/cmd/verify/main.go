package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func main() {
	auditLogPath := flag.String("audit-log", "", "Path to exported audit log JSON (HSM-only or combined)")
	deviceCertPath := flag.String("device-cert", "", "Path to device attestation certificate (DER or PEM)")
	yubicoCAPath := flag.String("yubico-ca", "", "Path to Yubico root CA PEM")
	yubicoIntPath := flag.String("yubico-intermediate", "", "Path to Yubico intermediate CA PEM")
	flag.Parse()

	if *auditLogPath == "" && *deviceCertPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: secsy-verify --audit-log <file> [--device-cert <file> --yubico-ca <file> --yubico-intermediate <file>]")
		fmt.Fprintln(os.Stderr, "\n  The audit log can be:")
		fmt.Fprintln(os.Stderr, "    - HSM-only:  {device_serial, entries: [{number, command, ...}]}")
		fmt.Fprintln(os.Stderr, "    - Combined:  {hsm_entries: [...], sign_operations: [...]}")
		os.Exit(1)
	}

	exitCode := 0

	if *deviceCertPath != "" {
		if *yubicoCAPath == "" || *yubicoIntPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --yubico-ca and --yubico-intermediate are required with --device-cert")
			os.Exit(1)
		}
		if !verifyDeviceCert(*deviceCertPath, *yubicoCAPath, *yubicoIntPath) {
			exitCode = 1
		}
		fmt.Println()
	}

	if *auditLogPath != "" {
		if !verifyAuditLog(*auditLogPath) {
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

func verifyDeviceCert(certPath, caPath, intPath string) bool {
	fmt.Println("=== Device Certificate Verification ===")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Printf("Error reading device cert: %v\n", err)
		return false
	}

	var cert *x509.Certificate
	if block, _ := pem.Decode(certData); block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
	} else {
		cert, err = x509.ParseCertificate(certData)
	}
	if err != nil {
		fmt.Printf("Error parsing device cert: %v\n", err)
		return false
	}

	fmt.Printf("  Subject:    %s\n", cert.Subject)
	fmt.Printf("  Issuer:     %s\n", cert.Issuer)
	fmt.Printf("  Serial:     %s\n", cert.SerialNumber)
	fmt.Printf("  Valid:      %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))

	caData, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Printf("Error reading root CA: %v\n", err)
		return false
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caData) {
		fmt.Println("Error: failed to parse root CA PEM")
		return false
	}

	intData, err := os.ReadFile(intPath)
	if err != nil {
		fmt.Printf("Error reading intermediate CA: %v\n", err)
		return false
	}
	intPool := x509.NewCertPool()
	if !intPool.AppendCertsFromPEM(intData) {
		fmt.Println("Error: failed to parse intermediate CA PEM")
		return false
	}

	chains, err := cert.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intPool})
	if err != nil {
		fmt.Printf("  Verification: FAIL (%v)\n", err)
		return false
	}

	fmt.Printf("  Chain:       ")
	for i, c := range chains[0] {
		if i > 0 {
			fmt.Print(" -> ")
		}
		fmt.Print(c.Subject.CommonName)
	}
	fmt.Println()
	fmt.Println("  Verification: PASS")
	return true
}

func cmdName(cmd uint8) string {
	if name, ok := hsm.CryptoCommands[cmd]; ok {
		return name
	}
	switch cmd {
	case 0xff:
		return "BOOT SENTINEL"
	case 0x00:
		return "BOOT"
	case hsm.CmdPutOption:
		return "PUT OPTION"
	case hsm.CmdPutAuthKey:
		return "PUT AUTH KEY"
	case hsm.CmdChangeAuthKey:
		return "CHANGE AUTH KEY"
	case hsm.CmdDeleteObject:
		return "DELETE OBJECT"
	case hsm.CmdPutWrapKey:
		return "PUT WRAP KEY"
	case hsm.CmdGenerateWrapKey:
		return "GENERATE WRAP KEY"
	case hsm.CmdExportWrapped:
		return "EXPORT WRAPPED"
	case hsm.CmdImportWrapped:
		return "IMPORT WRAPPED"
	default:
		return fmt.Sprintf("0x%02x", cmd)
	}
}

func verifyAuditLog(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading audit log: %v\n", err)
		return false
	}

	// Try combined format first
	var combined models.CombinedAuditExport
	if err := json.Unmarshal(data, &combined); err == nil && len(combined.HSMEntries) > 0 {
		return verifyCombinedLog(&combined)
	}

	// Try HSM-only format
	var hsmLog hsm.AuditLog
	if err := json.Unmarshal(data, &hsmLog); err == nil && len(hsmLog.Entries) > 0 {
		return verifyHSMOnlyLog(&hsmLog)
	}

	// Try bare array
	var entries []hsm.AuditLogEntry
	if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
		return verifyHSMOnlyLog(&hsm.AuditLog{Entries: entries})
	}

	fmt.Println("Error: could not parse audit log (no entries found)")
	return false
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

	// Convert HSM entries for chain verification
	hsmEntries := make([]hsm.AuditLogEntry, len(combined.HSMEntries))
	for i, e := range combined.HSMEntries {
		hsmEntries[i] = hsm.AuditLogEntry{
			Number: e.Number, Command: e.Command, Length: e.Length,
			SessionKey: e.SessionKey, TargetKey: e.TargetKey, SecondKey: e.SecondKey,
			Result: e.Result, Tick: e.Tick, Hash: e.Hash,
		}
	}

	chainOK := verifyHSMChain(hsmEntries)

	// Cross-reference: for each crypto HSM entry with a sign_audit_id, verify it has a matching sign op
	fmt.Println("\n=== Sign Operation Cross-Reference ===")

	signOpMap := make(map[string]*models.AuditLogEntry)
	for i := range combined.SignOps {
		signOpMap[combined.SignOps[i].ID] = &combined.SignOps[i]
	}

	cryptoLinked := 0
	cryptoUnlinked := 0
	crossRefOK := true

	for _, e := range combined.HSMEntries {
		_, isCrypto := hsm.CryptoCommands[e.Command]
		if !isCrypto {
			continue
		}

		if e.SignAuditID == nil {
			fmt.Printf("  WARNING: HSM entry %d (%s) has no linked sign operation\n",
				e.Number, cmdName(e.Command))
			cryptoUnlinked++
			continue
		}

		signOp, exists := signOpMap[*e.SignAuditID]
		if !exists {
			fmt.Printf("  FAIL: HSM entry %d links to sign op %s which doesn't exist\n",
				e.Number, *e.SignAuditID)
			crossRefOK = false
			continue
		}

		cryptoLinked++
		fmt.Printf("  Entry %3d: %-25s -> key_id=%q principals=%v cert_type=%s valid=%s..%s pubkey=%s...\n",
			e.Number, cmdName(e.Command),
			signOp.KeyID,
			signOp.Principals,
			orDefault(signOp.CertType, "user"),
			signOp.ValidAfter.Format(time.DateOnly),
			signOp.ValidBefore.Format(time.DateOnly),
			truncStr(signOp.PublicKey, 40),
		)
	}

	fmt.Printf("\n  Linked crypto operations:   %d\n", cryptoLinked)
	if cryptoUnlinked > 0 {
		fmt.Printf("  Unlinked crypto operations: %d (provisioning/test ops before sign tracking)\n", cryptoUnlinked)
	}
	fmt.Printf("  Cross-reference:            %s\n", passOrFail(crossRefOK))

	// Check no sign ops are missing from HSM log
	linkedIDs := make(map[string]bool)
	for _, e := range combined.HSMEntries {
		if e.SignAuditID != nil {
			linkedIDs[*e.SignAuditID] = true
		}
	}

	orphanOps := 0
	for _, op := range combined.SignOps {
		if !linkedIDs[op.ID] {
			fmt.Printf("  WARNING: Sign op %s (key_id=%q) has no HSM entry (signing may predate audit provisioning)\n",
				op.ID[:8], op.KeyID)
			orphanOps++
		}
	}
	if orphanOps > 0 {
		fmt.Printf("  Unmatched sign operations:  %d\n", orphanOps)
	}

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
	var failures []string

	for i, ok := range results {
		e := entries[i]
		name := cmdName(e.Command)
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
				failures = append(failures, fmt.Sprintf(
					"  FAIL entry %d: %s (cmd=0x%02x target=0x%04x tick=%d)",
					e.Number, name, e.Command, e.TargetKey, e.Tick))
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
	fmt.Printf("  Hash chain integrity:    %s\n", passOrFail(chainOK))
	fmt.Printf("  Crypto operations found: %d\n", cryptoCount)

	if cryptoCount > 0 {
		allCryptoOK := cryptoFail == 0
		fmt.Printf("  Crypto operations valid: %s\n", passOrFail(allCryptoOK))
		if !allCryptoOK {
			fmt.Printf("\n  %d crypto operation(s) with broken hash chain:\n", cryptoFail)
			for _, f := range failures {
				fmt.Println(f)
			}
		}
	} else {
		fmt.Println("  WARNING: No crypto operations in log (audit logging may not be enabled)")
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
