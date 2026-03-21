package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

func main() {
	auditLogPath := flag.String("audit-log", "", "Path to exported HSM audit log JSON")
	deviceCertPath := flag.String("device-cert", "", "Path to device attestation certificate (DER or PEM)")
	yubicoCAPath := flag.String("yubico-ca", "", "Path to Yubico root CA PEM")
	yubicoIntPath := flag.String("yubico-intermediate", "", "Path to Yubico intermediate CA PEM")
	flag.Parse()

	if *auditLogPath == "" && *deviceCertPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: secsy-verify --audit-log <file> [--device-cert <file> --yubico-ca <file> --yubico-intermediate <file>]")
		fmt.Fprintln(os.Stderr, "  At least --audit-log or --device-cert must be provided.")
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

	// Try PEM first, fall back to DER
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

	// Load root CA
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

	// Load intermediate CA
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

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intPool,
	}

	chains, err := cert.Verify(opts)
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
	fmt.Println("=== Audit Log Hash Chain Verification ===")

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading audit log: %v\n", err)
		return false
	}

	var log hsm.AuditLog
	if err := json.Unmarshal(data, &log); err != nil {
		var entries []hsm.AuditLogEntry
		if err2 := json.Unmarshal(data, &entries); err2 != nil {
			fmt.Printf("Error parsing audit log JSON: %v\n", err)
			return false
		}
		log.Entries = entries
	}

	if log.DeviceSerial != "" {
		fmt.Printf("  Device Serial: %s\n", log.DeviceSerial)
	}
	if !log.ExportedAt.IsZero() {
		fmt.Printf("  Exported At:   %s\n", log.ExportedAt.Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Printf("  Entries:       %d\n\n", len(log.Entries))

	if len(log.Entries) == 0 {
		fmt.Println("  No entries to verify")
		return true
	}

	results, err := hsm.VerifyHashChain(log.Entries)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return false
	}

	chainOK := true
	cryptoCount := 0
	cryptoFail := 0
	var failures []string

	for i, ok := range results {
		e := log.Entries[i]
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
			return false
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
