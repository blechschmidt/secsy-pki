package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// cmdCA dispatches the "ca" command group: the externally-signed subordinate CA
// flow, where the CA key lives in our HSM but the parent is external (an
// offline corporate root or a third-party bridge CA).
//
//	secsy-ca ca csr         generate an HSM-backed CA key + PKCS#10 CSR
//	secsy-ca ca import-cert validate/install the externally signed certificate
func cmdCA(db *database.DB, mgr *ca.Manager, args []string) error {
	if len(args) == 0 {
		caUsage()
		return fmt.Errorf("a ca subcommand is required")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "csr":
		return cmdCACSR(db, mgr, rest)
	case "import-cert":
		return cmdCAImportCert(db, mgr, rest)
	case "help", "-h", "--help":
		caUsage()
		return nil
	default:
		caUsage()
		return fmt.Errorf("unknown ca subcommand %q", sub)
	}
}

func caUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca ca — externally-signed subordinate CA (offline/third-party root)

Usage:
  secsy-ca ca csr -label <label> -cn <name> [flags]   Generate an HSM-backed CA
      key and emit a PKCS#10 CSR (CA basicConstraints/keyUsage) for the external
      parent to sign. The CA is created in the "pending" state.
  secsy-ca ca csr -ca <id|label> [-out file]          Re-emit the stored CSR of
      an existing externally-signed CA (pending re-download, or renewal of the
      same key by the external parent).
  secsy-ca ca import-cert -ca <id|label> -cert <file> [flags]   Validate and
      install the certificate the external parent signed. The public key must
      match the HSM key; -chain imports the external parents (up to the external
      root) so the served chain reaches the external trust anchor.

Run "secsy-ca ca <subcommand> -h" for the full flag list.
`)
}

// cmdCACSR generates an HSM-backed subordinate-CA key and emits its PKCS#10
// CSR, or re-emits the stored CSR of an existing externally-signed CA (-ca).
func cmdCACSR(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("ca csr", flag.ContinueOnError)
	caRef := fs.String("ca", "", "existing CA id or label: re-emit its stored CSR instead of generating a key")
	label := fs.String("label", "", "key label / CA name (required when generating)")
	tenant := fs.String("tenant", "", "owning tenant id or slug (default: the built-in default tenant)")
	keyType := fs.String("key-type", "ecdsa-p384", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048/3072/4096)")
	pathLen := fs.Int("path-len", -1, "path length requested in the CSR (-1 = unconstrained, 0 = leaf-only); the external parent decides what it issues")
	out := fs.String("out", "", "write the CSR PEM here (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit the pending CA record and CSR as JSON on stdout")
	subj := addSubjectFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Re-emit mode: -ca given, nothing is generated.
	if *caRef != "" {
		if *label != "" || *subj.cn != "" {
			return fmt.Errorf("-ca re-emits an existing CSR; it cannot be combined with -label/-cn")
		}
		caID, err := resolveCA(db, *caRef)
		if err != nil {
			return err
		}
		csrPEM, err := mgr.ExternalCACSR(caID)
		if err != nil {
			return err
		}
		return emitCSR(csrPEM, *out)
	}

	if *label == "" || *subj.cn == "" {
		fs.Usage()
		return fmt.Errorf("-label and -cn are required (or -ca to re-emit an existing CSR)")
	}
	tenantID, err := resolveTenant(db, *tenant)
	if err != nil {
		return err
	}

	result, err := mgr.GenerateExternalCACSR(context.Background(), ca.ExternalCACSRSpec{
		TenantID:   tenantID,
		Label:      *label,
		KeyType:    *keyType,
		Subject:    ca.PKIXName(subj.subject()),
		MaxPathLen: pathLenValue(*pathLen),
	})
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: "cli:ca-csr", Action: audit.ActionCACSR, TargetName: *label,
			Result: audit.ResultError, Detail: err.Error(),
		})
		return err
	}
	appendAudit(db, &audit.Event{
		Actor: "cli:ca-csr", Action: audit.ActionCACSR, Target: result.CA.ID, TargetName: result.CA.Label,
		Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("subject=%s key_type=%s", result.CA.Subject, result.CA.KeyType),
	})

	if *jsonOut {
		enc, err := json.MarshalIndent(map[string]interface{}{
			"ca":      result.CA,
			"csr_pem": string(result.CSRPEM),
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(enc))
		return nil
	}

	fmt.Printf("Pending externally-signed CA created (key generated inside the provider):\n")
	fmt.Printf("  ID:       %s\n", result.CA.ID)
	fmt.Printf("  Label:    %s\n", result.CA.Label)
	fmt.Printf("  Subject:  %s\n", result.CA.Subject)
	fmt.Printf("  Key type: %s\n", result.CA.KeyType)
	fmt.Printf("  URI:      %s\n", result.CA.PKCS11URI)
	fmt.Printf("  Status:   %s\n\n", result.CA.Status)
	if err := emitCSR(result.CSRPEM, *out); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nSubmit the CSR to the external parent for signing, then install the result with:\n  secsy-ca ca import-cert -ca %s -cert <signed.pem> [-chain <external-chain.pem>]\n", result.CA.Label)
	return nil
}

// emitCSR writes a CSR PEM to a file or stdout.
func emitCSR(csrPEM []byte, out string) error {
	if out != "" {
		if err := os.WriteFile(out, csrPEM, 0o644); err != nil {
			return fmt.Errorf("writing -out: %w", err)
		}
		fmt.Printf("CSR written to %s\n", out)
		return nil
	}
	os.Stdout.Write(csrPEM)
	return nil
}

// cmdCAImportCert validates and installs an externally signed CA certificate
// (plus the optional external chain) onto a pending CA.
func cmdCAImportCert(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("ca import-cert", flag.ContinueOnError)
	caRef := fs.String("ca", "", "pending CA id or label (required)")
	certFile := fs.String("cert", "", "PEM file with the externally signed CA certificate (required; extra certificates are treated as chain)")
	chainFile := fs.String("chain", "", "PEM file with the external issuing chain (intermediates + root) for verification and chain serving")
	replace := fs.Bool("replace", false, "allow replacing an already-installed externally signed certificate (renewal for the same key, or adding the chain later)")
	chainOut := fs.String("chain-out", "", "write the combined served chain PEM here")
	jsonOut := fs.Bool("json", false, "emit the activated CA record and warnings as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *certFile == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -cert are required")
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("reading -cert: %w", err)
	}
	var chainPEM []byte
	if *chainFile != "" {
		chainPEM, err = os.ReadFile(*chainFile)
		if err != nil {
			return fmt.Errorf("reading -chain: %w", err)
		}
	}

	result, err := mgr.ImportExternalCACertificate(context.Background(), ca.ImportExternalCACertSpec{
		CAID:           caID,
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		Replace:        *replace,
	})
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: "cli:ca-import-cert", Action: audit.ActionCAImportCert, Target: caID,
			Result: audit.ResultError, Detail: err.Error(),
		})
		return err
	}
	detail := fmt.Sprintf("subject=%s serial=%s", result.CA.Subject, result.CA.Serial)
	if len(result.Warnings) > 0 {
		detail += " warnings=" + strings.Join(result.Warnings, "; ")
	}
	appendAudit(db, &audit.Event{
		Actor: "cli:ca-import-cert", Action: audit.ActionCAImportCert, Target: result.CA.ID, TargetName: result.CA.Label,
		Result: audit.ResultSuccess, Detail: detail,
	})

	if *chainOut != "" {
		if err := os.WriteFile(*chainOut, result.ChainPEM, 0o644); err != nil {
			return fmt.Errorf("writing -chain-out: %w", err)
		}
	}

	if *jsonOut {
		enc, err := json.MarshalIndent(map[string]interface{}{
			"ca":        result.CA,
			"warnings":  result.Warnings,
			"chain_pem": string(result.ChainPEM),
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(enc))
		return nil
	}

	fmt.Printf("Imported externally signed certificate for %q:\n", result.CA.Label)
	fmt.Printf("  ID:        %s\n", result.CA.ID)
	fmt.Printf("  Subject:   %s\n", result.CA.Subject)
	fmt.Printf("  Serial:    %s\n", result.CA.Serial)
	if result.CA.NotBefore != nil && result.CA.NotAfter != nil {
		fmt.Printf("  Validity:  %s — %s\n", result.CA.NotBefore.Format(time.RFC3339), result.CA.NotAfter.Format(time.RFC3339))
	}
	fmt.Printf("  Status:    %s\n", result.CA.Status)
	if result.CA.ExternalChain != "" {
		fmt.Printf("  Chain:     external parent(s) imported; served via /api/ca/%s/chain\n", result.CA.ID)
	}
	for _, w := range result.Warnings {
		fmt.Printf("  WARNING:   %s\n", w)
	}
	if *chainOut != "" {
		fmt.Printf("  Chain PEM: %s\n", *chainOut)
	}
	return nil
}
