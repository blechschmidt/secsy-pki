package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// cmdBlockedKeys implements `secsy-ca blocked-keys <add|list|remove>` — operator
// management of the compromised-key blocklist (Task 120). A key on the blocklist
// is rejected by the fail-closed pre-issuance key-quality gate on every issuance
// surface. Entries are keyed by the SubjectPublicKeyInfo SHA-256 fingerprint
// ("SHA256:<base64>"); the blocklist holds no key material. Local CLI access is
// platform-operator level (it bypasses the API's RBAC), so the commands operate
// directly on the store.
func cmdBlockedKeys(db *database.DB, args []string) error {
	if len(args) == 0 {
		blockedKeysUsage()
		return fmt.Errorf("blocked-keys: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add", "block":
		return cmdBlockedKeysAdd(db, rest)
	case "list", "ls":
		return cmdBlockedKeysList(db, rest)
	case "remove", "rm", "unblock":
		return cmdBlockedKeysRemove(db, rest)
	case "help", "-h", "--help":
		blockedKeysUsage()
		return nil
	default:
		blockedKeysUsage()
		return fmt.Errorf("blocked-keys: unknown subcommand %q", sub)
	}
}

func blockedKeysUsage() {
	fmt.Fprint(os.Stderr, `Usage: secsy-ca blocked-keys <subcommand> [flags]

Manage the compromised-key blocklist: public keys the CA must never certify
again (weak/compromised keys, key-compromise incidents). Entries are keyed by the
SubjectPublicKeyInfo SHA-256 fingerprint ("SHA256:<base64>"); no key material is
stored. Blocked keys are rejected fail-closed by the pre-issuance key-quality gate.

Subcommands:
  add      Add a key to the blocklist (from a certificate, CSR, public key, or fingerprint)
  list     List blocklisted keys
  remove   Remove a key from the blocklist (by fingerprint)

Examples:
  secsy-ca blocked-keys add -cert leaked.pem -reason "key compromise, INC-1234"
  secsy-ca blocked-keys add -csr device.csr -reason "weak vendor key"
  secsy-ca blocked-keys add -fingerprint SHA256:abc... -reason "reported compromised"
  secsy-ca blocked-keys list
  secsy-ca blocked-keys remove SHA256:abc...
`)
}

func cmdBlockedKeysAdd(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("blocked-keys add", flag.ContinueOnError)
	certPath := fs.String("cert", "", "path to a certificate (PEM or DER) whose subject key to block")
	csrPath := fs.String("csr", "", "path to a PKCS#10 CSR (PEM or DER) whose public key to block")
	keyPath := fs.String("key", "", "path to a public key (PEM/DER SubjectPublicKeyInfo) to block")
	fingerprint := fs.String("fingerprint", "", "block a key by its SHA256:<base64> SubjectPublicKeyInfo fingerprint directly")
	reason := fs.String("reason", "", "operator justification for the block (recorded and audited)")
	source := fs.String("source", "cli", "where the block originated (free-form label)")
	asJSON := fs.Bool("json", false, "emit the blocklist entry as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fp, err := resolveBlockFingerprint(*fingerprint, *certPath, *csrPath, *keyPath)
	if err != nil {
		return err
	}

	rec := &models.BlockedKey{
		Fingerprint: fp,
		Reason:      strings.TrimSpace(*reason),
		Source:      strings.TrimSpace(*source),
		AddedBy:     cliActor(),
		AddedAt:     time.Now().UTC(),
	}
	added, err := db.AddBlockedKey(rec)
	if err != nil {
		return fmt.Errorf("adding blocked key: %w", err)
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionKeyBlock,
		Target: fp, TargetName: rec.Reason, Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("source=%s newly_added=%t via=cli", rec.Source, added),
	})

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(struct {
			*models.BlockedKey
			NewlyAdded bool `json:"newly_added"`
		}{BlockedKey: rec, NewlyAdded: added})
	}
	if !added {
		fmt.Printf("Key already blocked: %s\n", fp)
		return nil
	}
	fmt.Printf("Key blocked: %s\n", fp)
	if rec.Reason != "" {
		fmt.Printf("  reason: %s\n", rec.Reason)
	}
	fmt.Println("  The pre-issuance key-quality gate will now reject any certificate request bearing this key.")
	return nil
}

func cmdBlockedKeysList(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("blocked-keys list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the blocklist as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := db.ListBlockedKeys()
	if err != nil {
		return err
	}
	if *asJSON {
		if keys == nil {
			keys = []models.BlockedKey{}
		}
		return json.NewEncoder(os.Stdout).Encode(keys)
	}
	if len(keys) == 0 {
		fmt.Println("No blocked keys.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tADDED\tADDED-BY\tSOURCE\tREASON")
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			k.Fingerprint, k.AddedAt.Format(time.RFC3339), orDash(k.AddedBy), orDash(k.Source), orDash(k.Reason))
	}
	return w.Flush()
}

func cmdBlockedKeysRemove(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("blocked-keys remove", flag.ContinueOnError)
	fp, rest := splitIDAndFlags(args)
	reason := fs.String("reason", "", "operator justification for un-blocking (recorded and audited)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fp == "" {
		fp = fs.Arg(0)
	}
	if strings.TrimSpace(fp) == "" {
		return fmt.Errorf("usage: secsy-ca blocked-keys remove <fingerprint>")
	}
	removed, err := db.RemoveBlockedKey(fp)
	if err != nil {
		return fmt.Errorf("removing blocked key: %w", err)
	}
	if !removed {
		fmt.Printf("Key was not on the blocklist: %s\n", fp)
		return nil
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionKeyUnblock,
		Target: fp, TargetName: strings.TrimSpace(*reason), Result: audit.ResultSuccess,
		Detail: "via=cli",
	})
	fmt.Printf("Key un-blocked: %s\n", fp)
	return nil
}

// resolveBlockFingerprint derives the SubjectPublicKeyInfo fingerprint to block
// from exactly one input source. A directly-supplied fingerprint is validated and
// normalized; a certificate/CSR/public-key file is parsed and its subject public
// key fingerprinted with keycheck.Fingerprint (the exact value the gate compares).
func resolveBlockFingerprint(fingerprint, certPath, csrPath, keyPath string) (string, error) {
	set := 0
	for _, s := range []string{fingerprint, certPath, csrPath, keyPath} {
		if strings.TrimSpace(s) != "" {
			set++
		}
	}
	if set == 0 {
		return "", fmt.Errorf("one of -cert, -csr, -key, or -fingerprint is required")
	}
	if set > 1 {
		return "", fmt.Errorf("give exactly one of -cert, -csr, -key, or -fingerprint")
	}

	if strings.TrimSpace(fingerprint) != "" {
		fp := strings.TrimSpace(fingerprint)
		if !strings.HasPrefix(fp, "SHA256:") {
			return "", fmt.Errorf("-fingerprint must be a SHA256:<base64> SubjectPublicKeyInfo fingerprint")
		}
		return fp, nil
	}

	var (
		pub crypto.PublicKey
		err error
	)
	switch {
	case certPath != "":
		pub, err = publicKeyFromCert(certPath)
	case csrPath != "":
		pub, err = publicKeyFromCSR(csrPath)
	default:
		pub, err = publicKeyFromKeyFile(keyPath)
	}
	if err != nil {
		return "", err
	}
	fp, err := keycheck.Fingerprint(pub)
	if err != nil {
		return "", fmt.Errorf("fingerprinting public key: %w", err)
	}
	return fp, nil
}

func publicKeyFromCert(path string) (crypto.PublicKey, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := pki.ParseCertificatePEMOrDER(data)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert.PublicKey, nil
}

func publicKeyFromCSR(path string) (crypto.PublicKey, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, fmt.Errorf("reading CSR: %w", err)
	}
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	return csr.PublicKey, nil
}

func publicKeyFromKeyFile(path string) (crypto.PublicKey, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing public key (expected a SubjectPublicKeyInfo): %w", err)
	}
	return pub, nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
