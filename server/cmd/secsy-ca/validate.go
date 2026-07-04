package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/certvalidate"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// cmdValidateCert implements `secsy-ca validate-cert`: a read-only, HSM-independent
// certificate chain/path validation (Task 123). It builds and validates a supplied
// leaf (and optional intermediates) against a CA's configured trust anchors and
// prints a structured report, exiting non-zero when the chain is not valid.
//
// It opens only the database (for the CA's trust anchors and the live revocation
// store); it never touches the HSM, so it works during an HSM outage and is
// dispatched before the key provider is constructed.
func cmdValidateCert(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("validate-cert", flag.ContinueOnError)
	caRef := fs.String("ca", "", "trust-anchor CA id or label to validate against (required)")
	var interFiles multiFlag
	fs.Var(&interFiles, "intermediate", "path to an intermediate certificate (PEM or DER) to bridge the path; repeatable")
	skipRevocation := fs.Bool("skip-revocation", false, "skip the live per-certificate revocation (CRL/OCSP) checks")
	asJSON := fs.Bool("json", false, "emit the validation report as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ca validate-cert -ca <id|label> [flags] <cert>   (PEM or DER; use - for stdin)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	path := fs.Arg(0)
	if path == "" {
		fs.Usage()
		return fmt.Errorf("a certificate path is required (use - for stdin)")
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	caModel, err := db.GetCA(caID)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}
	if caModel == nil {
		return fmt.Errorf("CA %q not found", *caRef)
	}

	// Parse the leaf (a PEM bundle's first certificate is the leaf; the rest are
	// treated as supplied intermediates) plus any -intermediate files.
	leafBytes, err := readInput(path)
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}
	leafAndChain, err := parseCertsFile(leafBytes)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	if len(leafAndChain) == 0 {
		return fmt.Errorf("no certificate found in %s", path)
	}
	leaf := leafAndChain[0]
	supplied := append([]*x509.Certificate(nil), leafAndChain[1:]...)
	for _, f := range interFiles {
		b, err := readInput(f)
		if err != nil {
			return fmt.Errorf("reading intermediate %s: %w", f, err)
		}
		certs, err := parseCertsFile(b)
		if err != nil {
			return fmt.Errorf("parsing intermediate %s: %w", f, err)
		}
		supplied = append(supplied, certs...)
	}

	mgr := ca.NewManager(db, nil) // validation is HSM-independent; no key provider needed
	roots, inter, err := mgr.TrustAnchorsFor(caID)
	if err != nil {
		return fmt.Errorf("resolving trust anchors: %w", err)
	}
	anchorLabel := caModel.Label
	if caModel.Subject != "" {
		anchorLabel = fmt.Sprintf("%s (%s)", caModel.Label, caModel.Subject)
	}
	opts := certvalidate.Options{
		Roots:            roots,
		Intermediates:    inter,
		TrustAnchorLabel: anchorLabel,
	}
	if !*skipRevocation {
		cas, err := db.ListCAsForTenant(caModel.TenantID)
		if err != nil {
			return fmt.Errorf("loading tenant CAs for revocation checking: %w", err)
		}
		opts.Revocation = mgr.NewChainRevocationResolver(cas)
	}

	report := certvalidate.Validate(opts, leaf, supplied)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			CAID    string `json:"ca_id"`
			CALabel string `json:"ca_label"`
			*certvalidate.Report
		}{CAID: caModel.ID, CALabel: caModel.Label, Report: report}); err != nil {
			return err
		}
	} else {
		printValidationReport(os.Stdout, caModel.Label, report)
	}

	if !report.Valid {
		return fmt.Errorf("certificate chain validation FAILED: %s", strings.Join(report.Reasons, "; "))
	}
	return nil
}

// parseCertsFile decodes one or more certificates from PEM (a single certificate
// or a bundle) or, when the input carries no PEM certificate block, a single raw
// DER certificate.
func parseCertsFile(b []byte) ([]*x509.Certificate, error) {
	certs, err := pki.ParseCertificateChainPEM(b)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		return certs, nil
	}
	cert, err := pki.ParseCertificatePEMOrDER(b)
	if err != nil {
		return nil, fmt.Errorf("input is neither a PEM certificate nor valid DER: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

// printValidationReport renders a human-readable validation report.
func printValidationReport(w *os.File, caLabel string, r *certvalidate.Report) {
	fmt.Fprintf(w, "Chain validation against CA %q\n", caLabel)
	fmt.Fprintf(w, "Trust anchor:  %s\n", r.TrustAnchor)
	fmt.Fprintf(w, "Evaluated at:  %s\n", r.Now.UTC().Format(time.RFC3339))
	built := "no"
	if r.ChainBuilt {
		built = "yes"
	}
	fmt.Fprintf(w, "Chain built:   %s (%d certificate(s))\n", built, len(r.Chain))
	if !r.ValidFrom.IsZero() && !r.ValidUntil.IsZero() {
		fmt.Fprintf(w, "Validity:      %s .. %s\n", r.ValidFrom.UTC().Format(time.RFC3339), r.ValidUntil.UTC().Format(time.RFC3339))
	}

	fmt.Fprintln(w, "\nChain:")
	for _, ci := range r.Chain {
		role := "leaf"
		if ci.IsTrustAnchor {
			role = "anchor"
		} else if ci.Position > 0 {
			role = "ca"
		}
		key := ci.KeyAlgorithm
		if ci.KeySize > 0 {
			key = fmt.Sprintf("%s-%d", ci.KeyAlgorithm, ci.KeySize)
		}
		fmt.Fprintf(w, "  [%d] %-6s %s\n", ci.Position, role, ci.Subject)
		fmt.Fprintf(w, "        serial=%s key=%s sig=%s\n", ci.SerialNumber, key, ci.SignatureAlgorithm)
		fmt.Fprintf(w, "        not_before=%s not_after=%s\n", ci.NotBefore.UTC().Format(time.RFC3339), ci.NotAfter.UTC().Format(time.RFC3339))
		var flags []string
		if ci.Expired {
			flags = append(flags, "EXPIRED")
		}
		if ci.NotYetValid {
			flags = append(flags, "NOT-YET-VALID")
		}
		if ci.WeakKey {
			flags = append(flags, "WEAK-KEY")
		}
		if ci.WeakSignature {
			flags = append(flags, "WEAK-SIGNATURE")
		}
		if ci.Revocation != nil {
			flags = append(flags, "revocation="+string(ci.Revocation.State))
		}
		if len(flags) > 0 {
			fmt.Fprintf(w, "        %s\n", strings.Join(flags, " "))
		}
	}

	fmt.Fprintln(w, "\nChecks:")
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  [%s] %s: %s\n", strings.ToUpper(string(c.Status)), c.Name, c.Detail)
		for _, f := range c.Findings {
			fmt.Fprintf(w, "        - %s\n", f)
		}
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  ! warning: %s\n", warn)
	}

	verdict := "VALID"
	if !r.Valid {
		verdict = "INVALID"
	}
	fmt.Fprintf(w, "\nResult: %s\n", verdict)
	for _, reason := range r.Reasons {
		fmt.Fprintf(w, "  - %s\n", reason)
	}
}
