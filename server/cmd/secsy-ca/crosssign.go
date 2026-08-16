package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// cmdCrossSign cross-signs a subject public key with a local issuer CA's
// HSM-backed key, producing an alternate chain for bridge-CA or root-transition
// topologies. The subject may be another CA in this deployment (-subject-ca), an
// externally supplied certificate (-cert), or a CSR (-csr). The subject's private
// key is never involved — only its public half is re-certified under a new issuer.
func cmdCrossSign(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("cross-sign", flag.ContinueOnError)
	issuerRef := fs.String("issuer", "", "issuer CA id or label whose HSM key signs (required)")
	subjectCARef := fs.String("subject-ca", "", "local CA id or label to cross-sign")
	certFile := fs.String("cert", "", "PEM certificate file to cross-sign (external subject)")
	csrFile := fs.String("csr", "", "PEM CSR file to cross-sign (external subject)")
	validityDays := fs.Int("validity-days", 0, "cross-signed cert validity in days (0 = reuse subject's span; required for a CSR)")
	pathLen := fs.Int("path-len", -2, "max path length for the cross-signed cert (-2 = preserve subject's, -1 = unconstrained)")
	certOut := fs.String("out", "", "write the cross-signed certificate PEM here")
	chainOut := fs.String("chain-out", "", "write the alternate chain PEM (cross-cert + issuer chain) here")
	jsonOut := fs.Bool("json", false, "emit the cross-sign record as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuerRef == "" {
		fs.Usage()
		return fmt.Errorf("-issuer is required")
	}

	// Exactly one subject source.
	sources := 0
	if *subjectCARef != "" {
		sources++
	}
	if *certFile != "" {
		sources++
	}
	if *csrFile != "" {
		sources++
	}
	if sources != 1 {
		fs.Usage()
		return fmt.Errorf("set exactly one of -subject-ca, -cert, or -csr")
	}

	issuerID, err := resolveCA(db, *issuerRef)
	if err != nil {
		return err
	}

	spec := ca.CrossSignSpec{
		IssuerCAID:  issuerID,
		RequestedBy: "cli:cross-sign",
	}
	if *validityDays > 0 {
		spec.Validity = time.Duration(*validityDays) * 24 * time.Hour
	}
	// -2 preserves the subject's constraint; -1 means explicitly unconstrained;
	// >= 0 sets the constraint to that value.
	switch *pathLen {
	case -2:
		// leave spec.MaxPathLen nil so the subject's constraint is preserved
	case -1:
		// unconstrained: CreateCACertificate leaves the path length unset
	default:
		v := *pathLen
		spec.MaxPathLen = &v
	}

	switch {
	case *subjectCARef != "":
		subjectID, err := resolveCA(db, *subjectCARef)
		if err != nil {
			return err
		}
		spec.SubjectCAID = subjectID
	case *certFile != "":
		pem, err := os.ReadFile(*certFile)
		if err != nil {
			return fmt.Errorf("reading -cert: %w", err)
		}
		spec.CertPEM = pem
	case *csrFile != "":
		pem, err := os.ReadFile(*csrFile)
		if err != nil {
			return fmt.Errorf("reading -csr: %w", err)
		}
		spec.CSRPEM = pem
	}

	result, err := mgr.CrossSign(context.Background(), spec)
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: "cli:cross-sign", Action: audit.ActionCACrossSign, Target: issuerID,
			Result: audit.ResultError, Detail: err.Error(),
		})
		return err
	}

	cs := result.CrossSign
	appendAudit(db, &audit.Event{
		Actor: "cli:cross-sign", Action: audit.ActionCACrossSign, Target: cs.IssuerCAID, TargetName: cs.Subject,
		Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("cross_sign=%s subject_key_id=%s source=%s serial=%s", cs.ID, cs.SubjectKeyID, cs.Source, cs.Serial),
	})

	if *certOut != "" {
		if err := os.WriteFile(*certOut, result.CertificatePEM, 0o644); err != nil {
			return fmt.Errorf("writing -out: %w", err)
		}
	}
	if *chainOut != "" {
		if err := os.WriteFile(*chainOut, result.ChainPEM, 0o644); err != nil {
			return fmt.Errorf("writing -chain-out: %w", err)
		}
	}

	if *jsonOut {
		return cliout.Emit(cs)
	}

	fmt.Printf("Cross-signed %q\n", cs.Subject)
	fmt.Printf("  Cross-sign ID:   %s\n", cs.ID)
	fmt.Printf("  Issuer CA:       %s\n", cs.IssuerCAID)
	fmt.Printf("  Subject key ID:  %s\n", cs.SubjectKeyID)
	fmt.Printf("  Source:          %s\n", cs.Source)
	fmt.Printf("  Serial:          %s\n", cs.Serial)
	fmt.Printf("  Not after:       %s\n", cs.NotAfter.Format(time.RFC3339))
	if *certOut != "" {
		fmt.Printf("  Certificate:     %s\n", *certOut)
	}
	if *chainOut != "" {
		fmt.Printf("  Alternate chain: %s\n", *chainOut)
	}
	return nil
}

// cmdListCrossSigns lists the cross-sign relationships related to a CA (both
// those it issued and those certifying its key), or prints the alternate chains
// available for a subject CA with -chains.
func cmdListCrossSigns(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("list-cross-signs", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	chains := fs.Bool("chains", false, "print the alternate chains available for the CA instead of the records")
	chainOut := fs.String("chain-out", "", "with -chains: write the concatenated alternate chains PEM here")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	if *chains {
		alts, err := mgr.AlternateChains(caID)
		if err != nil {
			return err
		}
		if asJSON {
			return cliout.Emit(alts)
		}
		if *chainOut != "" {
			var bundle []byte
			for _, c := range alts {
				bundle = append(bundle, []byte(c.PEM)...)
			}
			if err := os.WriteFile(*chainOut, bundle, 0o644); err != nil {
				return fmt.Errorf("writing -chain-out: %w", err)
			}
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TYPE\tISSUER\tISSUER CA ID\tCROSS-SIGN ID")
		for _, c := range alts {
			typ := "cross-signed"
			if c.Native {
				typ = "native"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", typ, c.IssuerLabel, c.IssuerCAID, c.CrossSignID)
		}
		return tw.Flush()
	}

	records, err := mgr.ListCrossSigns(caID)
	if err != nil {
		return err
	}
	if asJSON {
		return cliout.Emit(records)
	}
	if len(records) == 0 {
		fmt.Println("No cross-sign relationships for this CA.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSUBJECT\tISSUER CA ID\tSOURCE\tSTATUS\tNOT AFTER")
	for _, cs := range records {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cs.ID, cs.Subject, cs.IssuerCAID, cs.Source, cs.Status, cs.NotAfter.Format("2006-01-02"))
	}
	return tw.Flush()
}
