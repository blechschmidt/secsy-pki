package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
)

// printIssuePreview renders a single-request pre-issuance dry-run (Task 113) for
// an operator: the overall decision, the resolved leaf the CA would sign, and
// every pre-issuance gate's verdict. It is the CLI counterpart of the
// POST /api/ca/{id}/certificates:preview response.
func printIssuePreview(w io.Writer, p *ca.PreviewResult) {
	fmt.Fprintf(w, "Issuance preview for CA %s (%s)\n", p.CALabel, p.CAID)
	fmt.Fprintf(w, "  decision:   %s\n", strings.ToUpper(p.Decision))
	fmt.Fprintf(w, "  profile:    %s\n", p.Profile)
	fmt.Fprintf(w, "  subject:    %s\n", p.Subject)
	if len(p.SANs) > 0 {
		fmt.Fprintf(w, "  SANs:       %s\n", strings.Join(p.SANs, ", "))
	}
	fmt.Fprintf(w, "  validity:   %s .. %s (%dd)\n",
		p.NotBefore.Format(time.RFC3339), p.NotAfter.Format(time.RFC3339), p.ValidityDays)
	if p.RequestedValidityDays != p.ValidityDays || p.MaxValidityDays > 0 {
		fmt.Fprintf(w, "              requested %dd", p.RequestedValidityDays)
		if p.MaxValidityDays > 0 {
			fmt.Fprintf(w, ", profile max %dd", p.MaxValidityDays)
		}
		fmt.Fprintln(w)
	}
	if len(p.KeyUsages) > 0 {
		fmt.Fprintf(w, "  key usage:  %s\n", strings.Join(p.KeyUsages, ", "))
	}
	if len(p.ExtKeyUsages) > 0 {
		fmt.Fprintf(w, "  ext usage:  %s\n", strings.Join(p.ExtKeyUsages, ", "))
	}
	if p.MustStaple {
		fmt.Fprintln(w, "  must-staple: yes (RFC 7633 status_request)")
	}
	if p.SubjectKeyID != "" {
		provided := ""
		if !p.SubjectKeyProvided {
			provided = " (indicative — no subject key supplied)"
		}
		fmt.Fprintf(w, "  SKI:        %s%s\n", p.SubjectKeyID, provided)
	}
	if p.AuthorityKeyID != "" {
		fmt.Fprintf(w, "  AKI:        %s\n", p.AuthorityKeyID)
	}
	if len(p.Extensions) > 0 {
		fmt.Fprintf(w, "  extensions: %s\n", strings.Join(extensionLabels(p.Extensions), ", "))
	}

	fmt.Fprintln(w, "  gates:")
	for _, g := range p.Gates {
		fmt.Fprintf(w, "    [%-7s] %s: %s\n", strings.ToUpper(string(g.Status)), g.Name, g.Reason)
		for _, f := range g.Findings {
			fmt.Fprintf(w, "                %s\n", f)
		}
	}

	switch p.Decision {
	case "accept":
		fmt.Fprintln(w, "\nRESULT: request would be ISSUED immediately.")
	case "park":
		fmt.Fprintln(w, "\nRESULT: request would be HELD for four-eyes approval (via the API path).")
	default:
		fmt.Fprintln(w, "\nRESULT: request would be REJECTED — see the failing gate(s) above.")
	}
}

// extensionLabels renders the resolved extensions as "name" (or the raw OID when
// unknown), flagging critical ones.
func extensionLabels(exts []ca.PreviewExtension) []string {
	out := make([]string, 0, len(exts))
	for _, e := range exts {
		label := e.Name
		if label == "" {
			label = e.OID
		}
		if e.Critical {
			label += " (critical)"
		}
		out = append(out, label)
	}
	return out
}
