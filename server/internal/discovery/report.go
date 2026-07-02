package discovery

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Report is the outcome of a discovery scan: every finding plus roll-up counts.
type Report struct {
	GeneratedAt time.Time      `json:"generated_at"`
	ExpiryDays  int            `json:"expiry_days"`
	Findings    []Finding      `json:"findings"`
	Counts      ReportCounts   `json:"counts"`
}

// ReportCounts summarizes a scan for at-a-glance dashboards and alerts.
type ReportCounts struct {
	Total        int `json:"total"`
	Reachable    int `json:"reachable"`
	Unreachable  int `json:"unreachable"`
	ExpiringSoon int `json:"expiring_soon"`
	WeakKey      int `json:"weak_key"`
	SHA1         int `json:"sha1_signature"`
	SelfSigned   int `json:"self_signed"`
	Mismatch     int `json:"hostname_mismatch"`
	Rogue        int `json:"rogue"`
	IssuedByPKI  int `json:"issued_by_pki"`
	Warning      int `json:"warning"`
	Critical     int `json:"critical"`
}

// BuildReport assembles a Report from findings, computing roll-up counts.
func BuildReport(findings []Finding, expiryDays int, now time.Time) *Report {
	r := &Report{GeneratedAt: now, ExpiryDays: expiryDays, Findings: findings}
	for _, f := range findings {
		r.Counts.Total++
		if !f.Reachable {
			r.Counts.Unreachable++
			continue
		}
		r.Counts.Reachable++
		if f.ExpiringSoon {
			r.Counts.ExpiringSoon++
		}
		if f.WeakKey {
			r.Counts.WeakKey++
		}
		if f.SHA1Signature {
			r.Counts.SHA1++
		}
		if f.SelfSigned {
			r.Counts.SelfSigned++
		}
		if f.HostnameMismatch {
			r.Counts.Mismatch++
		}
		if f.Rogue {
			r.Counts.Rogue++
		}
		if f.IssuedByPKI {
			r.Counts.IssuedByPKI++
		}
		switch f.Severity {
		case SeverityWarning:
			r.Counts.Warning++
		case SeverityCritical:
			r.Counts.Critical++
		}
	}
	return r
}

// ToModel converts a reachable finding into its persisted inventory record. It
// returns (nil, false) for an unreachable endpoint, which has no certificate to
// record.
func (f Finding) ToModel(tenantID, id string) (*models.DiscoveredCertificate, bool) {
	if !f.Reachable {
		return nil, false
	}
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	return &models.DiscoveredCertificate{
		ID:                 id,
		TenantID:           tenantID,
		Endpoint:           f.Endpoint,
		ServerName:         f.ServerName,
		Subject:            f.Subject,
		CommonName:         f.CommonName,
		SANs:               f.SANs,
		Issuer:             f.Issuer,
		Serial:             f.Serial,
		NotBefore:          f.NotBefore,
		NotAfter:           f.NotAfter,
		KeyAlgorithm:       f.KeyAlgorithm,
		KeySize:            f.KeySize,
		SignatureAlgorithm: f.SignatureAlgorithm,
		ChainLength:        f.ChainLength,
		ChainComplete:      f.ChainComplete,
		Fingerprint:        f.Fingerprint,
		Certificate:        f.LeafPEM,
		IssuedByPKI:        f.IssuedByPKI,
		Rogue:              f.Rogue,
		SelfSigned:         f.SelfSigned,
		WeakKey:            f.WeakKey,
		SHA1Signature:      f.SHA1Signature,
		HostnameMismatch:   f.HostnameMismatch,
		ExpiringSoon:       f.ExpiringSoon,
		Severity:           f.Severity,
		Flags:              f.Flags,
		DiscoveredAt:       f.DiscoveredAt,
	}, true
}

// WriteText renders a human-readable summary of a report to w. It lists the most
// urgent findings first (critical, then warning, then ok) so an operator sees the
// rogue/weak/expiring certificates at the top.
func (r *Report) WriteText(w io.Writer) {
	sorted := append([]Finding(nil), r.Findings...)
	rank := map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityOK: 2}
	sort.SliceStable(sorted, func(i, j int) bool {
		return rank[sorted[i].Severity] < rank[sorted[j].Severity]
	})

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ENDPOINT\tCOMMON NAME\tKEY\tEXPIRES\tSEVERITY\tFLAGS")
	for _, f := range sorted {
		if !f.Reachable {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Endpoint, "-", "-", "-", "unreachable", f.Error)
			continue
		}
		key := f.KeyAlgorithm
		if f.KeySize > 0 {
			key = fmt.Sprintf("%s-%d", f.KeyAlgorithm, f.KeySize)
		}
		expires := f.NotAfter.Format("2006-01-02")
		flags := "-"
		if len(f.Flags) > 0 {
			flags = joinFlags(f.Flags)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Endpoint, truncate(f.CommonName, 32), key, expires, f.Severity, flags)
	}
	tw.Flush()

	c := r.Counts
	fmt.Fprintf(w, "\n%d endpoint(s): %d reachable, %d unreachable.\n", c.Total, c.Reachable, c.Unreachable)
	fmt.Fprintf(w, "flags: expiring=%d weak-key=%d sha1=%d self-signed=%d hostname-mismatch=%d rogue=%d (issued-by-this-pki=%d)\n",
		c.ExpiringSoon, c.WeakKey, c.SHA1, c.SelfSigned, c.Mismatch, c.Rogue, c.IssuedByPKI)
}

func joinFlags(flags []string) string {
	out := ""
	for i, f := range flags {
		if i > 0 {
			out += ", "
		}
		out += f
	}
	return out
}

func truncate(s string, n int) string {
	if s == "" {
		return "-"
	}
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
