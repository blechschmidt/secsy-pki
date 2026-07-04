//go:build zlint

package certlint

import (
	"fmt"
	"strings"

	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

// This file is the ONLY place in the tree that references github.com/zmap/zlint
// and github.com/zmap/zcrypto, and it is compiled only under the "zlint" build
// tag. Default, FIPS, and supply-chain-hardened builds omit it and therefore do
// not link (or expose to govulncheck's default reachability analysis) either
// dependency. See docs/certlint.md for the dependency/govulncheck implications.

const zlintCompiledIn = true

// runZLint parses der with zcrypto and executes the filtered zlint registry
// against it, returning every reportable result (notice / warn / error / fatal).
func runZLint(der []byte, filter zlintFilter) ([]zlintRaw, error) {
	cert, err := zx509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate for zlint: %w", err)
	}
	registry, err := buildRegistry(filter)
	if err != nil {
		return nil, err
	}
	var set *zlint.ResultSet
	if registry == nil {
		set = zlint.LintCertificate(cert)
	} else {
		set = zlint.LintCertificateEx(cert, registry)
	}
	out := make([]zlintRaw, 0, len(set.Results))
	for name, res := range set.Results {
		status, report := reportableStatus(res.Status)
		if !report {
			continue
		}
		out = append(out, zlintRaw{
			Name:     name,
			Status:   status,
			Details:  res.Details,
			Citation: res.LintMetadata.Citation,
			Source:   string(res.LintMetadata.Source),
		})
	}
	return out, nil
}

// buildRegistry constructs a filtered lint registry from the policy's source and
// name selectors, or returns nil to run the entire global registry.
func buildRegistry(filter zlintFilter) (lint.Registry, error) {
	if len(filter.IncludeSources) == 0 && len(filter.ExcludeSources) == 0 &&
		len(filter.IncludeNames) == 0 && len(filter.ExcludeNames) == 0 {
		return nil, nil
	}
	opts := lint.FilterOptions{
		IncludeNames: filter.IncludeNames,
		ExcludeNames: filter.ExcludeNames,
	}
	if err := sourcesFromStrings(&opts.IncludeSources, filter.IncludeSources); err != nil {
		return nil, fmt.Errorf("zlint include_sources: %w", err)
	}
	if err := sourcesFromStrings(&opts.ExcludeSources, filter.ExcludeSources); err != nil {
		return nil, fmt.Errorf("zlint exclude_sources: %w", err)
	}
	reg, err := lint.GlobalRegistry().Filter(opts)
	if err != nil {
		return nil, fmt.Errorf("building zlint registry: %w", err)
	}
	return reg, nil
}

// sourcesFromStrings parses a list of source labels (e.g. "CABF_BR", "RFC5280")
// into a zlint SourceList.
func sourcesFromStrings(dst *lint.SourceList, in []string) error {
	if len(in) == 0 {
		return nil
	}
	return dst.FromString(strings.Join(in, ","))
}

// reportableStatus maps a zlint status to our lowercase label, reporting only
// the actionable statuses. NA (not applicable), NE (not effective), Pass, and
// Reserved are non-findings and are dropped.
func reportableStatus(s lint.LintStatus) (string, bool) {
	switch s {
	case lint.Notice:
		return zlintStatusNotice, true
	case lint.Warn:
		return zlintStatusWarn, true
	case lint.Error:
		return zlintStatusError, true
	case lint.Fatal:
		return zlintStatusFatal, true
	default:
		return "", false
	}
}
