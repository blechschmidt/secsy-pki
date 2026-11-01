package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Task 222: the CA-creation flags cover the whole X.509 extension set, and the
// ones whose values contain commas must not be split by the repeatable-flag
// convenience. These tests drive the flag sets exactly as init-root,
// issue-intermediate and `ca csr` do.

func parseExtFlags(t *testing.T, args ...string) *caExtFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder))
	c := addCAExtensionFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return c
}

// TestCAExtensionFlagsCoverTheSet drives one flag per extension and checks the
// compiled configuration, which is the same object the REST API accepts as JSON.
func TestCAExtensionFlagsCoverTheSet(t *testing.T) {
	c := parseExtFlags(t,
		"-key-usage", "certSign,crlSign",
		"-eku", "serverAuth", "-eku", "1.3.6.1.4.1.99999.3", "-eku-critical",
		"-san-dns", "ca.example.test", "-san-ip", "192.0.2.10",
		"-san-email", "pki@example.test", "-san-uri", "https://ca.example.test/",
		"-san-upn", "svc@CORP.EXAMPLE",
		"-san-dirname", "O=Example Org,C=DE",
		"-san-registered-id", "1.3.6.1.4.1.99999.9",
		"-san-othername", "1.3.6.1.4.1.99999.10:ia5:marker",
		"-san-critical",
		"-ian-uri", "https://root.example.test/",
		"-crl-url", "http://crl.example.test/root.crl",
		"-delta-crl-url", "http://crl.example.test/delta.crl",
		"-ocsp-url", "http://ocsp.example.test/",
		"-ca-issuer-url", "http://pki.example.test/parent.cer",
		"-ca-repository-url", "http://pki.example.test/certs/",
		"-timestamp-url", "http://tsa.example.test/",
		"-inhibit-any-policy", "1",
		"-key-usage-period", "180d",
		"-must-staple", "-ocsp-no-check",
		"-netscape-comment", "a root",
		"-netscape-cert-type", "sslCA,smimeCA",
		"-subject-key-id", "de:ad:be:ef",
		"-subject-dir-attr", "1.3.6.1.5.5.7.9.4:printable:DE",
		"-ext", "1.3.6.1.4.1.99999.100:critical:utf8:enterprise marker",
		"-ext", "1.3.6.1.4.1.99999.101:der-hex:0500",
	)
	cfg, err := c.extensions()
	if err != nil {
		t.Fatalf("extensions(): %v", err)
	}
	if cfg == nil {
		t.Fatal("extensions() returned nil for a fully populated flag set")
	}

	if got := cfg.KeyUsages; len(got) != 2 || got[0] != "certSign" || got[1] != "crlSign" {
		t.Errorf("key usages = %v", got)
	}
	if len(cfg.ExtKeyUsages) != 2 || !cfg.ExtKeyUsageCritical {
		t.Errorf("EKUs = %v (critical %v)", cfg.ExtKeyUsages, cfg.ExtKeyUsageCritical)
	}
	// The one that the comma-splitting convenience used to break: a two-RDN DN
	// must arrive as ONE subtree.
	san := cfg.SubjectAltName
	if san == nil || len(san.DirNames) != 1 || san.DirNames[0] != "O=Example Org,C=DE" {
		t.Errorf("SAN directoryNames = %v, want one two-RDN DN", san.DirNames)
	}
	if !san.Critical {
		t.Error("-san-critical did not take")
	}
	if len(san.OtherNames) != 1 || san.OtherNames[0].OID != "1.3.6.1.4.1.99999.10" ||
		san.OtherNames[0].Encoding != "ia5" || san.OtherNames[0].Value != "marker" {
		t.Errorf("SAN otherNames = %+v", san.OtherNames)
	}
	if cfg.IssuerAltName == nil || len(cfg.IssuerAltName.URI) != 1 {
		t.Errorf("issuerAltName = %+v", cfg.IssuerAltName)
	}
	for name, got := range map[string][]string{
		"crl_distribution_points": cfg.CRLDistributionPoints,
		"freshest_crl":            cfg.FreshestCRL,
		"ocsp_servers":            cfg.OCSPServers,
		"ca_issuers":              cfg.CAIssuers,
		"ca_repositories":         cfg.CARepositories,
		"timestamp_servers":       cfg.TimestampServers,
	} {
		if len(got) != 1 {
			t.Errorf("%s = %v, want one URI", name, got)
		}
	}
	if cfg.InhibitAnyPolicy == nil || *cfg.InhibitAnyPolicy != 1 {
		t.Errorf("inhibitAnyPolicy = %v", cfg.InhibitAnyPolicy)
	}
	if cfg.PrivateKeyUsagePeriod == nil || cfg.PrivateKeyUsagePeriod.Duration != "180d" {
		t.Errorf("privateKeyUsagePeriod = %+v", cfg.PrivateKeyUsagePeriod)
	}
	if !cfg.MustStaple || !cfg.OCSPNoCheck {
		t.Error("must-staple / ocsp-no-check did not take")
	}
	if cfg.NetscapeComment != "a root" || len(cfg.NetscapeCertType) != 2 {
		t.Errorf("netscape = %q / %v", cfg.NetscapeComment, cfg.NetscapeCertType)
	}
	if cfg.SubjectKeyID != "de:ad:be:ef" {
		t.Errorf("subject key id = %q", cfg.SubjectKeyID)
	}
	if len(cfg.SubjectDirectoryAttributes) != 1 || cfg.SubjectDirectoryAttributes[0].Values[0] != "DE" {
		t.Errorf("directory attributes = %+v", cfg.SubjectDirectoryAttributes)
	}
	// An extension value with a space and a "critical" marker must survive.
	if len(cfg.Custom) != 2 {
		t.Fatalf("custom extensions = %+v", cfg.Custom)
	}
	if !cfg.Custom[0].Critical || cfg.Custom[0].Encoding != "utf8" || cfg.Custom[0].Value != "enterprise marker" {
		t.Errorf("custom[0] = %+v", cfg.Custom[0])
	}
	if cfg.Custom[1].Critical || cfg.Custom[1].Encoding != "der-hex" || cfg.Custom[1].Value != "0500" {
		t.Errorf("custom[1] = %+v", cfg.Custom[1])
	}
}

// TestCAExtensionFlagsNoneIsNil pins that an unconfigured command sends nothing,
// so `init-root` without any of these flags issues exactly the certificate it
// always has.
func TestCAExtensionFlagsNoneIsNil(t *testing.T) {
	cfg, err := parseExtFlags(t).extensions()
	if err != nil {
		t.Fatalf("extensions(): %v", err)
	}
	if cfg != nil {
		t.Errorf("an unconfigured flag set produced %+v", cfg)
	}
}

// TestCAExtensionFlagsValidateEarly checks the flags are compiled at parse time,
// so a bad value is reported before the command touches the HSM.
func TestCAExtensionFlagsValidateEarly(t *testing.T) {
	cases := map[string][]string{
		"key usage without certSign": {"-key-usage", "digitalSignature"},
		"unknown EKU":                {"-eku", "notAUsage"},
		"bad extension OID":          {"-ext", "nope:utf8:x"},
		"malformed -ext":             {"-ext", "1.2.3:utf8"},
		"truncated DER":              {"-ext", "1.2.3:der-hex:0c05"},
		"malformed dir attr":         {"-subject-dir-attr", "1.2.3:printable"},
		"malformed otherName":        {"-san-othername", "1.2.3:utf8"},
		"bad SAN IP":                 {"-san-ip", "299.0.0.1"},
		"bad netscape type":          {"-netscape-cert-type", "webserver"},
		"bad usage period":           {"-key-usage-period", "soon"},
		"bad subject key id":         {"-subject-key-id", "nothex"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseExtFlags(t, args...).extensions(); err == nil {
				t.Errorf("expected an error for %v", args)
			}
		})
	}
}

// TestCAExtensionFileMergesUnderFlags checks -ca-ext-file carries a whole
// configuration and that the named flags override or extend it, which is what
// lets a ceremony keep its extension set in version control.
func TestCAExtensionFileMergesUnderFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.json")
	if err := os.WriteFile(path, []byte(`{
  "ext_key_usages": ["serverAuth"],
  "ca_repositories": ["http://pki.example.test/certs/"],
  "custom": [{"oid": "1.3.6.1.4.1.99999.200", "encoding": "ia5", "value": "from-a-file"}]
}`), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}

	// The file alone.
	cfg, err := parseExtFlags(t, "-ca-ext-file", path).extensions()
	if err != nil {
		t.Fatalf("extensions(): %v", err)
	}
	if cfg == nil || len(cfg.ExtKeyUsages) != 1 || len(cfg.Custom) != 1 {
		t.Fatalf("file-only configuration = %+v", cfg)
	}

	// A flag replaces the file's list; a URI flag appends to it.
	cfg, err = parseExtFlags(t, "-ca-ext-file", path,
		"-eku", "clientAuth", "-ca-repository-url", "http://other.example.test/",
		"-ext", "1.3.6.1.4.1.99999.201:utf8:from-a-flag").extensions()
	if err != nil {
		t.Fatalf("extensions(): %v", err)
	}
	if len(cfg.ExtKeyUsages) != 1 || cfg.ExtKeyUsages[0] != "clientAuth" {
		t.Errorf("EKUs = %v, want the flag to replace the file's list", cfg.ExtKeyUsages)
	}
	if len(cfg.CARepositories) != 2 {
		t.Errorf("caRepositories = %v, want the flag appended to the file's", cfg.CARepositories)
	}
	if len(cfg.Custom) != 2 {
		t.Errorf("custom = %+v, want the file's and the flag's", cfg.Custom)
	}

	// An unknown field in the file is a typo, not something to ignore.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"must_stapel": true}`), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	if _, err := parseExtFlags(t, "-ca-ext-file", bad).extensions(); err == nil {
		t.Error("expected an error for an unknown field in -ca-ext-file")
	}
	if _, err := parseExtFlags(t, "-ca-ext-file", filepath.Join(dir, "absent.json")).extensions(); err == nil {
		t.Error("expected an error for a missing -ca-ext-file")
	}
}

// TestFullSubjectFlags covers the extended distinguished-name flags, including
// that a DN attribute value containing a comma is not split.
func TestFullSubjectFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder))
	s := addFullSubjectFlags(fs)
	if err := fs.Parse([]string{
		"-cn", "Example Root CA", "-o", "Example Org", "-c", "DE",
		"-subject-serial-number", "HRB 12345",
		"-street", "Hafenstrasse 1", "-postal-code", "20457",
		"-subject-email", "pki@example.test",
		"-dc", "com", "-dc", "example",
		"-dn", "organizationIdentifier=VATDE-123456789",
		"-dn", "businessCategory=Private Organization, Inc",
	}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	subj, err := s.subject()
	if err != nil {
		t.Fatalf("subject(): %v", err)
	}
	if s.cn() != "Example Root CA" || subj.CommonName != "Example Root CA" {
		t.Errorf("CN = %q / %q", s.cn(), subj.CommonName)
	}
	if subj.SerialNumber != "HRB 12345" || subj.Street != "Hafenstrasse 1" || subj.PostalCode != "20457" {
		t.Errorf("subject = %+v", subj)
	}
	if subj.EmailAddress != "pki@example.test" {
		t.Errorf("email = %q", subj.EmailAddress)
	}
	if len(subj.DomainComponents) != 2 || subj.DomainComponents[0] != "com" {
		t.Errorf("domain components = %v", subj.DomainComponents)
	}
	if len(subj.ExtraNames) != 2 {
		t.Fatalf("extra names = %+v", subj.ExtraNames)
	}
	if subj.ExtraNames[1].Value != "Private Organization, Inc" {
		t.Errorf("extra name value = %q, want the comma preserved", subj.ExtraNames[1].Value)
	}

	// A malformed -dn is reported rather than dropped.
	fs2 := flag.NewFlagSet("test", flag.ContinueOnError)
	fs2.SetOutput(new(strings.Builder))
	s2 := addFullSubjectFlags(fs2)
	if err := fs2.Parse([]string{"-cn", "x", "-dn", "noEquals"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, err := s2.subject(); err == nil {
		t.Error("expected an error for a -dn without TYPE=VALUE")
	}
}

// TestNameConstraintDirNameNotSplit is the regression guard for the flag the
// documented example never worked with: "-permit-dirname O=Acme,C=US" is one
// two-RDN subtree, which is what the flag's help text has always claimed.
func TestNameConstraintDirNameNotSplit(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder))
	c := addConstraintFlags(fs)
	if err := fs.Parse([]string{"-permit-dirname", "O=Acme,C=US", "-exclude-dirname", "O=Other,C=US"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	nc := c.nameConstraints()
	if nc == nil {
		t.Fatal("nameConstraints() returned nil")
	}
	if len(nc.Permitted.DirNames) != 1 || nc.Permitted.DirNames[0] != "O=Acme,C=US" {
		t.Errorf("permitted dirNames = %v, want one two-RDN DN", nc.Permitted.DirNames)
	}
	if len(nc.Excluded.DirNames) != 1 || nc.Excluded.DirNames[0] != "O=Other,C=US" {
		t.Errorf("excluded dirNames = %v, want one two-RDN DN", nc.Excluded.DirNames)
	}
	// The built constraints must carry both RDNs in the order written.
	built, err := nc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(built.Permitted.DirNames) != 1 {
		t.Fatalf("built dirName subtrees = %d, want 1", len(built.Permitted.DirNames))
	}
	if got := built.Permitted.DirNames[0].String(); !strings.Contains(got, "Acme") || !strings.Contains(got, "US") {
		t.Errorf("built dirName = %q, want both RDNs", got)
	}
}
