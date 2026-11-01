package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/caext"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
)

// multiFlag collects a repeatable string flag (e.g. -permit-dns a -permit-dns b).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	// Also accept a single comma-separated value for convenience.
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

// Flags whose value legitimately contains a comma — a distinguished name
// ("O=Acme,C=US"), an extension value, a subject attribute — use rawMultiFlag
// (declared next to the role-mapping command, which needs it for group DNs)
// rather than multiFlag. The comma-splitting convenience above is a trap for
// exactly those: a two-RDN DN silently became two one-RDN DNs.

// constraintFlags groups the CLI flags that configure a CA's Name Constraints
// (2.5.29.30) and certificate-policy family (2.5.29.32/.33/.36) extensions.
type constraintFlags struct {
	permitDNS, excludeDNS     multiFlag
	permitIP, excludeIP       multiFlag
	permitEmail, excludeEmail multiFlag
	permitURI, excludeURI     multiFlag
	// A directoryName subtree contains commas, so it uses the non-splitting
	// flag: "O=Acme,C=US" is one two-RDN subtree, not two one-RDN subtrees.
	permitDir, excludeDir rawMultiFlag

	policyOIDs      multiFlag
	policyMappings  multiFlag
	policyCPS       *string
	requireExplicit *int
	inhibitMapping  *int
}

// addConstraintFlags registers the name-constraint and certificate-policy flags
// on a flag set (shared by init-root and issue-intermediate).
func addConstraintFlags(fs *flag.FlagSet) *constraintFlags {
	c := &constraintFlags{}
	fs.Var(&c.permitDNS, "permit-dns", "permitted DNS name subtree (repeatable, e.g. internal.example.com)")
	fs.Var(&c.excludeDNS, "exclude-dns", "excluded DNS name subtree (repeatable)")
	fs.Var(&c.permitIP, "permit-ip", "permitted IP subtree in CIDR (repeatable, e.g. 10.0.0.0/8)")
	fs.Var(&c.excludeIP, "exclude-ip", "excluded IP subtree in CIDR (repeatable)")
	fs.Var(&c.permitEmail, "permit-email", "permitted e-mail subtree (repeatable, e.g. example.com or .example.com)")
	fs.Var(&c.excludeEmail, "exclude-email", "excluded e-mail subtree (repeatable)")
	fs.Var(&c.permitURI, "permit-uri", "permitted URI host subtree (repeatable)")
	fs.Var(&c.excludeURI, "exclude-uri", "excluded URI host subtree (repeatable)")
	fs.Var(&c.permitDir, "permit-dirname", "permitted directoryName subtree as an RFC 4514 DN (repeatable, e.g. O=Acme,C=US)")
	fs.Var(&c.excludeDir, "exclude-dirname", "excluded directoryName subtree (repeatable)")

	fs.Var(&c.policyOIDs, "policy-oid", "certificate-policy OID to assert (repeatable; 'anyPolicy' accepted)")
	fs.Var(&c.policyMappings, "policy-mapping", "policy mapping issuerOID:subjectOID (repeatable)")
	c.policyCPS = fs.String("policy-cps", "", "CPS URI qualifier applied to every -policy-oid")
	c.requireExplicit = fs.Int("require-explicit-policy", -1, "policyConstraints requireExplicitPolicy skipCerts (-1 = unset)")
	c.inhibitMapping = fs.Int("inhibit-policy-mapping", -1, "policyConstraints inhibitPolicyMapping skipCerts (-1 = unset)")
	return c
}

// nameConstraints returns the configured Name Constraints, or nil when none of
// the subtree flags were set.
func (c *constraintFlags) nameConstraints() *nameconstraints.Config {
	cfg := &nameconstraints.Config{
		Permitted: nameconstraints.SubtreeConfig{
			DNS: c.permitDNS, IP: c.permitIP, Email: c.permitEmail, URI: c.permitURI, DirNames: c.permitDir,
		},
		Excluded: nameconstraints.SubtreeConfig{
			DNS: c.excludeDNS, IP: c.excludeIP, Email: c.excludeEmail, URI: c.excludeURI, DirNames: c.excludeDir,
		},
	}
	if cfg.IsZero() {
		return nil
	}
	return cfg
}

// policies returns the configured certificate-policy settings, or nil when no
// policy flags were set.
func (c *constraintFlags) policies() *certpolicy.PolicyConfig {
	cfg := &certpolicy.PolicyConfig{
		OIDs:     c.policyOIDs,
		Mappings: c.policyMappings,
		CPS:      *c.policyCPS,
	}
	if *c.requireExplicit >= 0 {
		v := *c.requireExplicit
		cfg.RequireExplicitPolicy = &v
	}
	if *c.inhibitMapping >= 0 {
		v := *c.inhibitMapping
		cfg.InhibitPolicyMapping = &v
	}
	if cfg.IsZero() {
		return nil
	}
	return cfg
}

// buildSpecConstraints resolves both configs into the built types the CA manager
// consumes, mirroring the server handler.
func (c *constraintFlags) build() (nameconstraints.Constraints, certpolicy.Policies, error) {
	var nc nameconstraints.Constraints
	var pol certpolicy.Policies
	if ncCfg := c.nameConstraints(); ncCfg != nil {
		var err error
		if nc, err = ncCfg.Build(); err != nil {
			return nc, pol, err
		}
	}
	if polCfg := c.policies(); polCfg != nil {
		var err error
		if pol, err = polCfg.Build(); err != nil {
			return nc, pol, err
		}
	}
	return nc, pol, nil
}

// -----------------------------------------------------------------------------
// The wider CA extension set (Task 222)
// -----------------------------------------------------------------------------

// caExtFlags groups the CLI flags that configure the rest of a CA certificate's
// X.509 v3 extension set — everything beyond the Name Constraints and
// certificate policies above. The two are registered together by
// addCAExtensionFlags and resolved together by build.
//
// The named flags cover what an operator reaches for; -ca-ext-file reaches the
// whole caext.Config as JSON (and is merged under the flags, which win), so a
// configuration too elaborate to type — a dozen custom extensions, an otherName
// with a hand-built DER value — can be kept in version control next to the
// ceremony script that applies it.
type caExtFlags struct {
	keyUsages    multiFlag
	extKeyUsages multiFlag
	ekuCritical  *bool

	sanDNS, sanIP, sanEmail, sanURI, sanUPN multiFlag
	sanRegisteredIDs                        multiFlag
	// A directoryName and an otherName value may contain commas.
	sanDirNames, sanOtherNames rawMultiFlag
	sanCritical                *bool
	ianURI, ianDNS, ianEmail   multiFlag

	crlDPs, freshestCRL           multiFlag
	ocspServers, caIssuers        multiFlag
	caRepositories, timestampURLs multiFlag

	inhibitAnyPolicy *int
	pkupDuration     *string
	pkupFraction     *float64

	mustStaple       *bool
	ocspNoCheck      *bool
	netscapeComment  *string
	netscapeCertType multiFlag
	subjectKeyID     *string

	// An extension value and a directory-attribute value may contain commas.
	custom   rawMultiFlag
	dirAttrs rawMultiFlag
	extFile  *string
}

// addCAExtensionFlags registers the extension flags on a flag set, shared by
// init-root, issue-intermediate and external-csr.
func addCAExtensionFlags(fs *flag.FlagSet) *caExtFlags {
	c := &caExtFlags{}
	fs.Var(&c.keyUsages, "key-usage", "CA key usage (repeatable; default certSign,crlSign,digitalSignature; certSign is required)")
	fs.Var(&c.extKeyUsages, "eku", "extended key usage constraining the subtree (repeatable; a name such as serverAuth or a dotted OID)")
	c.ekuCritical = fs.Bool("eku-critical", false, "mark the extKeyUsage extension critical")

	fs.Var(&c.sanDNS, "san-dns", "subjectAltName dNSName on the CA certificate (repeatable)")
	fs.Var(&c.sanIP, "san-ip", "subjectAltName iPAddress (repeatable)")
	fs.Var(&c.sanEmail, "san-email", "subjectAltName rfc822Name (repeatable)")
	fs.Var(&c.sanURI, "san-uri", "subjectAltName uniformResourceIdentifier (repeatable)")
	fs.Var(&c.sanUPN, "san-upn", "subjectAltName id-ms-UPN otherName (repeatable)")
	fs.Var(&c.sanDirNames, "san-dirname", "subjectAltName directoryName as a DN (repeatable, e.g. O=Acme,C=US)")
	fs.Var(&c.sanRegisteredIDs, "san-registered-id", "subjectAltName registeredID as a dotted OID (repeatable)")
	fs.Var(&c.sanOtherNames, "san-othername", "subjectAltName otherName as OID:encoding:value (repeatable)")
	c.sanCritical = fs.Bool("san-critical", false, "mark the subjectAltName extension critical")
	fs.Var(&c.ianURI, "ian-uri", "issuerAltName uniformResourceIdentifier (repeatable)")
	fs.Var(&c.ianDNS, "ian-dns", "issuerAltName dNSName (repeatable)")
	fs.Var(&c.ianEmail, "ian-email", "issuerAltName rfc822Name (repeatable)")

	fs.Var(&c.crlDPs, "crl-url", "cRLDistributionPoints URI for this certificate (repeatable)")
	fs.Var(&c.freshestCRL, "delta-crl-url", "freshestCRL (delta CRL) URI (repeatable)")
	fs.Var(&c.ocspServers, "ocsp-url", "authorityInfoAccess id-ad-ocsp URI (repeatable)")
	fs.Var(&c.caIssuers, "ca-issuer-url", "authorityInfoAccess id-ad-caIssuers URI (repeatable)")
	fs.Var(&c.caRepositories, "ca-repository-url", "subjectInfoAccess id-ad-caRepository URI (repeatable)")
	fs.Var(&c.timestampURLs, "timestamp-url", "subjectInfoAccess id-ad-timeStamping URI (repeatable)")

	c.inhibitAnyPolicy = fs.Int("inhibit-any-policy", -1, "inhibitAnyPolicy skipCerts (-1 = unset)")
	c.pkupDuration = fs.String("key-usage-period", "", "privateKeyUsagePeriod length from notBefore (e.g. 180d, 1y); the key may only sign within it")
	c.pkupFraction = fs.Float64("key-usage-period-fraction", 0, "privateKeyUsagePeriod as a fraction (0,1] of the certificate's validity")

	c.mustStaple = fs.Bool("must-staple", false, "assert RFC 7633 status_request (OCSP must-staple) for the subtree")
	c.ocspNoCheck = fs.Bool("ocsp-no-check", false, "stamp id-pkix-ocsp-nocheck (delegated OCSP responder certificates)")
	c.netscapeComment = fs.String("netscape-comment", "", "legacy Netscape comment extension text")
	fs.Var(&c.netscapeCertType, "netscape-cert-type", "legacy Netscape certificate type (repeatable: sslClient, sslServer, sslCA, smime, smimeCA, objsign, objCA)")
	c.subjectKeyID = fs.String("subject-key-id", "", "explicit subject key identifier as hex (default: derived from the public key)")

	fs.Var(&c.custom, "ext", "arbitrary extension as OID[:critical]:encoding:value (repeatable), e.g. 1.3.6.1.4.1.1.1:utf8:hello")
	fs.Var(&c.dirAttrs, "subject-dir-attr", "subjectDirectoryAttributes entry as OID:encoding:value (repeatable)")
	c.extFile = fs.String("ca-ext-file", "", "JSON file holding a full CA extension set (the flags above override it)")
	return c
}

// extensions resolves the flags (merged over -ca-ext-file) into a caext.Config,
// or nil when nothing was configured, so an unconfigured command produces
// exactly the certificate it always has.
func (c *caExtFlags) extensions() (*caext.Config, error) {
	cfg := &caext.Config{}
	if path := strings.TrimSpace(*c.extFile); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading -ca-ext-file: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parsing -ca-ext-file %s: %w", path, err)
		}
	}

	if len(c.keyUsages) > 0 {
		cfg.KeyUsages = c.keyUsages
	}
	if len(c.extKeyUsages) > 0 {
		cfg.ExtKeyUsages = c.extKeyUsages
	}
	if *c.ekuCritical {
		cfg.ExtKeyUsageCritical = true
	}

	san := &caext.GeneralNamesConfig{
		DNS: c.sanDNS, IP: c.sanIP, Email: c.sanEmail, URI: c.sanURI,
		UPN: c.sanUPN, DirNames: c.sanDirNames, RegisteredIDs: c.sanRegisteredIDs,
	}
	for _, spec := range c.sanOtherNames {
		on, err := parseOtherNameFlag(spec)
		if err != nil {
			return nil, err
		}
		san.OtherNames = append(san.OtherNames, on)
	}
	if !san.IsZero() {
		san.Critical = *c.sanCritical
		cfg.SubjectAltName = san
	} else if *c.sanCritical && cfg.SubjectAltName != nil {
		cfg.SubjectAltName.Critical = true
	}
	ian := &caext.GeneralNamesConfig{DNS: c.ianDNS, Email: c.ianEmail, URI: c.ianURI}
	if !ian.IsZero() {
		cfg.IssuerAltName = ian
	}

	appendIf(&cfg.CRLDistributionPoints, c.crlDPs)
	appendIf(&cfg.FreshestCRL, c.freshestCRL)
	appendIf(&cfg.OCSPServers, c.ocspServers)
	appendIf(&cfg.CAIssuers, c.caIssuers)
	appendIf(&cfg.CARepositories, c.caRepositories)
	appendIf(&cfg.TimestampServers, c.timestampURLs)

	if *c.inhibitAnyPolicy >= 0 {
		v := *c.inhibitAnyPolicy
		cfg.InhibitAnyPolicy = &v
	}
	if d := strings.TrimSpace(*c.pkupDuration); d != "" {
		cfg.PrivateKeyUsagePeriod = &caext.PrivateKeyUsagePeriodConfig{Duration: d}
	} else if *c.pkupFraction != 0 {
		cfg.PrivateKeyUsagePeriod = &caext.PrivateKeyUsagePeriodConfig{Fraction: *c.pkupFraction}
	}

	if *c.mustStaple {
		cfg.MustStaple = true
	}
	if *c.ocspNoCheck {
		cfg.OCSPNoCheck = true
	}
	if s := strings.TrimSpace(*c.netscapeComment); s != "" {
		cfg.NetscapeComment = s
	}
	if len(c.netscapeCertType) > 0 {
		cfg.NetscapeCertType = c.netscapeCertType
	}
	if s := strings.TrimSpace(*c.subjectKeyID); s != "" {
		cfg.SubjectKeyID = s
	}

	for _, spec := range c.custom {
		ext, err := parseCustomExtensionFlag(spec)
		if err != nil {
			return nil, err
		}
		cfg.Custom = append(cfg.Custom, ext)
	}
	for _, spec := range c.dirAttrs {
		attr, err := parseDirAttrFlag(spec)
		if err != nil {
			return nil, err
		}
		cfg.SubjectDirectoryAttributes = append(cfg.SubjectDirectoryAttributes, attr)
	}

	if cfg.IsZero() {
		return nil, nil
	}
	// Compile now so a bad configuration is reported before a key is generated.
	if _, err := cfg.Build(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// appendIf appends the flag values to a list only when any were given, leaving a
// list that came from -ca-ext-file alone otherwise.
func appendIf(dst *[]string, values multiFlag) {
	if len(values) > 0 {
		*dst = append(*dst, values...)
	}
}

// parseCustomExtensionFlag parses an -ext value: OID[:critical]:encoding:value.
// The value may itself contain colons (a hex DER blob written with separators,
// a URI), so the split is bounded from the left and the remainder is the value.
func parseCustomExtensionFlag(spec string) (caext.CustomExtension, error) {
	const usage = "want OID[:critical]:encoding:value, e.g. 1.3.6.1.4.1.1.1:utf8:hello or 1.3.6.1.4.1.1.1:critical:der-hex:0500"
	parts := strings.SplitN(spec, ":", 4)
	if len(parts) < 3 {
		return caext.CustomExtension{}, fmt.Errorf("invalid -ext %q (%s)", spec, usage)
	}
	ext := caext.CustomExtension{OID: strings.TrimSpace(parts[0])}
	if strings.EqualFold(strings.TrimSpace(parts[1]), "critical") {
		if len(parts) < 4 {
			return caext.CustomExtension{}, fmt.Errorf("invalid -ext %q (%s)", spec, usage)
		}
		ext.Critical = true
		ext.Encoding = strings.TrimSpace(parts[2])
		ext.Value = parts[3]
		return ext, nil
	}
	ext.Encoding = strings.TrimSpace(parts[1])
	ext.Value = strings.Join(parts[2:], ":")
	return ext, nil
}

// parseOtherNameFlag parses a -san-othername value: OID:encoding:value.
func parseOtherNameFlag(spec string) (caext.OtherNameConfig, error) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) < 3 {
		return caext.OtherNameConfig{}, fmt.Errorf("invalid -san-othername %q (want OID:encoding:value, e.g. 1.3.6.1.4.1.1.1:utf8:marker)", spec)
	}
	return caext.OtherNameConfig{
		OID:      strings.TrimSpace(parts[0]),
		Encoding: strings.TrimSpace(parts[1]),
		Value:    parts[2],
	}, nil
}

// parseDirAttrFlag parses a -subject-dir-attr value: OID:encoding:value.
func parseDirAttrFlag(spec string) (caext.AttributeConfig, error) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) < 3 {
		return caext.AttributeConfig{}, fmt.Errorf("invalid -subject-dir-attr %q (want OID:encoding:value, e.g. 1.3.6.1.5.5.7.9.4:printable:DE)", spec)
	}
	return caext.AttributeConfig{
		OID:      strings.TrimSpace(parts[0]),
		Encoding: strings.TrimSpace(parts[1]),
		Values:   []string{parts[2]},
	}, nil
}

// -----------------------------------------------------------------------------
// The full subject distinguished name (Task 222)
// -----------------------------------------------------------------------------

// fullSubjectFlags extends the six core subject flags (-cn/-o/-ou/-c/-st/-l)
// with the rest of the distinguished-name attributes a CA DN uses, plus a
// repeatable escape hatch for any attribute at all. It is a drop-in for
// subjectFlags: subject() returns the same models.CASubject.
type fullSubjectFlags struct {
	core         subjectFlags
	serialNumber *string
	street       *string
	postalCode   *string
	email        *string
	dc           multiFlag
	// A DN attribute value may contain commas.
	extra rawMultiFlag
}

// addFullSubjectFlags registers the core subject flags and the extended set.
func addFullSubjectFlags(fs *flag.FlagSet) *fullSubjectFlags {
	s := &fullSubjectFlags{core: addSubjectFlags(fs)}
	s.serialNumber = fs.String("subject-serial-number", "", "subject serialNumber attribute (a registry number, not the certificate serial)")
	s.street = fs.String("street", "", "subject streetAddress")
	s.postalCode = fs.String("postal-code", "", "subject postalCode")
	s.email = fs.String("subject-email", "", "subject emailAddress attribute (PKCS#9, IA5String)")
	fs.Var(&s.dc, "dc", "subject domainComponent, most significant first (repeatable, e.g. -dc com -dc example)")
	fs.Var(&s.extra, "dn", "any further subject attribute as TYPE=VALUE (repeatable, e.g. organizationIdentifier=VATDE-123 or 2.5.4.15=Private Organization)")
	return s
}

// subject assembles the models.CASubject from the flags, in the order the
// attributes were given on the command line for -dn.
func (s *fullSubjectFlags) subject() (models.CASubject, error) {
	out := s.core.subject()
	out.SerialNumber = strings.TrimSpace(*s.serialNumber)
	out.Street = strings.TrimSpace(*s.street)
	out.PostalCode = strings.TrimSpace(*s.postalCode)
	out.EmailAddress = strings.TrimSpace(*s.email)
	out.DomainComponents = s.dc
	for _, spec := range s.extra {
		typ, value, ok := strings.Cut(spec, "=")
		if !ok || strings.TrimSpace(typ) == "" || strings.TrimSpace(value) == "" {
			return models.CASubject{}, fmt.Errorf("invalid -dn %q (want TYPE=VALUE, e.g. organizationIdentifier=VATDE-123)", spec)
		}
		out.ExtraNames = append(out.ExtraNames, models.CASubjectAttribute{
			Type: strings.TrimSpace(typ), Value: strings.TrimSpace(value),
		})
	}
	return out, nil
}

// cn reports the common name, which every CA command requires.
func (s *fullSubjectFlags) cn() string { return strings.TrimSpace(*s.core.cn) }
