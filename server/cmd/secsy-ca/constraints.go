package main

import (
	"flag"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
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

// constraintFlags groups the CLI flags that configure a CA's Name Constraints
// (2.5.29.30) and certificate-policy family (2.5.29.32/.33/.36) extensions.
type constraintFlags struct {
	permitDNS, excludeDNS     multiFlag
	permitIP, excludeIP       multiFlag
	permitEmail, excludeEmail multiFlag
	permitURI, excludeURI     multiFlag
	permitDir, excludeDir     multiFlag

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
