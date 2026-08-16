package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Profile is a named issuance template constraining the certificates a CA may
// mint: which key usages and extended key usages they carry, how long they are
// valid, and whether they may themselves be CAs. Profiles let an operator offer
// distinct, auditable certificate shapes (TLS server, TLS client, code signing,
// …) without callers hand-crafting extensions per request.
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// KeyUsages / ExtKeyUsages are the string identifiers understood by
	// pki.X509KeyUsageFromString / pki.X509ExtKeyUsageFromString.
	KeyUsages    []string `json:"key_usages"`
	ExtKeyUsages []string `json:"ext_key_usages"`
	// DefaultValidity is applied when a request does not specify one.
	DefaultValidity time.Duration `json:"-"`
	// MaxValidity caps the validity a request may ask for. Zero means uncapped.
	MaxValidity time.Duration `json:"-"`
	// DefaultValidityDays / MaxValidityDays mirror the durations above for JSON.
	DefaultValidityDays int `json:"default_validity_days"`
	MaxValidityDays     int `json:"max_validity_days"`
	// IsCA mints a subordinate CA certificate rather than a leaf. Reserved for
	// specialized profiles; ordinary leaf profiles leave it false.
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
	// CT is the profile's Certificate Transparency policy. Nil (or disabled)
	// means precertificate submission and SCT embedding are skipped.
	CT *CTConfig `json:"ct,omitempty"`
	// Lint is the profile's pre-issuance lint policy. Nil applies the default
	// gate (enforce mode, internal-name rules); see LintConfig.
	Lint *LintConfig `json:"lint,omitempty"`
	// CAA is the profile's DNS Certification Authority Authorization policy (RFC
	// 8659). Nil (or mode "off") disables the CAA pre-issuance gate; see CAAConfig.
	CAA *CAAConfig `json:"caa,omitempty"`
	// Policies assigns RFC 5280 certificate-policy OIDs (2.5.29.32) to every leaf
	// issued under this profile, optionally with a CPS-URI qualifier and policy
	// mappings. Empty emits no certificatePolicies extension. See certpolicy.
	Policies *certpolicy.PolicyConfig `json:"policies,omitempty"`
	// SMIME marks this as an S/MIME (emailProtection) profile: rfc822Name SANs
	// are validated, normalized, and allowlist-checked before signing, and the
	// CA/B Forum S/MIME Baseline Requirements lint rules apply. See SMIMEConfig.
	SMIME *SMIMEConfig `json:"smime,omitempty"`
	// UPN marks this as a Microsoft smartcard-logon / Kerberos PKINIT profile:
	// User Principal Name (id-ms-UPN) otherName SANs are validated and checked
	// against the profile/tenant realm allowlists before signing. Its presence is
	// what permits a leaf under this profile to carry a UPN SAN at all. See
	// UPNConfig.
	UPN *UPNConfig `json:"upn,omitempty"`
	// KeyChecks is the profile's pre-issuance key-quality policy (Task 120,
	// CA/Browser Forum BR §6.1.1.3): the fail-closed weak-key (ROCA / exponent /
	// modulus / Debian) and compromised-key (operator blocklist / reused-subject)
	// gate. Nil applies the default (enforce mode, standard structural checks +
	// blocklist); see KeyCheckConfig.
	KeyChecks *KeyCheckConfig `json:"key_checks,omitempty"`

	// QCStatements assigns EU qualified-certificate semantics (eIDAS / ETSI EN
	// 319 412-5) to every leaf issued under this profile: the non-critical
	// id-pe-qcStatements extension (OID 1.3.6.1.5.5.7.1.3) carrying QcCompliance,
	// QcType, QcSSCD, QcRetentionPeriod, QcPDS, and/or the ETSI TS 119 495 PSD2
	// QcStatement. Nil emits no such extension. See QCStatementsConfig.
	QCStatements *QCStatementsConfig `json:"qcstatements,omitempty"`

	// PrivateKeyUsagePeriod stamps the RFC 5280 id-ce-privateKeyUsagePeriod
	// extension (OID 2.5.29.16) on every leaf issued under this profile: the window
	// during which the certified private key may be used to produce signatures,
	// which can be narrower than the certificate's own validity. It pairs naturally
	// with signing profiles (the qualified-* profiles, code-signing). Nil emits no
	// such extension. See PrivateKeyUsagePeriodConfig.
	PrivateKeyUsagePeriod *PrivateKeyUsagePeriodConfig `json:"private_key_usage_period,omitempty"`

	// MustStaple stamps the RFC 7633 TLS Feature / OCSP Must-Staple extension
	// (id-pe-tlsfeature, OID 1.3.6.1.5.5.7.1.24) on every leaf issued under this
	// profile: a non-critical SEQUENCE OF INTEGER containing status_request(5).
	// A relying party that honors it must abort a TLS handshake in which the
	// server does not staple a valid OCSP response, so the certificate cannot be
	// used soft-fail. It is opt-in and typically paired with a serverAuth profile.
	MustStaple bool `json:"must_staple,omitempty"`
	// AllowMustStapleOverride lets an operator/API issue request override the
	// profile's MustStaple default per certificate (turning it on or off). When
	// false the profile default is authoritative and any per-request value is
	// ignored — the "where policy permits" gate on the override.
	AllowMustStapleOverride bool `json:"allow_must_staple_override,omitempty"`

	// DelegationUsage stamps the RFC 9345 id-ce-delegationUsage extension
	// (OID 1.3.6.1.4.1.44363.44; a non-critical NULL) on every leaf issued under
	// this profile, marking it eligible to authorize TLS Delegated Credentials: the
	// certified key may sign short-lived DelegatedCredential structures that
	// authenticate TLS 1.3 handshakes on its behalf (see internal/delegatedcred).
	// It is opt-in and pairs with a serverAuth profile. RFC 9345 §4.2 requires the
	// digitalSignature key usage and forbids combining the marker with the RFC 7633
	// OCSP Must-Staple commitment; SetCustomProfiles enforces both statically and
	// the issuance path enforces the mutual exclusion fail-closed (see
	// applyDelegationUsage).
	DelegationUsage bool `json:"delegation_usage,omitempty"`

	// Algorithm selects the signature scheme family for certificates issued under
	// this profile: classical (default), pure post-quantum ML-DSA, or hybrid
	// (classical primary + ML-DSA alternative signature). See the pqc package.
	Algorithm CertAlgorithm `json:"algorithm,omitempty"`
	// PQCKeyType is the ML-DSA parameter set used for the post-quantum key: the
	// subject key for a pqc profile, or the alternative key for a hybrid profile.
	// Empty defaults to ml-dsa-65. Ignored for classical profiles.
	PQCKeyType string `json:"pqc_key_type,omitempty"`

	// RequireApproval routes operator/API-driven leaf issuance under this profile
	// through the four-eyes / maker-checker approval gate (Task 84) instead of
	// issuing immediately: the request is parked for a configurable number of
	// distinct approvers, and the certificate is delivered only once the threshold
	// is met. Enterprises use it for high-assurance, wildcard, or otherwise
	// sensitive profiles. It gates only operator/API issuance (the REST and gRPC
	// IssueCertificate paths); automated protocol flows (ACME/EST/SCEP/CMP), which
	// enroll machines, deliberately bypass the manual gate. Enforcement also
	// requires the approvals engine to be enabled and the cert.issue class guarded
	// (see approvals.enabled / approvals.thresholds); when the gate is disabled the
	// flag is inert and issuance proceeds immediately.
	RequireApproval bool `json:"require_approval,omitempty"`
}

// CertAlgorithm names the signature scheme family a profile issues under.
type CertAlgorithm string

const (
	// AlgClassical issues ordinary ECDSA/RSA/Ed25519 certificates. It is the
	// zero value, so profiles that omit Algorithm remain classical.
	AlgClassical CertAlgorithm = ""
	// AlgPQC issues pure post-quantum certificates: the subject key and issuer
	// signature are both ML-DSA. Requires an ML-DSA issuing CA and the software
	// key provider (SoftHSM has no ML-DSA mechanism).
	AlgPQC CertAlgorithm = "pqc"
	// AlgHybrid issues catalyst hybrid certificates: a classical primary key and
	// signature plus a parallel ML-DSA key and signature carried in the
	// alternative-signature extensions. Requires a hybrid issuing CA.
	AlgHybrid CertAlgorithm = "hybrid"
)

// defaultPQCKeyType is the ML-DSA parameter set used when a PQC/hybrid profile
// does not name one. ML-DSA-65 (NIST security category 3) is a balanced default.
const defaultPQCKeyType = "ml-dsa-65"

// pqcKeyType returns the profile's effective ML-DSA parameter set.
func (p Profile) pqcKeyType() string {
	if p.PQCKeyType != "" {
		return p.PQCKeyType
	}
	return defaultPQCKeyType
}

// resolveMustStaple returns the effective RFC 7633 Must-Staple decision for one
// issuance. A non-nil override (from the REST/gRPC issue request) wins only when
// the profile allows per-request overrides; otherwise the profile default holds.
func (p Profile) resolveMustStaple(override *bool) bool {
	if override != nil && p.AllowMustStapleOverride {
		return *override
	}
	return p.MustStaple
}

// day is a convenience unit for profile validity periods.
const day = 24 * time.Hour

// builtinProfiles are the certificate profiles available out of the box. They
// are keyed by (lowercase) name.
var builtinProfiles = map[string]Profile{
	"server": {
		Name:            "server",
		Description:     "TLS server certificate (serverAuth)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 397 * day, // CA/Browser Forum maximum for TLS leaves
		MaxValidity:     397 * day,
	},
	"client": {
		Name:            "client",
		Description:     "TLS client / mTLS certificate (clientAuth)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"clientAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
	},
	"server-client": {
		Name:            "server-client",
		Description:     "Dual-purpose TLS certificate (serverAuth + clientAuth)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth", "clientAuth"},
		DefaultValidity: 397 * day,
		MaxValidity:     397 * day,
	},
	// server-muststaple is server with the RFC 7633 OCSP Must-Staple commitment
	// (id-pe-tlsfeature: status_request) stamped on every leaf, so the certificate
	// cannot be used without a stapled OCSP response. It permits a per-request
	// override so an operator can opt an individual certificate out (e.g. for a
	// host that cannot yet staple) without defining a second profile.
	"server-muststaple": {
		Name:                    "server-muststaple",
		Description:             "TLS server certificate with OCSP Must-Staple (RFC 7633 status_request)",
		KeyUsages:               []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:            []string{"serverAuth"},
		DefaultValidity:         397 * day,
		MaxValidity:             397 * day,
		MustStaple:              true,
		AllowMustStapleOverride: true,
	},
	// server-delegation is server marked eligible to authorize RFC 9345 TLS
	// Delegated Credentials: every leaf carries the non-critical
	// id-ce-delegationUsage extension, so its key may sign short-lived delegated
	// credentials for a front end without that front end holding the certificate
	// key (see internal/delegatedcred and `secsy-ca delegated-credential`).
	// digitalSignature is present as RFC 9345 §4.2 requires; the profile
	// deliberately cannot also be OCSP Must-Staple (§4.2 forbids the combination).
	"server-delegation": {
		Name:            "server-delegation",
		Description:     "TLS server certificate eligible to authorize RFC 9345 delegated credentials (DelegationUsage)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 397 * day,
		MaxValidity:     397 * day,
		DelegationUsage: true,
	},
	"code-signing": {
		Name:            "code-signing",
		Description:     "Code-signing certificate (codeSigning)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"codeSigning"},
		DefaultValidity: 3 * 365 * day,
		MaxValidity:     3 * 365 * day,
	},
	// email predates the first-class S/MIME profiles below and is kept for
	// backward compatibility. New deployments should prefer smime / smime-sign /
	// smime-encrypt, which validate and normalize mailbox addresses and enforce
	// the CA/B Forum S/MIME Baseline Requirements.
	"email": {
		Name:            "email",
		Description:     "S/MIME e-mail protection certificate (emailProtection; legacy — prefer the smime profiles)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"emailProtection"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
	},
	// The smime profile family issues mailbox-validated e-mail protection
	// certificates per the CA/B Forum S/MIME Baseline Requirements
	// (multipurpose class by default). smime is single-key dual-use; the
	// sign/encrypt pair splits the usages so the encryption key can be escrowed
	// (see internal/secret escrow, Task 33) without ever escrowing a signing
	// key. The dual-use and encryption profiles expect RSA subject keys
	// (keyEncipherment); EC (ECDH keyAgreement) encryption is not offered as a
	// built-in — define a custom profile with key_usages: [keyAgreement] for
	// that. Validity stays well inside the 825-day multipurpose cap.
	"smime": {
		Name:            "smime",
		Description:     "S/MIME dual-use certificate (sign + encrypt, single RSA key)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"emailProtection"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
		SMIME:           &SMIMEConfig{Variant: "dual"},
	},
	"smime-sign": {
		Name:            "smime-sign",
		Description:     "S/MIME signing-only certificate (digitalSignature)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"emailProtection"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
		SMIME:           &SMIMEConfig{Variant: "sign"},
	},
	"smime-encrypt": {
		Name:            "smime-encrypt",
		Description:     "S/MIME encryption-only certificate (keyEncipherment, RSA)",
		KeyUsages:       []string{"keyEncipherment"},
		ExtKeyUsages:    []string{"emailProtection"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
		SMIME:           &SMIMEConfig{Variant: "encrypt"},
	},
	"pqc-server": {
		Name:            "pqc-server",
		Description:     "Pure post-quantum TLS server certificate (ML-DSA subject key + ML-DSA signature)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     397 * day,
		Algorithm:       AlgPQC,
		PQCKeyType:      "ml-dsa-65",
	},
	// spiffe-svid mints SPIFFE X.509-SVID workload identities: a single spiffe://
	// URI SAN as the sole identity (no CN reliance, no DNS/IP SAN by default),
	// CA:false, key usage digitalSignature, and serverAuth+clientAuth EKUs for
	// mutual TLS. SVIDs are deliberately short-lived and auto-renewed aggressively
	// by the expiry monitor; see internal/spiffe and docs/certificates/spiffe.md.
	"spiffe-svid": {
		Name:            "spiffe-svid",
		Description:     "SPIFFE X.509-SVID workload identity (spiffe:// URI SAN, short-lived)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth", "clientAuth"},
		DefaultValidity: time.Hour,
		MaxValidity:     24 * time.Hour,
	},
	// smartcard-logon issues Microsoft Windows smartcard-logon certificates for
	// Active Directory: a User Principal Name (user@REALM) in an id-ms-UPN
	// otherName SAN, the id-ms-smartcardLogon (1.3.6.1.4.1.311.20.2.2) EKU
	// alongside id-kp-clientAuth for interoperable client authentication, and
	// keyUsage digitalSignature. The UPN is validated and realm-allowlist-checked
	// before signing (see UPNConfig); require_upn makes an omitted UPN a hard
	// error, since a smartcard-logon certificate is useless without one.
	"smartcard-logon": {
		Name:            "smartcard-logon",
		Description:     "Microsoft smartcard-logon certificate (UPN otherName SAN + msSmartcardLogon/clientAuth EKU)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"clientAuth", "msSmartcardLogon"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
		UPN:             &UPNConfig{RequireUPN: true},
	},
	// pkinit-client issues Kerberos PKINIT client-authentication certificates
	// (RFC 4556): a UPN otherName SAN plus the id-pkinit-KPClientAuth
	// (1.3.6.1.5.2.3.4) EKU alongside id-kp-clientAuth, keyUsage digitalSignature.
	"pkinit-client": {
		Name:            "pkinit-client",
		Description:     "Kerberos PKINIT client-authentication certificate (UPN otherName SAN + pkinitClientAuth/clientAuth EKU)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"clientAuth", "pkinitClientAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
		UPN:             &UPNConfig{RequireUPN: true},
	},
	// smartcard-pkinit is a combined profile carrying both the Microsoft
	// smartcard-logon and the Kerberos PKINIT client-auth EKUs, for a single
	// credential usable against both a Windows KDC and an MIT/Heimdal KDC.
	"smartcard-pkinit": {
		Name:            "smartcard-pkinit",
		Description:     "Combined smartcard-logon + Kerberos PKINIT client certificate (UPN SAN + msSmartcardLogon/pkinitClientAuth/clientAuth EKU)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"clientAuth", "msSmartcardLogon", "pkinitClientAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
		UPN:             &UPNConfig{RequireUPN: true},
	},
	"hybrid-server": {
		Name:            "hybrid-server",
		Description:     "Hybrid TLS server certificate (classical primary + ML-DSA alternative signature)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth", "clientAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     397 * day,
		Algorithm:       AlgHybrid,
		PQCKeyType:      "ml-dsa-65",
	},
	// The qualified-* profiles issue EU qualified certificates (eIDAS, Regulation
	// (EU) No 910/2014) carrying the ETSI EN 319 412-5 id-pe-qcStatements
	// extension. qualified-esign is a Qualified Certificate for Electronic
	// Signature (natural person): keyUsage contentCommitment (non-repudiation),
	// asserting QcCompliance, QcType=esign, and QcSSCD (key in a QSCD).
	"qualified-esign": {
		Name:            "qualified-esign",
		Description:     "eIDAS qualified certificate for electronic signature (QcCompliance + QcType esign + QcSSCD)",
		KeyUsages:       []string{"contentCommitment"},
		DefaultValidity: 3 * 365 * day,
		MaxValidity:     3 * 365 * day,
		QCStatements: &QCStatementsConfig{
			Compliance: true,
			Type:       "esign",
			SSCD:       true,
		},
		// A qualified electronic-signature key is the classic case for an RFC 5280
		// private-key usage period (the signing key retires before the certificate
		// expires while signatures it already made stay verifiable). No default
		// window is imposed — the deployment supplies one per request (-pkup) where
		// its policy requires it (Task 132).
		PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{AllowOverride: true},
	},
	// qualified-eseal is a Qualified Certificate for Electronic Seal (legal
	// person): the same shape as qualified-esign with QcType=eseal.
	"qualified-eseal": {
		Name:            "qualified-eseal",
		Description:     "eIDAS qualified certificate for electronic seal (QcCompliance + QcType eseal + QcSSCD)",
		KeyUsages:       []string{"contentCommitment"},
		DefaultValidity: 3 * 365 * day,
		MaxValidity:     3 * 365 * day,
		QCStatements: &QCStatementsConfig{
			Compliance: true,
			Type:       "eseal",
			SSCD:       true,
		},
		// Per-request private-key usage period, as for qualified-esign (Task 132).
		PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{AllowOverride: true},
	},
	// qualified-web is a Qualified Website Authentication Certificate (QWAC): a
	// TLS serverAuth leaf asserting QcCompliance and QcType=web. It permits a
	// per-request PSD2 QcStatement override (ETSI TS 119 495) so a single profile
	// can serve payment service providers whose roles and authorizing NCA differ
	// per certificate.
	"qualified-web": {
		Name:            "qualified-web",
		Description:     "eIDAS qualified website-authentication certificate / QWAC (QcCompliance + QcType web; PSD2 override permitted)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth", "clientAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     397 * day,
		QCStatements: &QCStatementsConfig{
			Compliance:        true,
			Type:              "web",
			AllowPSD2Override: true,
		},
	},
	// canary is the dedicated profile for the synthetic issuance canary
	// (internal/canary, Task 71). Its certificates are short-lived operational
	// self-test artifacts: minted, chain/OCSP/CRL-checked, and revoked within a
	// single probe. The profile is deliberately non-public (internal names like
	// secsy-canary.invalid must lint cleanly) with the lint gate pinned to
	// enforce mode, so every probe also proves the fail-closed lint path. The
	// prober stamps its records with models.CertMarkerCanary, which keeps them
	// out of expiry monitoring and inventory reports; tenant scoping follows the
	// probed CA through the ordinary issuance gate.
	"canary": {
		Name:            "canary",
		Description:     "Synthetic issuance-canary probe certificate (short-lived, internal-only, revoked after each probe)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"clientAuth"},
		DefaultValidity: time.Hour,
		MaxValidity:     24 * time.Hour,
		Lint:            &LintConfig{Mode: "enforce"},
	},
}

// defaultProfileName is used when a request omits the profile.
const defaultProfileName = "server"

// customProfiles holds operator-defined profiles installed from central
// configuration via SetCustomProfiles. They layer over the built-ins: a custom
// profile with the same (lowercase) name as a built-in overrides it. This lets
// deployments add issuance shapes or tighten validity without a code change.
// Set once at startup before serving, so no locking is required for reads.
var customProfiles = map[string]Profile{}

// SetCustomProfiles validates and installs operator-defined profiles. Each
// profile must have a name and reference only known key usages / extended key
// usages. It is intended to be called once during initialization; calling it
// again replaces the previous custom set.
func SetCustomProfiles(profiles []Profile) error {
	next := make(map[string]Profile, len(profiles))
	for _, p := range profiles {
		if p.Name == "" {
			return fmt.Errorf("custom profile: name is required")
		}
		key := normalizeProfileName(p.Name)
		if _, dup := next[key]; dup {
			return fmt.Errorf("custom profile %q: duplicate name", p.Name)
		}
		// Fold day-based validity (from config) into durations if the caller only
		// supplied days, then validate the usage identifiers eagerly.
		if p.DefaultValidity == 0 && p.DefaultValidityDays > 0 {
			p.DefaultValidity = time.Duration(p.DefaultValidityDays) * day
		}
		if p.MaxValidity == 0 && p.MaxValidityDays > 0 {
			p.MaxValidity = time.Duration(p.MaxValidityDays) * day
		}
		if _, err := p.keyUsage(); err != nil {
			return err
		}
		if _, _, err := p.extKeyUsage(); err != nil {
			return err
		}
		if p.SMIME != nil {
			if err := p.SMIME.validate(p.Name); err != nil {
				return err
			}
		}
		if p.UPN != nil {
			if err := p.UPN.validate(p.Name); err != nil {
				return err
			}
		}
		if p.QCStatements != nil {
			if err := p.QCStatements.validate(p.Name); err != nil {
				return err
			}
		}
		if p.PrivateKeyUsagePeriod != nil {
			if err := p.PrivateKeyUsagePeriod.validate(p.Name); err != nil {
				return err
			}
		}
		// RFC 9345 delegated-credential eligibility. §4.2 forbids combining the
		// DelegationUsage marker with the RFC 7633 OCSP Must-Staple TLS Feature, so
		// reject a profile that could ever produce both — including one that merely
		// permits a per-request Must-Staple override — making the combination
		// statically impossible. §4.2 also requires the authorizing certificate to
		// carry the digitalSignature key usage.
		if p.DelegationUsage {
			if p.MustStaple || p.AllowMustStapleOverride {
				return fmt.Errorf("custom profile %q: delegation_usage cannot be combined with must_staple or allow_must_staple_override (RFC 9345 §4.2 forbids OCSP Must-Staple on a delegated-credential-eligible certificate)", p.Name)
			}
			ku, _ := p.keyUsage() // already validated above
			if ku&x509.KeyUsageDigitalSignature == 0 {
				return fmt.Errorf("custom profile %q: delegation_usage requires the digitalSignature key usage (RFC 9345 §4.2)", p.Name)
			}
		}
		// Under the FIPS policy a PQC/hybrid profile is refused at install time so
		// the misconfiguration surfaces at startup, not at the first issuance.
		if fips.PolicyEnforced() && p.Algorithm != AlgClassical {
			return fmt.Errorf("custom profile %q: algorithm %q is %w", p.Name, p.Algorithm, fips.ErrNotApproved)
		}
		next[key] = p
	}
	customProfiles = next
	return nil
}

// LookupProfile resolves a profile by name (case-insensitive), preferring a
// custom profile over a built-in of the same name. When name is empty the
// default profile is returned.
func LookupProfile(name string) (Profile, error) {
	if name == "" {
		name = defaultProfileName
	}
	key := normalizeProfileName(name)
	if p, ok := customProfiles[key]; ok {
		p.fillValidityDays()
		return p, nil
	}
	p, ok := builtinProfiles[key]
	if !ok {
		return Profile{}, fmt.Errorf("unknown certificate profile %q (available: %v)", name, ProfileNames())
	}
	p.fillValidityDays()
	return p, nil
}

// mergedProfiles returns the effective profile set: built-ins overlaid with any
// custom profiles.
func mergedProfiles() map[string]Profile {
	out := make(map[string]Profile, len(builtinProfiles)+len(customProfiles))
	for k, v := range builtinProfiles {
		out[k] = v
	}
	for k, v := range customProfiles {
		out[k] = v
	}
	return out
}

// Profiles returns every effective profile (built-in + custom), sorted by name.
func Profiles() []Profile {
	merged := mergedProfiles()
	out := make([]Profile, 0, len(merged))
	for _, p := range merged {
		p.fillValidityDays()
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProfileNames returns the sorted list of effective profile names.
func ProfileNames() []string {
	merged := mergedProfiles()
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func normalizeProfileName(name string) string {
	return name // names are already stored lowercase; kept for a single choke point
}

// fillValidityDays populates the *Days JSON fields from the durations.
func (p *Profile) fillValidityDays() {
	p.DefaultValidityDays = int(p.DefaultValidity / day)
	p.MaxValidityDays = int(p.MaxValidity / day)
}

// keyUsage resolves the profile's string key usages to an x509 bitmask.
func (p Profile) keyUsage() (x509.KeyUsage, error) {
	var ku x509.KeyUsage
	for _, s := range p.KeyUsages {
		v, ok := pki.X509KeyUsageFromString[s]
		if !ok {
			return 0, fmt.Errorf("profile %q references unknown key usage %q", p.Name, s)
		}
		ku |= v
	}
	return ku, nil
}

// extKeyUsage resolves the profile's string extended key usages into the
// crypto/x509 enum constants plus the OIDs of usages crypto/x509 has no constant
// for (the Microsoft smartcard-logon and Kerberos PKINIT client-auth EKUs). The
// two sets are recombined into a single extKeyUsage extension by
// x509.CreateCertificate.
func (p Profile) extKeyUsage() ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	known := make([]x509.ExtKeyUsage, 0, len(p.ExtKeyUsages))
	var unknown []asn1.ObjectIdentifier
	for _, s := range p.ExtKeyUsages {
		if v, ok := pki.X509ExtKeyUsageFromString[s]; ok {
			known = append(known, v)
			continue
		}
		if oid, ok := pki.X509ExtKeyUsageOIDFromString[s]; ok {
			unknown = append(unknown, oid)
			continue
		}
		return nil, nil, fmt.Errorf("profile %q references unknown extended key usage %q", p.Name, s)
	}
	return known, unknown, nil
}

// policyExtensions builds the certificate-policy extensions (certificatePolicies,
// and any configured policy mappings/constraints) a leaf issued under this
// profile should carry. It returns nil when the profile assigns no policies.
func (p Profile) policyExtensions() ([]pkix.Extension, error) {
	if p.Policies == nil || p.Policies.IsZero() {
		return nil, nil
	}
	built, err := p.Policies.Build()
	if err != nil {
		return nil, fmt.Errorf("profile %q certificate policies: %w", p.Name, err)
	}
	exts, err := built.Extensions()
	if err != nil {
		return nil, fmt.Errorf("profile %q certificate policies: %w", p.Name, err)
	}
	return exts, nil
}

// resolveValidity clamps a requested validity to the profile's bounds. A
// non-positive request falls back to the profile default.
func (p Profile) resolveValidity(requested time.Duration) time.Duration {
	if requested <= 0 {
		requested = p.DefaultValidity
	}
	if p.MaxValidity > 0 && requested > p.MaxValidity {
		requested = p.MaxValidity
	}
	return requested
}
