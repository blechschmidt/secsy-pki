// Package mswstep implements the two Microsoft certificate-enrollment web
// services that drive GPO-based autoenrollment for Active-Directory-joined
// Windows machines, bridging them to the HSM-backed ca.Manager:
//
//   - MS-XCEP ([MS-XCEP], the "CEP" service): a GetPolicies SOAP endpoint that
//     advertises the certificate-enrollment policy — the set of available
//     templates (mapped from secsy-pki issuance profiles) with their OID/name,
//     key specs, validity/renewal windows, and enrollment flags, plus the issuing
//     CA and the URL of the companion enrollment ("CES") service.
//   - MS-WSTEP ([MS-WSTEP], the "CES" service): a WS-Trust RequestSecurityToken
//     (Issue) SOAP endpoint that accepts a PKCS#10 in a wsse:BinarySecurityToken,
//     resolves the requested template to a profile, issues the certificate through
//     the shared HSM-backed ca.Manager, and returns it as a certs-only PKCS#7 in
//     a RequestSecurityTokenResponse.
//
// Windows normally authenticates these services with Kerberos/NTLM against AD.
// Since that cannot be exercised without a domain, this implementation supports
// two Kerberos-free client-authentication mechanisms that thread the existing
// RBAC/tenant model: a native scoped API token (Task 86) and a mutual-TLS client
// certificate (an operator credential bound through the client-CA pool, or a
// certificate this enrollment CA previously issued — the machine-renewal path).
// Every leaf is signed through ca.Manager, so the CA key never leaves its
// provider, and issuance is subject to the same profile gates, tenant scoping,
// audit logging, and rate limiting as the other enrollment protocols.
package mswstep

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// defaultTemplateOIDArc is the base OID arc under which per-profile template OIDs
// are synthesized when an operator does not assign explicit ones. It is a
// deliberately synthetic placeholder (a reserved private-enterprise arc); a
// production deployment that must match an existing AD template OID should set
// mswstep.template_oid_arc (or per-template oid) explicitly.
const defaultTemplateOIDArc = "1.3.6.1.4.1.99999.162"

// Template maps one secsy-pki issuance profile to a Windows certificate template.
// The template is advertised by MS-XCEP GetPolicies and matched (by OID or common
// name) when an MS-WSTEP request selects it, so a Windows client can pick a
// template and have it resolve back to the profile the certificate is issued
// under.
type Template struct {
	// Profile is the secsy-pki issuance profile this template maps to (required).
	Profile string
	// Name is the template common name advertised in the policy and matched from a
	// request (the CSR's Microsoft template-name extension, or the RST context).
	// Defaults to Profile.
	Name string
	// OID is the template object identifier advertised in the policy and matched
	// from a request (the CSR's Microsoft V2 template extension). Defaults to a
	// value synthesized under the configured template OID arc.
	OID string
	// Enroll / AutoEnroll are the advertised enrollment permissions. Enroll
	// defaults to true; AutoEnroll defaults to true (GPO autoenrollment is the
	// whole point). Set AutoEnroll false to advertise a manual-enroll-only
	// template.
	Enroll     *bool
	AutoEnroll *bool
	// MinimalKeyLength is the advertised minimum subject key length in bits
	// (privateKeyAttributes.minimalKeyLength). Defaults to 2048.
	MinimalKeyLength int
	// SchemaVersion is the advertised template schema version (policySchema).
	// Defaults to 2 (Windows Server 2003+ / autoenrollment-capable).
	SchemaVersion int
	// MajorRevision is the advertised template major revision. Defaults to 100.
	MajorRevision int
}

// Config configures the Microsoft enrollment web services.
type Config struct {
	// PolicyPath is the URL the MS-XCEP GetPolicies (CEP) endpoint mounts under
	// (default "/mswstep/policy").
	PolicyPath string
	// EnrollPath is the URL the MS-WSTEP RequestSecurityToken (CES) endpoint mounts
	// under (default "/mswstep/enroll").
	EnrollPath string
	// CAID is the issuing CA (must be an X.509 issuer). It binds the services to a
	// single CA and therefore a single tenant, like the other enrollment protocols.
	CAID string
	// DefaultProfile is the issuance profile used when a request selects no
	// (recognized) template (default "client").
	DefaultProfile string
	// PolicyID is the CEP policyID advertised in GetPolicies (a stable identifier a
	// client uses to detect policy changes). Defaults to a value derived from CAID.
	PolicyID string
	// PolicyFriendlyName is the human-readable CEP policy name (default
	// "secsy-pki Certificate Enrollment Policy").
	PolicyFriendlyName string
	// NextUpdateHours is the advertised CEP refresh hint in hours (default 8).
	NextUpdateHours int
	// TemplateOIDArc is the base OID arc for synthesized template OIDs (default
	// defaultTemplateOIDArc).
	TemplateOIDArc string
	// CESEndpoint is the absolute URL of the companion MS-WSTEP (CES) enrollment
	// service, advertised to the client in the policy's CA URIs. When empty the
	// policy omits the CA URI list (the client must be configured with the CES URL
	// out of band, e.g. via GPO).
	CESEndpoint string
	// Templates maps issuance profiles to advertised/honored templates. When empty,
	// a single template is derived from DefaultProfile.
	Templates []Template

	// AllowClientCertIssuedByCA authorizes MS-WSTEP enrollment for a mutual-TLS
	// client certificate this CA previously issued (the machine-renewal path),
	// without an API token or operator credential. It is the analogue of EST's
	// allow_tls_client_reenroll.
	AllowClientCertIssuedByCA bool

	// Tokens verifies native scoped API tokens (Task 86) presented in the
	// Authorization header — the primary Kerberos-free machine-auth mechanism.
	// Nil disables token authentication.
	Tokens *authn.TokenAuthenticator
	// CertBinder resolves a mutual-TLS client certificate (verified against the
	// operator client-CA pool) to an RBAC principal. Nil disables operator-mTLS
	// authentication.
	CertBinder *authn.CertBinder
}

func (c Config) withDefaults() Config {
	c.PolicyPath = normalizePath(c.PolicyPath, "/mswstep/policy")
	c.EnrollPath = normalizePath(c.EnrollPath, "/mswstep/enroll")
	if c.DefaultProfile == "" {
		c.DefaultProfile = "client"
	}
	if c.PolicyFriendlyName == "" {
		c.PolicyFriendlyName = "secsy-pki Certificate Enrollment Policy"
	}
	if c.NextUpdateHours <= 0 {
		c.NextUpdateHours = 8
	}
	if strings.TrimSpace(c.TemplateOIDArc) == "" {
		c.TemplateOIDArc = defaultTemplateOIDArc
	}
	if c.PolicyID == "" {
		// A stable, deployment-specific identifier so a client can detect a changed
		// policy. Derived from the CA so two CAs never advertise the same policyID.
		c.PolicyID = "secsy-pki-" + c.CAID
	}
	return c
}

func normalizePath(p, def string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		p = def
	}
	return "/" + strings.Trim(p, "/")
}

// resolvedTemplate is a Template with all defaults applied and its OID
// synthesized, precomputed once at construction.
type resolvedTemplate struct {
	profile       string
	name          string
	oid           string
	enroll        bool
	autoEnroll    bool
	minKeyLength  int
	schemaVersion int
	majorRevision int
	// oidRef / caRef are the reference indices this template uses into the
	// GetPolicies oIDs and cAs collections (assigned by order).
	oidRef int
}

// Server implements the MS-XCEP and MS-WSTEP endpoints.
type Server struct {
	db        *database.DB
	provider  keyprovider.Provider
	caMgr     *ca.Manager
	cfg       Config
	templates []resolvedTemplate
	byName    map[string]resolvedTemplate // lowercased template name -> template
	byOID     map[string]resolvedTemplate // template OID -> template
	now       func() time.Time
}

// New constructs the server and precomputes the advertised template set. Call
// Register to attach the endpoints.
func New(db *database.DB, provider keyprovider.Provider, cfg Config) *Server {
	cfg = cfg.withDefaults()
	s := &Server{
		db:       db,
		provider: provider,
		caMgr:    ca.NewManager(db, provider),
		cfg:      cfg,
		byName:   map[string]resolvedTemplate{},
		byOID:    map[string]resolvedTemplate{},
		now:      time.Now,
	}
	s.templates = s.buildTemplates()
	for _, t := range s.templates {
		s.byName[strings.ToLower(t.name)] = t
		s.byOID[t.oid] = t
	}
	return s
}

// SetClock overrides the time source (used by tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// buildTemplates resolves the configured templates (or a single default derived
// from the default profile), filling defaults and synthesizing OIDs.
func (s *Server) buildTemplates() []resolvedTemplate {
	specs := s.cfg.Templates
	if len(specs) == 0 {
		specs = []Template{{Profile: s.cfg.DefaultProfile}}
	}
	out := make([]resolvedTemplate, 0, len(specs))
	for i, spec := range specs {
		rt := resolvedTemplate{
			profile:       spec.Profile,
			name:          spec.Name,
			oid:           strings.TrimSpace(spec.OID),
			enroll:        boolOrDefault(spec.Enroll, true),
			autoEnroll:    boolOrDefault(spec.AutoEnroll, true),
			minKeyLength:  spec.MinimalKeyLength,
			schemaVersion: spec.SchemaVersion,
			majorRevision: spec.MajorRevision,
			oidRef:        i,
		}
		if rt.name == "" {
			rt.name = spec.Profile
		}
		if rt.oid == "" {
			rt.oid = fmt.Sprintf("%s.%d", strings.Trim(s.cfg.TemplateOIDArc, "."), i+1)
		}
		if rt.minKeyLength <= 0 {
			rt.minKeyLength = 2048
		}
		if rt.schemaVersion <= 0 {
			rt.schemaVersion = 2
		}
		if rt.majorRevision <= 0 {
			rt.majorRevision = 100
		}
		out = append(out, rt)
	}
	return out
}

func boolOrDefault(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

// Register mounts the MS-XCEP and MS-WSTEP endpoints on mux. Both are SOAP POST
// endpoints authenticated per request (mTLS / API token), so they mount outside
// the OIDC middleware like the other enrollment protocols.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+s.cfg.PolicyPath, s.handleGetPolicies)
	mux.HandleFunc("POST "+s.cfg.EnrollPath, s.handleRequestSecurityToken)
	log.Printf("MS-XCEP/MS-WSTEP autoenrollment enabled (CEP=%s CES=%s CA=%s templates=%d)",
		s.cfg.PolicyPath, s.cfg.EnrollPath, s.cfg.CAID, len(s.templates))
}

// resolveTemplate maps a requested template identifier (an OID or a common name,
// case-insensitive) to its resolved template. An empty or unrecognized selector
// returns the template for the default profile (synthesizing one if the default
// profile is not among the configured templates), never an error: a Windows
// client that omits the template still gets the deployment's default.
func (s *Server) resolveTemplate(selector string) resolvedTemplate {
	selector = strings.TrimSpace(selector)
	if selector != "" {
		if t, ok := s.byOID[selector]; ok {
			return t
		}
		if t, ok := s.byName[strings.ToLower(selector)]; ok {
			return t
		}
	}
	// Fall back to the default profile's template.
	for _, t := range s.templates {
		if strings.EqualFold(t.profile, s.cfg.DefaultProfile) {
			return t
		}
	}
	// The default profile has no advertised template (unusual): synthesize one so
	// issuance can still proceed under the configured default profile.
	return resolvedTemplate{profile: s.cfg.DefaultProfile, name: s.cfg.DefaultProfile}
}

// issue signs a CSR through the shared HSM-backed ca.Manager under the given
// profile. A User Principal Name carried in the CSR SAN (id-ms-UPN otherName) is
// threaded through for smartcard-logon / machine-account enrollment; the
// profile's UPN gate validates it (and rejects it under a non-UPN profile).
func (s *Server) issue(ctx context.Context, csr *x509.CertificateRequest, profile, actor string) (*ca.IssueResult, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	return s.caMgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:        s.cfg.CAID,
		CSRPEM:      csrPEM,
		Profile:     profile,
		RequestedBy: actor,
		UPNs:        pki.UPNsFromCSR(csr),
	})
}

// --- CA plumbing -----------------------------------------------------------

func (s *Server) caCert() (*x509.Certificate, error) {
	m, err := s.db.GetCA(s.cfg.CAID)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Certificate == "" {
		return nil, fmt.Errorf("mswstep CA %q not found or has no certificate", s.cfg.CAID)
	}
	return pki.ParseCertificatePEM([]byte(m.Certificate))
}

// caChain returns the issuing CA certificate and its issuers, leaf-issuer first.
func (s *Server) caChain() ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	id := s.cfg.CAID
	for id != "" {
		m, err := s.db.GetCA(id)
		if err != nil {
			return nil, err
		}
		if m == nil || m.Certificate == "" {
			break
		}
		cert, err := pki.ParseCertificatePEM([]byte(m.Certificate))
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
		if m.ParentID == nil {
			break
		}
		id = *m.ParentID
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("mswstep CA %q not found", s.cfg.CAID)
	}
	return chain, nil
}

// caTenant returns the tenant that owns the issuing CA, defaulting to the
// built-in tenant when the CA carries none.
func (s *Server) caTenant() string {
	tenantID, err := s.db.GetCATenant(s.cfg.CAID)
	if err != nil || tenantID == "" {
		return models.DefaultTenantID
	}
	return tenantID
}

func (s *Server) recordEvent(r *http.Request, actor, action, target, result, detail string) {
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "mswstep",
		Action:     action,
		Tenant:     s.caTenant(),
		Target:     target,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
	}
	if err := s.db.AppendEvent(e); err != nil {
		log.Printf("mswstep: appending audit event %q: %v", action, err)
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
