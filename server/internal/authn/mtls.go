package authn

import (
	"crypto/x509"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// CertBinding binds a mutual-TLS client certificate to a principal. A binding
// matches when EVERY non-empty selector it declares matches the presented
// certificate; a binding with no selectors matches nothing (fail-closed) so an
// empty/misconfigured entry can never authorize a caller. On a match the caller
// is authenticated as the named principal with the listed roles.
type CertBinding struct {
	// --- selectors (all present ones must match) ---
	// SubjectCN matches the certificate subject Common Name exactly.
	SubjectCN string
	// SubjectDN matches the full RFC 2253 subject distinguished name exactly.
	SubjectDN string
	// SANDNS / SANURI / SANEmail match a value present in the corresponding SAN
	// list. A machine identity is best pinned by SAN rather than CN.
	SANDNS   string
	SANURI   string
	SANEmail string

	// --- resulting principal ---
	// Subject is the principal id recorded on the resolved UserInfo and in audit
	// events. Defaults to the certificate subject CN when empty.
	Subject string
	// Name is a human-readable label for the principal (optional).
	Name string
	// Roles are the platform-wide RBAC roles granted to the bound principal.
	Roles []rbac.Role
	// TenantRoles grants tenant-scoped roles (tenant id -> roles).
	TenantRoles map[string][]rbac.Role
}

func (b CertBinding) hasSelector() bool {
	return b.SubjectCN != "" || b.SubjectDN != "" || b.SANDNS != "" || b.SANURI != "" || b.SANEmail != ""
}

// CertBinder resolves a client certificate to a principal using an ordered list
// of bindings. It is immutable after construction and safe for concurrent use.
//
// The server requests client certificates with tls.RequestClientCert, which does
// NOT verify them at the handshake (so an EST device certificate, issued by the
// PKI's own CA rather than the operator client CA, does not break the handshake
// and is instead validated by the EST handler). The binder therefore verifies
// the presented chain against its own operator client-CA pool before binding —
// see Authenticate. Bind performs selector matching only.
type CertBinder struct {
	bindings []CertBinding
	// roots is the operator client-CA pool a presented certificate must chain to.
	// When nil, chain verification is skipped and callers must have verified it by
	// other means (used only in unit tests that construct synthetic certificates).
	roots *x509.CertPool
}

// NewCertBinder builds a binder from bindings, dropping any that declare no
// selector (which would otherwise match nothing and only invite confusion).
// Invalid role names are filtered so a typo cannot broaden access. roots is the
// operator client-CA pool a presented certificate is verified against by
// Authenticate; pass nil only in tests.
func NewCertBinder(bindings []CertBinding, roots *x509.CertPool) *CertBinder {
	cleaned := make([]CertBinding, 0, len(bindings))
	for _, b := range bindings {
		if !b.hasSelector() {
			continue
		}
		b.Roles = filterRoles(b.Roles)
		if len(b.TenantRoles) > 0 {
			tr := make(map[string][]rbac.Role, len(b.TenantRoles))
			for tid, roles := range b.TenantRoles {
				if v := filterRoles(roles); len(v) > 0 {
					tr[tid] = v
				}
			}
			b.TenantRoles = tr
		}
		cleaned = append(cleaned, b)
	}
	return &CertBinder{bindings: cleaned, roots: roots}
}

// Empty reports whether no bindings are configured.
func (b *CertBinder) Empty() bool { return b == nil || len(b.bindings) == 0 }

// Authenticate verifies a presented client-certificate chain against the
// operator client-CA pool and, on success, resolves it to a principal. chain is
// the raw tls.ConnectionState.PeerCertificates (leaf first, any intermediates
// after). It returns (nil, false) when the chain does not verify or matches no
// binding — the caller then falls through to the next authentication mechanism.
func (b *CertBinder) Authenticate(chain []*x509.Certificate) (*models.UserInfo, bool) {
	if b == nil || len(chain) == 0 {
		return nil, false
	}
	leaf := chain[0]
	if b.roots != nil {
		intermediates := x509.NewCertPool()
		for _, c := range chain[1:] {
			intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         b.roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, false
		}
	}
	return b.Bind(leaf)
}

// Bind resolves cert to a principal, returning the first matching binding's
// UserInfo. It reports (nil, false) when no binding matches — the caller then
// falls through to the next authentication mechanism (or is rejected).
func (b *CertBinder) Bind(cert *x509.Certificate) (*models.UserInfo, bool) {
	if b == nil || cert == nil {
		return nil, false
	}
	for _, bind := range b.bindings {
		if !matches(bind, cert) {
			continue
		}
		subject := bind.Subject
		if subject == "" {
			subject = cert.Subject.CommonName
		}
		if subject == "" {
			// Nothing to identify the principal by; skip rather than mint an
			// anonymous authenticated caller.
			continue
		}
		info := &models.UserInfo{
			Subject: subject,
			Name:    bind.Name,
			Roles:   roleStrings(bind.Roles),
		}
		if len(bind.TenantRoles) > 0 {
			info.TenantRoles = make(map[string][]string, len(bind.TenantRoles))
			for tid, roles := range bind.TenantRoles {
				info.TenantRoles[tid] = roleStrings(roles)
			}
		}
		return info, true
	}
	return nil, false
}

// matches reports whether every selector declared by bind matches cert.
func matches(bind CertBinding, cert *x509.Certificate) bool {
	if bind.SubjectCN != "" && cert.Subject.CommonName != bind.SubjectCN {
		return false
	}
	if bind.SubjectDN != "" && cert.Subject.String() != bind.SubjectDN {
		return false
	}
	if bind.SANDNS != "" && !containsFold(cert.DNSNames, bind.SANDNS) {
		return false
	}
	if bind.SANEmail != "" && !contains(cert.EmailAddresses, bind.SANEmail) {
		return false
	}
	if bind.SANURI != "" {
		found := false
		for _, u := range cert.URIs {
			if u != nil && u.String() == bind.SANURI {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// containsFold matches DNS names case-insensitively, since DNS is not
// case-sensitive.
func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func filterRoles(roles []rbac.Role) []rbac.Role {
	var out []rbac.Role
	for _, r := range roles {
		if rbac.ValidRole(r) {
			out = append(out, r)
		}
	}
	return out
}

func roleStrings(roles []rbac.Role) []string {
	if len(roles) == 0 {
		return nil
	}
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = string(r)
	}
	return out
}
