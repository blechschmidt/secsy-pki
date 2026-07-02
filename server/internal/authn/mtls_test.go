package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url %q: %v", s, err)
	}
	return u
}

func TestCertBinderBind(t *testing.T) {
	binder := NewCertBinder([]CertBinding{
		{
			SubjectCN: "robot-1",
			Subject:   "svc:robot-1",
			Name:      "Build Robot 1",
			Roles:     []rbac.Role{rbac.RoleIssuer},
		},
		{
			SANDNS: "scanner.example.com",
			Roles:  []rbac.Role{rbac.RoleAuditor},
		},
		{
			SANURI:      "spiffe://example.org/ns/ops/sa/deployer",
			Subject:     "deployer",
			Roles:       []rbac.Role{rbac.RoleAdmin},
			TenantRoles: map[string][]rbac.Role{"acme-corp": {rbac.RoleIssuer}},
		},
		{
			SubjectCN: "multi",
			SANEmail:  "multi@example.com",
			Subject:   "multi",
			Roles:     []rbac.Role{rbac.RoleIssuer},
		},
	}, nil)

	t.Run("match by subject CN", func(t *testing.T) {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: "robot-1"}}
		info, ok := binder.Bind(cert)
		if !ok {
			t.Fatal("expected a binding match")
		}
		if info.Subject != "svc:robot-1" || info.Name != "Build Robot 1" {
			t.Errorf("unexpected principal: %+v", info)
		}
		if !reflect.DeepEqual(info.Roles, []string{"issuer"}) {
			t.Errorf("roles = %v, want [issuer]", info.Roles)
		}
	})

	t.Run("match by SAN DNS defaults subject to CN", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "cn-fallback"},
			DNSNames: []string{"scanner.example.com"},
		}
		info, ok := binder.Bind(cert)
		if !ok {
			t.Fatal("expected a binding match")
		}
		if info.Subject != "cn-fallback" {
			t.Errorf("subject = %q, want fallback to CN", info.Subject)
		}
		if !reflect.DeepEqual(info.Roles, []string{"auditor"}) {
			t.Errorf("roles = %v, want [auditor]", info.Roles)
		}
	})

	t.Run("match by SAN URI carries tenant roles", func(t *testing.T) {
		cert := &x509.Certificate{URIs: []*url.URL{mustURL(t, "spiffe://example.org/ns/ops/sa/deployer")}}
		info, ok := binder.Bind(cert)
		if !ok {
			t.Fatal("expected a binding match")
		}
		if info.Subject != "deployer" {
			t.Errorf("subject = %q, want deployer", info.Subject)
		}
		if !reflect.DeepEqual(info.TenantRoles["acme-corp"], []string{"issuer"}) {
			t.Errorf("tenant roles = %v, want issuer", info.TenantRoles["acme-corp"])
		}
	})

	t.Run("all selectors must match", func(t *testing.T) {
		// The 'multi' binding requires BOTH the CN and the email SAN.
		onlyCN := &x509.Certificate{Subject: pkix.Name{CommonName: "multi"}}
		if _, ok := binder.Bind(onlyCN); ok {
			t.Error("expected no match when only the CN selector matches")
		}
		both := &x509.Certificate{
			Subject:        pkix.Name{CommonName: "multi"},
			EmailAddresses: []string{"multi@example.com"},
		}
		if _, ok := binder.Bind(both); !ok {
			t.Error("expected a match when both selectors match")
		}
	})

	t.Run("no match", func(t *testing.T) {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: "stranger"}}
		if _, ok := binder.Bind(cert); ok {
			t.Error("expected no match for an unbound certificate")
		}
	})

	t.Run("nil inputs", func(t *testing.T) {
		if _, ok := binder.Bind(nil); ok {
			t.Error("nil cert must not match")
		}
		var nilBinder *CertBinder
		if _, ok := nilBinder.Bind(&x509.Certificate{}); ok {
			t.Error("nil binder must not match")
		}
	})
}

func TestCertBinderDropsSelectorlessBindings(t *testing.T) {
	// A binding with no selector matches nothing and is dropped at construction,
	// so it can never authorize a caller.
	binder := NewCertBinder([]CertBinding{
		{Subject: "ghost", Roles: []rbac.Role{rbac.RoleAdmin}}, // no selector
	}, nil)
	if !binder.Empty() {
		t.Fatal("expected selectorless binding to be dropped")
	}
	if _, ok := binder.Bind(&x509.Certificate{Subject: pkix.Name{CommonName: "anything"}}); ok {
		t.Error("selectorless binding must not authorize any certificate")
	}
}

// issueClientCert builds a throwaway CA and a client leaf signed by it, for
// exercising Authenticate's chain verification.
func issueClientCert(t *testing.T, cn string) (root *x509.Certificate, leaf *x509.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	root, _ = x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, caKey)
	leaf, _ = x509.ParseCertificate(leafDER)
	return root, leaf
}

func TestCertBinderAuthenticateVerifiesChain(t *testing.T) {
	root, leaf := issueClientCert(t, "robot-1")
	pool := x509.NewCertPool()
	pool.AddCert(root)

	binder := NewCertBinder([]CertBinding{
		{SubjectCN: "robot-1", Subject: "svc:robot-1", Roles: []rbac.Role{rbac.RoleIssuer}},
	}, pool)

	t.Run("cert chaining to the pool authenticates", func(t *testing.T) {
		info, ok := binder.Authenticate([]*x509.Certificate{leaf})
		if !ok || info.Subject != "svc:robot-1" {
			t.Fatalf("expected bound principal, got %+v ok=%v", info, ok)
		}
	})

	t.Run("cert from a foreign CA is rejected", func(t *testing.T) {
		_, foreign := issueClientCert(t, "robot-1") // same CN, different CA
		if _, ok := binder.Authenticate([]*x509.Certificate{foreign}); ok {
			t.Error("a certificate not chaining to the client-CA pool must be rejected")
		}
	})
}

func TestCertBinderDNSCaseInsensitive(t *testing.T) {
	binder := NewCertBinder([]CertBinding{
		{SANDNS: "Host.Example.COM", Subject: "h", Roles: []rbac.Role{rbac.RoleIssuer}},
	}, nil)
	cert := &x509.Certificate{DNSNames: []string{"host.example.com"}}
	if _, ok := binder.Bind(cert); !ok {
		t.Error("DNS SAN matching should be case-insensitive")
	}
}
