package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// This file provides an in-process, embedded LDAP server that speaks just enough
// of RFC 4511 (bind, search, StartTLS, unbind) to exercise the REAL go-ldap client
// — including real TLS — hermetically, with no external directory. The client and
// this server share the same well-tested BER codec (go-asn1-ber), so the tests
// cover the authenticator's actual wire behaviour rather than a stub.

const startTLSOID = "1.3.6.1.4.1.1466.20037"

// mockEntry is a directory entry the server can return from a search and/or bind
// as. A non-empty password makes the entry bindable.
type mockEntry struct {
	dn       string
	password string
	attrs    map[string][]string
}

func (e *mockEntry) get(attr string) []string {
	for k, v := range e.attrs {
		if strings.EqualFold(k, attr) {
			return v
		}
	}
	return nil
}

// mockDirectory is a tiny in-memory directory backing the server.
type mockDirectory struct {
	entries []*mockEntry
}

func (d *mockDirectory) find(dn string) *mockEntry {
	for _, e := range d.entries {
		if strings.EqualFold(e.dn, dn) {
			return e
		}
	}
	return nil
}

// mockMode selects the transport behaviour of the server.
type mockMode int

const (
	modePlain          mockMode = iota // cleartext ldap:// (no TLS)
	modeStartTLS                       // ldap:// offering a working StartTLS
	modeStartTLSRefuse                 // ldap:// that refuses StartTLS (enforcement test)
	modeLDAPS                          // ldaps:// implicit TLS
)

// mockLDAP is the embedded server.
type mockLDAP struct {
	ln        net.Listener
	dir       *mockDirectory
	tlsConfig *tls.Config
	mode      mockMode
	binds     int32 // successful+failed bind attempts observed
	tlsBinds  int32 // bind attempts observed over a TLS-wrapped connection
	wg        sync.WaitGroup
}

// startMockLDAP launches an embedded server in the given mode and returns it and
// its base URL (ldap:// or ldaps://). It registers cleanup on t.
func startMockLDAP(t *testing.T, dir *mockDirectory, mode mockMode) (*mockLDAP, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockLDAP{ln: ln, dir: dir, mode: mode}
	if mode == modeLDAPS || mode == modeStartTLS {
		m.tlsConfig = testServerTLS(t)
	}
	scheme := "ldap"
	if mode == modeLDAPS {
		scheme = "ldaps"
	}
	url := scheme + "://" + ln.Addr().String()
	m.wg.Add(1)
	go m.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		m.wg.Wait()
	})
	return m, url
}

func (m *mockLDAP) serve() {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handle(conn)
		}()
	}
}

func (m *mockLDAP) handle(conn net.Conn) {
	defer conn.Close()
	isTLS := false
	if m.mode == modeLDAPS {
		tc := tls.Server(conn, m.tlsConfig)
		if err := tc.Handshake(); err != nil {
			return
		}
		conn = tc
		isTLS = true
	}
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(packet.Children) < 2 {
			return
		}
		msgID, _ := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch int(op.Tag) {
		case ldap.ApplicationBindRequest:
			atomic.AddInt32(&m.binds, 1)
			if isTLS {
				atomic.AddInt32(&m.tlsBinds, 1)
			}
			m.handleBind(conn, msgID, op)
		case ldap.ApplicationSearchRequest:
			m.handleSearch(conn, msgID, op)
		case ldap.ApplicationExtendedRequest:
			newConn, ok := m.handleExtended(conn, msgID, op)
			if !ok {
				return
			}
			if newConn != conn {
				conn = newConn
				isTLS = true
			}
		case ldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

func (m *mockLDAP) handleBind(conn net.Conn, msgID int64, op *ber.Packet) {
	dn, _ := op.Children[1].Value.(string)
	var password string
	if len(op.Children) >= 3 {
		password = op.Children[2].Data.String()
	}
	code := ldap.LDAPResultInvalidCredentials
	if e := m.dir.find(dn); e != nil && e.password != "" && e.password == password {
		code = ldap.LDAPResultSuccess
	}
	writePacket(conn, resultPacket(msgID, ldap.ApplicationBindResponse, code))
}

func (m *mockLDAP) handleSearch(conn net.Conn, msgID int64, op *ber.Packet) {
	baseDN, _ := op.Children[0].Value.(string)
	scope, _ := op.Children[1].Value.(int64)
	filter := op.Children[6]
	var requested []string
	if len(op.Children) >= 8 {
		for _, a := range op.Children[7].Children {
			if s, ok := a.Value.(string); ok {
				requested = append(requested, s)
			}
		}
	}
	for _, e := range m.dir.entries {
		if !inScope(e.dn, baseDN, scope) {
			continue
		}
		if !matchFilter(filter, e) {
			continue
		}
		writePacket(conn, searchEntryPacket(msgID, e, requested))
	}
	writePacket(conn, resultPacket(msgID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess))
}

func (m *mockLDAP) handleExtended(conn net.Conn, msgID int64, op *ber.Packet) (net.Conn, bool) {
	var oid string
	if len(op.Children) > 0 {
		oid = op.Children[0].Data.String()
	}
	if oid == startTLSOID && m.mode == modeStartTLS {
		writePacket(conn, resultPacket(msgID, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess))
		tc := tls.Server(conn, m.tlsConfig)
		if err := tc.Handshake(); err != nil {
			return conn, false
		}
		return tc, true
	}
	// Refuse StartTLS (unwilling to perform) — drives the enforcement test.
	writePacket(conn, resultPacket(msgID, ldap.ApplicationExtendedResponse, 53))
	return conn, true
}

// --- BER helpers -------------------------------------------------------------

func writePacket(conn net.Conn, p *ber.Packet) {
	_, _ = conn.Write(p.Bytes())
}

func envelope(msgID int64) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	return env
}

func resultPacket(msgID int64, appTag, code int) *ber.Packet {
	env := envelope(msgID)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(appTag), nil, "response")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(op)
	return env
}

func searchEntryPacket(msgID int64, e *mockEntry, requested []string) *ber.Packet {
	env := envelope(msgID)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationSearchResultEntry), nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "objectName"))
	attrList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, vals := range e.attrs {
		if !wantAttr(name, requested) {
			continue
		}
		pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		}
		pa.AppendChild(set)
		attrList.AppendChild(pa)
	}
	op.AppendChild(attrList)
	env.AppendChild(op)
	return env
}

// wantAttr reports whether an attribute should be returned given the request's
// attribute selection (empty selection means "all user attributes").
func wantAttr(name string, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, r := range requested {
		if r == "*" || strings.EqualFold(r, name) {
			return true
		}
	}
	return false
}

// inScope reports whether dn falls within baseDN at the given scope (0 base,
// 1 one-level, 2 subtree). A simple suffix test is sufficient for the fixtures.
func inScope(dn, baseDN string, scope int64) bool {
	dn = strings.ToLower(strings.TrimSpace(dn))
	baseDN = strings.ToLower(strings.TrimSpace(baseDN))
	if scope == 0 { // baseObject
		return dn == baseDN
	}
	return dn == baseDN || strings.HasSuffix(dn, ","+baseDN)
}

// matchFilter evaluates an LDAP search filter packet against an entry, supporting
// and/or/not, equalityMatch, and present — the subset the tests exercise.
func matchFilter(f *ber.Packet, e *mockEntry) bool {
	switch int(f.Tag) {
	case 0: // and
		for _, c := range f.Children {
			if !matchFilter(c, e) {
				return false
			}
		}
		return true
	case 1: // or
		for _, c := range f.Children {
			if matchFilter(c, e) {
				return true
			}
		}
		return false
	case 2: // not
		return len(f.Children) == 1 && !matchFilter(f.Children[0], e)
	case 3: // equalityMatch
		if len(f.Children) != 2 {
			return false
		}
		attr, _ := f.Children[0].Value.(string)
		val, _ := f.Children[1].Value.(string)
		for _, v := range e.get(attr) {
			if strings.EqualFold(v, val) {
				return true
			}
		}
		return false
	case 7: // present
		return len(e.get(f.Data.String())) > 0
	default:
		return false
	}
}

// --- test TLS material -------------------------------------------------------

// testServerTLS returns a *tls.Config bearing a fresh self-signed certificate for
// 127.0.0.1, and stashes the CA (self) PEM so tests can trust it. Regenerated per
// call to keep tests independent.
func testServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	cert, _ := testCert(t)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// testCert generates a self-signed P-256 certificate valid for 127.0.0.1/localhost
// and returns the tls.Certificate plus its PEM (usable as the client trust anchor).
func testCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "secsy-ldap-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return cert, certPEM
}

// caPEMOf returns the CA PEM trust anchor for a server started with a TLS config
// created by testServerTLS — the leaf certificate itself (self-signed).
func caPEMOf(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	if cfg == nil || len(cfg.Certificates) == 0 {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cfg.Certificates[0].Certificate[0]})
}
