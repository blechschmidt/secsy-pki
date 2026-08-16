//go:build sqlite

// This file drives the secsy-agent host auto-enrollment client end-to-end
// against a real, HSM-backed CA (SoftHSM in CI):
//
//   - ACME (RFC 8555): the agent registers an account, answers http-01 from
//     its built-in solver, finalizes with a locally generated key, installs
//     atomically, and — after the certificate is revoked server-side — is told
//     to renew immediately by the ARI renewal-info endpoint (Task 30).
//   - EST (RFC 7030): the agent bootstraps with Basic credentials, derives its
//     trust bundle from /cacerts, enrolls, and later renews through
//     simplereenroll when its injected clock passes the lifetime fraction.
//
// Both flows assert the reload hook fired after the files were swapped into
// place (the hook's snapshot equals the final on-disk certificate) and that no
// temporary files leak. The EST flow additionally exercises the real CLI
// (`secsy-agent once` / `status`) including its work-done exit codes.
package e2e

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	acmesrv "github.com/blechschmidt/secsy-pki/server/internal/acme"
	"github.com/blechschmidt/secsy-pki/server/internal/agent"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	estsrv "github.com/blechschmidt/secsy-pki/server/internal/est"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// agentEnv is a full server stack (SoftHSM CA + ACME + EST) plus the file
// layout for one agent under test.
type agentEnv struct {
	db     *database.DB
	mgr    *ca.Manager
	caID   string
	root   *x509.Certificate
	inter  *x509.Certificate
	server *httptest.Server

	dir     string // agent working dir (state, pki outputs, hook artifacts)
	cfgPath string
}

// agentEnvOpts selects how the ACME server under test validates challenges.
type agentEnvOpts struct {
	// solverPort, when non-zero, wires the http-01 validator to dial the agent's
	// standalone solver on 127.0.0.1 (like a DNS A record pointing at the host).
	solverPort int
	// challenge is the single challenge type the ACME server offers (default
	// "http-01"). Set to "dns-01" to exercise the agent's dns-01 solver.
	challenge string
	// resolver answers the server-side dns-01 TXT lookup; required for dns-01.
	resolver acmesrv.Resolver
}

// setupAgentEnv builds root+intermediate on the HSM and mounts ACME and EST
// servers on one httptest server. solverPort, when non-zero, wires the ACME
// http-01 validator to dial the agent's standalone solver on 127.0.0.1.
func setupAgentEnv(t *testing.T, solverPort int) *agentEnv {
	return setupAgentEnvOpts(t, agentEnvOpts{solverPort: solverPort})
}

// setupAgentEnvOpts is setupAgentEnv with explicit challenge/validator control.
func setupAgentEnvOpts(t *testing.T, opts agentEnvOpts) *agentEnv {
	t.Helper()
	provider := hsmProvider(t)

	db, err := database.New("sqlite", t.TempDir()+"/agent.db")
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	ctx := context.Background()
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "agent-root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy Agent Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      uniqueLabel(t, "agent-inter"),
		KeyType:    keyprovider.KeyTypeECDSAP256,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy Agent Issuing CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	mux := http.NewServeMux()

	challenge := opts.challenge
	if challenge == "" {
		challenge = "http-01"
	}
	acmeServer := acmesrv.New(db, provider, acmesrv.Config{
		CAID:           inter.ID,
		Profile:        "server",
		ChallengeTypes: []string{challenge},
	})
	if opts.solverPort != 0 {
		// Validation URLs name the (unresolvable) test domain; dial them all to
		// the agent's http-01 solver instead, like a DNS record pointing at the
		// host would in production.
		solverAddr := fmt.Sprintf("127.0.0.1:%d", opts.solverPort)
		acmeServer.SetValidator(&acmesrv.Validator{
			HTTPClient: &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, solverAddr)
					},
				},
			},
			HTTPPort: 80,
		})
	}
	if opts.resolver != nil {
		// dns-01: the server validates by reading TXT records the agent's
		// DnsProvider published into the shared test resolver.
		acmeServer.SetValidator(&acmesrv.Validator{Resolver: opts.resolver})
	}
	acmeServer.Register(mux)

	estServer := estsrv.New(db, provider, estsrv.Config{
		CAID:    inter.ID,
		Profile: "server",
		Users:   map[string]estsrv.User{"agent": {Password: "enroll-pw", Profile: "server"}},
	})
	estServer.Register(mux)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	env := &agentEnv{
		db:     db,
		mgr:    mgr,
		caID:   inter.ID,
		root:   mustParse(t, root.Certificate),
		inter:  mustParse(t, inter.Certificate),
		server: server,
		dir:    t.TempDir(),
	}
	return env
}

func (env *agentEnv) path(rel string) string { return filepath.Join(env.dir, rel) }

func (env *agentEnv) writeConfig(t *testing.T, yaml string) {
	t.Helper()
	env.cfgPath = env.path("agent.yaml")
	if err := os.WriteFile(env.cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing agent config: %v", err)
	}
}

func (env *agentEnv) newAgent(t *testing.T) *agent.Agent {
	t.Helper()
	cfg, err := agent.LoadConfig(env.cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	a, err := agent.New(cfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	t.Cleanup(func() { a.Close() }) //nolint:errcheck
	return a
}

// readLeaf parses the first certificate in a PEM file.
func readLeaf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s holds no PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return cert
}

// verifyToRoot checks leaf+issuers (from fullchain/chain files) verify to the
// test root.
func (env *agentEnv) verifyToRoot(t *testing.T, leaf *x509.Certificate, issuerFiles ...string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(env.root)
	inters := x509.NewCertPool()
	inters.AddCert(env.inter)
	for _, f := range issuerFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		if !inters.AppendCertsFromPEM(data) {
			t.Fatalf("%s holds no certificates", f)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("installed certificate does not verify to the root: %v", err)
	}
}

// assertHookFired checks the hook log line count and that the hook's snapshot
// of the cert file equals its final content (proving the swap preceded the
// hook).
func (env *agentEnv) assertHookFired(t *testing.T, times int, certFile string) {
	t.Helper()
	logData, err := os.ReadFile(env.path("hook.log"))
	if err != nil {
		t.Fatalf("hook log: %v", err)
	}
	if got := strings.Count(string(logData), "fired"); got != times {
		t.Fatalf("hook fired %d times, want %d", got, times)
	}
	snap, err := os.ReadFile(env.path("hook-snapshot.pem"))
	if err != nil {
		t.Fatalf("hook snapshot: %v", err)
	}
	final, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(snap) != string(final) {
		t.Fatal("hook saw different certificate content than the final install — files were not in place before the hook ran")
	}
}

// assertNoTempFiles fails on leftover .secsy-tmp. staging files.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.Contains(d.Name(), ".secsy-tmp.") {
			t.Errorf("staging file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// freePort reserves an ephemeral TCP port for the agent's http-01 solver.
func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	lis.Close() //nolint:errcheck
	return port
}

// TestAgentACMEEnrollmentAndARIRenewal is the ACME http-01 flow: initial
// enrollment through the agent's standalone solver, then an ARI-driven
// immediate renewal after the certificate is revoked server-side.
func TestAgentACMEEnrollmentAndARIRenewal(t *testing.T) {
	solverPort := freePort(t)
	env := setupAgentEnv(t, solverPort)

	// The trust bundle is pre-provisioned with the root only; the agent must
	// complete the chain from the enrollment response.
	trustPath := env.path("trust.pem")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.root.Raw})
	if err := os.WriteFile(trustPath, rootPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	env.writeConfig(t, fmt.Sprintf(`
state_dir: %[1]s/state
trust:
  bundle_file: %[2]s
acme:
  directory: %[3]s/acme/directory
  contact: ["mailto:ops@example.test"]
  http01:
    listen: "127.0.0.1:%[4]d"
renewal:
  check_interval: 1m
metrics:
  textfile: %[1]s/agent.prom
certificates:
  - name: acme-web
    enroll: acme
    dns_names: [agent-acme.example.test]
    key_type: ecdsa-p256
    key_file: %[1]s/pki/acme-web.key
    cert_file: %[1]s/pki/acme-web.crt
    fullchain_file: %[1]s/pki/acme-web-fullchain.crt
    reload:
      command: 'cp "$SECSY_CERT_FILE" %[1]s/hook-snapshot.pem && echo fired >> %[1]s/hook.log'
`, env.dir, trustPath, env.server.URL, solverPort))

	a := env.newAgent(t)
	ctx := context.Background()

	// Pass 1: initial enrollment over http-01.
	report, err := a.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 || got[0] != "acme-web" {
		t.Fatalf("pass 1 renewed %v (failures %v), want [acme-web]", got, report.Failed())
	}
	certFile := env.path("pki/acme-web.crt")
	leaf1 := readLeaf(t, certFile)
	if leaf1.DNSNames[0] != "agent-acme.example.test" {
		t.Fatalf("issued SANs = %v", leaf1.DNSNames)
	}
	env.verifyToRoot(t, leaf1, env.path("pki/acme-web-fullchain.crt"))
	if info, err := os.Stat(env.path("pki/acme-web.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", info, err)
	}
	env.assertHookFired(t, 1, certFile)

	// Pass 2: steady state — the ARI window for a fresh certificate is far
	// away, so nothing happens.
	report, err = a.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	if len(report.Renewed()) != 0 || len(report.Failed()) != 0 {
		t.Fatalf("steady state pass did work: %+v", report.Outcomes)
	}

	// Revoke the certificate server-side. ARI now advertises an immediate
	// renewal window. The steady-state pass cached the previous (healthy)
	// answer for its Retry-After, so jump the agent's clock past that horizon
	// — its next poll then learns of the revocation and renews at once.
	applied, err := env.mgr.RevokeCertificate(ctx, env.caID, leaf1.SerialNumber.String(), "keyCompromise")
	if err != nil || !applied {
		t.Fatalf("RevokeCertificate: applied=%v err=%v", applied, err)
	}
	a.SetClock(func() time.Time { return time.Now().Add(7 * time.Hour) })

	report, err = a.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce 3: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 {
		t.Fatalf("post-revocation pass renewed %v (failures %v), want [acme-web]", got, report.Failed())
	}
	leaf2 := readLeaf(t, certFile)
	if leaf2.SerialNumber.Cmp(leaf1.SerialNumber) == 0 {
		t.Fatal("certificate serial unchanged after ARI-driven renewal")
	}
	env.verifyToRoot(t, leaf2, env.path("pki/acme-web-fullchain.crt"))
	env.assertHookFired(t, 2, certFile)

	// Metrics reflect the installed certificate.
	prom, err := os.ReadFile(env.path("agent.prom"))
	if err != nil {
		t.Fatalf("metrics textfile: %v", err)
	}
	if !strings.Contains(string(prom), `secsy_agent_certificate_present{certificate="acme-web"} 1`) {
		t.Errorf("metrics missing presence gauge:\n%s", prom)
	}

	assertNoTempFiles(t, env.dir)
}

// txtFileResolver answers dns-01 TXT lookups from a directory the agent's exec
// DnsProvider writes into: one file per record name holding the TXT value. The
// ACME server uses it to validate the challenge.
type txtFileResolver struct{ dir string }

func (r txtFileResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(r.dir, strings.TrimSuffix(name, ".")))
	if err != nil {
		return nil, nil //nolint:nilerr // a missing file models a DNS NODATA answer (no TXT record), not a resolver error.
	}
	return []string{string(data)}, nil
}

// txtDNSServer is a minimal UDP nameserver that serves TXT records from the same
// file store. The agent's propagation check (a pinned net.Resolver) queries it,
// so the real dns-01 propagation-polling path is exercised end to end.
type txtDNSServer struct {
	dir  string
	conn *net.UDPConn
}

func startTXTDNSServer(t *testing.T, dir string) *txtDNSServer {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &txtDNSServer{dir: dir, conn: pc}
	go s.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return s
}

func (s *txtDNSServer) addr() string { return s.conn.LocalAddr().String() }

func (s *txtDNSServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if resp := s.respond(append([]byte(nil), buf[:n]...)); resp != nil {
			_, _ = s.conn.WriteToUDP(resp, src)
		}
	}
}

func (s *txtDNSServer) respond(req []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
	_ = b.StartQuestions()
	_ = b.Question(q)
	if q.Type == dnsmessage.TypeTXT {
		name := strings.TrimSuffix(q.Name.String(), ".")
		if data, err := os.ReadFile(filepath.Join(s.dir, name)); err == nil {
			_ = b.StartAnswers()
			_ = b.TXTResource(
				dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 1},
				dnsmessage.TXTResource{TXT: []string{string(data)}},
			)
		}
	}
	msg, _ := b.Finish()
	return msg
}

// TestAgentACMEDNS01Enrollment drives the agent's dns-01 solver end-to-end
// against a real HSM-backed ACME server: the exec DnsProvider publishes the
// _acme-challenge TXT record, the server validates it, and a later ARI-driven
// renewal (after server-side revocation) also re-enrolls over dns-01. This is
// the firewalled-host path — the agent never opens an inbound HTTP listener.
func TestAgentACMEDNS01Enrollment(t *testing.T) {
	recDir := t.TempDir()
	env := setupAgentEnvOpts(t, agentEnvOpts{challenge: "dns-01", resolver: txtFileResolver{dir: recDir}})
	dns := startTXTDNSServer(t, recDir)

	trustPath := env.path("trust.pem")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.root.Raw})
	if err := os.WriteFile(trustPath, rootPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	// The exec provider writes the value to <recDir>/<record>; the agent's
	// propagation check polls the in-process TXT nameserver that serves the same
	// store, and the ACME server validates through its own file resolver.
	env.writeConfig(t, fmt.Sprintf(`
state_dir: %[1]s/state
trust:
  bundle_file: %[2]s
acme:
  directory: %[3]s/acme/directory
  contact: ["mailto:ops@example.test"]
  challenge: dns-01
  dns01:
    provider: exec
    propagation_timeout: 20s
    poll_interval: 200ms
    resolvers: ["%[5]s"]
    exec:
      present: 'printf "%%s" "$SECSY_DNS01_VALUE" > "%[4]s/$SECSY_DNS01_RECORD"'
      cleanup: 'rm -f "%[4]s/$SECSY_DNS01_RECORD"'
renewal:
  check_interval: 1m
certificates:
  - name: acme-dns
    enroll: acme
    dns_names: [agent-dns.example.test]
    key_type: ecdsa-p256
    key_file: %[1]s/pki/acme-dns.key
    cert_file: %[1]s/pki/acme-dns.crt
    fullchain_file: %[1]s/pki/acme-dns-fullchain.crt
    reload:
      command: 'cp "$SECSY_CERT_FILE" %[1]s/hook-snapshot.pem && echo fired >> %[1]s/hook.log'
`, env.dir, trustPath, env.server.URL, recDir, dns.addr()))

	a := env.newAgent(t)
	ctx := context.Background()

	// Pass 1: initial enrollment over dns-01.
	report, err := a.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 || got[0] != "acme-dns" {
		t.Fatalf("pass 1 renewed %v (failures %v), want [acme-dns]", got, report.Failed())
	}
	certFile := env.path("pki/acme-dns.crt")
	leaf1 := readLeaf(t, certFile)
	if len(leaf1.DNSNames) != 1 || leaf1.DNSNames[0] != "agent-dns.example.test" {
		t.Fatalf("issued SANs = %v", leaf1.DNSNames)
	}
	env.verifyToRoot(t, leaf1, env.path("pki/acme-dns-fullchain.crt"))
	env.assertHookFired(t, 1, certFile)

	// The provider withdrew the challenge record after validation.
	if _, err := os.Stat(filepath.Join(recDir, "_acme-challenge.agent-dns.example.test")); !os.IsNotExist(err) {
		t.Errorf("dns-01 challenge record was not cleaned up: %v", err)
	}

	// ARI-driven renewal over dns-01: revoke server-side, jump past the cached
	// Retry-After, and the next pass re-enrolls through the dns-01 solver.
	if applied, err := env.mgr.RevokeCertificate(ctx, env.caID, leaf1.SerialNumber.String(), "keyCompromise"); err != nil || !applied {
		t.Fatalf("RevokeCertificate: applied=%v err=%v", applied, err)
	}
	a.SetClock(func() time.Time { return time.Now().Add(7 * time.Hour) })

	report, err = a.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 {
		t.Fatalf("post-revocation pass renewed %v (failures %v), want [acme-dns]", got, report.Failed())
	}
	leaf2 := readLeaf(t, certFile)
	if leaf2.SerialNumber.Cmp(leaf1.SerialNumber) == 0 {
		t.Fatal("certificate serial unchanged after ARI-driven dns-01 renewal")
	}
	env.verifyToRoot(t, leaf2, env.path("pki/acme-dns-fullchain.crt"))
	env.assertHookFired(t, 2, certFile)

	assertNoTempFiles(t, env.dir)
}

// TestAgentESTEnrollmentAndFractionRenewal is the EST flow: CLI-driven initial
// enrollment (exit code 2 = work done, then 0 = fresh, plus status JSON), and
// a fraction-of-lifetime renewal through simplereenroll when the agent's
// clock passes 2/3 of the certificate lifetime.
func TestAgentESTEnrollmentAndFractionRenewal(t *testing.T) {
	env := setupAgentEnv(t, 0)

	env.writeConfig(t, fmt.Sprintf(`
state_dir: %[1]s/state
est:
  url: %[2]s/.well-known/est
  username: agent
  password: enroll-pw
metrics:
  textfile: %[1]s/agent.prom
certificates:
  - name: est-svc
    enroll: est
    dns_names: [agent-est.example.test]
    key_type: ecdsa-p256
    key_file: %[1]s/pki/est-svc.key
    cert_file: %[1]s/pki/est-svc.crt
    chain_file: %[1]s/pki/est-svc-chain.crt
    fullchain_file: %[1]s/pki/est-svc-fullchain.crt
    reload:
      command: 'cp "$SECSY_CERT_FILE" %[1]s/hook-snapshot.pem && echo fired >> %[1]s/hook.log'
`, env.dir, env.server.URL))

	certFile := env.path("pki/est-svc.crt")

	// Drive the initial enrollment through the real CLI when the Go toolchain
	// is available (it is under `go test`), asserting the documented exit
	// codes; otherwise fall back to the library.
	cli := buildAgentCLI(t)
	if cli != "" {
		if code, out := runAgentCLI(t, cli, env.cfgPath, "once"); code != 2 {
			t.Fatalf("first `once` exit = %d, want 2 (work done)\n%s", code, out)
		}
		if code, out := runAgentCLI(t, cli, env.cfgPath, "once"); code != 0 {
			t.Fatalf("second `once` exit = %d, want 0 (fresh)\n%s", code, out)
		}
		code, out := runAgentCLI(t, cli, env.cfgPath, "status")
		if code != 0 {
			t.Fatalf("status exit = %d\n%s", code, out)
		}
		var status struct {
			Certificates []struct {
				Name    string `json:"name"`
				Present bool   `json:"present"`
				Due     bool   `json:"due"`
			} `json:"certificates"`
		}
		if err := json.Unmarshal([]byte(out), &status); err != nil {
			t.Fatalf("status is not JSON: %v\n%s", err, out)
		}
		if len(status.Certificates) != 1 || !status.Certificates[0].Present || status.Certificates[0].Due {
			t.Fatalf("status = %+v", status.Certificates)
		}
	} else {
		a := env.newAgent(t)
		report, err := a.RunOnce(context.Background())
		if err != nil || len(report.Renewed()) != 1 {
			t.Fatalf("initial enrollment: renewed=%v err=%v", report.Renewed(), err)
		}
	}

	leaf1 := readLeaf(t, certFile)
	// The trust bundle was fetched from /cacerts (derived automatically from
	// est.url); the chain file must complete the leaf to our root.
	env.verifyToRoot(t, leaf1, env.path("pki/est-svc-chain.crt"))
	env.assertHookFired(t, 1, certFile)

	// Advance the agent's clock past the renewal fraction (default 2/3 plus
	// jitter) but well before expiry: the fallback scheduler must renew via
	// simplereenroll.
	lifetime := leaf1.NotAfter.Sub(leaf1.NotBefore)
	fakeNow := leaf1.NotBefore.Add(time.Duration(0.8 * float64(lifetime)))

	a := env.newAgent(t)
	a.SetClock(func() time.Time { return fakeNow })
	report, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("forced RunOnce: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 || got[0] != "est-svc" {
		t.Fatalf("forced pass renewed %v (failures %v), want [est-svc]", got, report.Failed())
	}
	leaf2 := readLeaf(t, certFile)
	if leaf2.SerialNumber.Cmp(leaf1.SerialNumber) == 0 {
		t.Fatal("certificate serial unchanged after fraction renewal")
	}
	env.verifyToRoot(t, leaf2, env.path("pki/est-svc-chain.crt"))
	env.assertHookFired(t, 2, certFile)

	// The private key rotated with the certificate and matches the new leaf.
	keyPEM, err := os.ReadFile(env.path("pki/est-svc.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("key file does not hold a private key")
	}

	assertNoTempFiles(t, env.dir)
}

// buildAgentCLI compiles cmd/secsy-agent into a temp dir, returning "" when
// the Go toolchain is unavailable.
func buildAgentCLI(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Log("go toolchain not on PATH; exercising the agent library instead of the CLI")
		return ""
	}
	out := filepath.Join(t.TempDir(), "secsy-agent")
	cmd := exec.Command(goBin, "build", "-o", out, "github.com/blechschmidt/secsy-pki/server/cmd/secsy-agent")
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building secsy-agent CLI: %v\n%s", err, output)
	}
	return out
}

// runAgentCLI runs the compiled CLI and returns its exit code and combined
// output.
func runAgentCLI(t *testing.T, cli, cfgPath string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(cli, append([]string{"-config", cfgPath}, args...)...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(output)
	}
	t.Fatalf("running CLI: %v\n%s", err, output)
	return -1, ""
}
