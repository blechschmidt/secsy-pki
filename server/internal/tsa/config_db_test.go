//go:build sqlite

package tsa

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// The CA-resolution half of LoadAuthorityConfig needs a store, so these cases
// live behind the sqlite build tag alongside the rest of the repo's
// database-backed tests. Everything is still hermetic: a fresh file-backed
// SQLite database per test and in-process ECDSA certificates.

// testDB opens a throwaway migrated store.
func testDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "tsa-test.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// insertCA stores a CA row. public_key is NOT NULL in the schema, so it is
// always populated; the value itself is irrelevant to the chain walk.
func insertCA(t *testing.T, db *database.DB, id, label string, parent *string, cert *x509.Certificate) {
	t.Helper()
	ca := &models.CA{
		ID:        id,
		Label:     label,
		ParentID:  parent,
		KeyType:   "rsa2048",
		PublicKey: "test-public-key",
		CreatedAt: time.Now(),
	}
	if cert != nil {
		ca.Certificate = string(pemCert(cert))
		ca.Subject = cert.Subject.String()
		ca.Serial = cert.SerialNumber.String()
	}
	if err := db.CreateCA(ca); err != nil {
		t.Fatalf("CreateCA(%s): %v", id, err)
	}
}

// ---- resolveTSACAID --------------------------------------------------------

// TestResolveTSACAID covers every way the configured issuing-CA reference can be
// wrong. Each must produce a distinct, actionable startup error rather than a
// silently empty chain, because the resolved CA decides what certReq responses
// carry.
func TestResolveTSACAID(t *testing.T) {
	db := testDB(t)
	root := selfSignedCert(t, "root")
	insertCA(t, db, "ca-root", "root-label", nil, root)
	// A CA row that exists only as an SSH signing key: no X.509 certificate.
	insertCA(t, db, "ca-ssh", "ssh-only", nil, nil)

	tests := []struct {
		name    string
		caID    string
		caLabel string
		want    string
		wantErr string
	}{
		{"by id", "ca-root", "", "ca-root", ""},
		{"by label", "", "root-label", "ca-root", ""},
		// An id takes precedence: the label is not even looked up, so a stale
		// label alongside a good id must not fail.
		{"id wins over label", "ca-root", "no-such-label", "ca-root", ""},
		{"neither set", "", "", "", "no tsa issuing CA configured"},
		{"unknown id", "ca-missing", "", "", `tsa CA "ca-missing" not found`},
		{"unknown label", "", "missing-label", "", `label "missing-label" not found`},
		{"label resolves to an SSH-only CA", "", "ssh-only", "", "not an X.509 issuer"},
		{"id resolves to an SSH-only CA", "ca-ssh", "", "", "not an X.509 issuer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTSACAID(db, tc.caID, tc.caLabel)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("resolveTSACAID returned %q, want an error", got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("resolveTSACAID returned %q alongside error %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTSACAID: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolveTSACAID = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---- caChain ---------------------------------------------------------------

// TestCAChain walks the parent chain. Order is load-bearing: the result is
// appended after the TSA leaf and embedded in CMS SignedData, where a verifier
// expects issuer-before-root.
func TestCAChain(t *testing.T) {
	db := testDB(t)
	root := selfSignedCert(t, "root")
	inter := selfSignedCert(t, "intermediate")
	leafCA := selfSignedCert(t, "issuing")

	rootID := "ca-root"
	interID := "ca-inter"
	insertCA(t, db, rootID, "root", nil, root)
	insertCA(t, db, interID, "inter", &rootID, inter)
	insertCA(t, db, "ca-issuing", "issuing", &interID, leafCA)

	tests := []struct {
		name string
		caID string
		want []string
	}{
		{"root only", rootID, []string{"root"}},
		{"intermediate then root", interID, []string{"intermediate", "root"}},
		{"three levels, child first", "ca-issuing", []string{"issuing", "intermediate", "root"}},
		// An unknown id yields an empty chain with no error: the loop breaks on
		// a nil row. LoadAuthorityConfig only reaches caChain after
		// resolveTSACAID has proven the CA exists, so this is the not-reached
		// path — pinned so it stays a clean empty result rather than a panic.
		{"unknown id yields an empty chain", "ca-nope", nil},
		{"empty id yields an empty chain", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := caChain(db, tc.caID)
			if err != nil {
				t.Fatalf("caChain: %v", err)
			}
			if len(got) != len(tc.want) {
				var cns []string
				for _, c := range got {
					cns = append(cns, c.Subject.CommonName)
				}
				t.Fatalf("caChain returned %v, want %v", cns, tc.want)
			}
			for i, cn := range tc.want {
				if got[i].Subject.CommonName != cn {
					t.Fatalf("chain[%d] CN = %q, want %q", i, got[i].Subject.CommonName, cn)
				}
			}
		})
	}
}

// TestCAChainStopsAtMissingParent covers a dangling parent_id: the walk stops
// and returns the part it could resolve instead of erroring. That is the
// deliberate behavior (an externally signed subordinate keeps its parent out of
// the store), so it is pinned rather than left to chance.
func TestCAChainStopsAtMissingParent(t *testing.T) {
	db := testDB(t)
	parentID := "ca-root"
	root := selfSignedCert(t, "root")
	child := selfSignedCert(t, "child")
	insertCA(t, db, parentID, "root", nil, root)
	insertCA(t, db, "ca-child", "child", &parentID, child)

	// A CA whose parent row exists but carries no certificate (an SSH-only CA):
	// the walk must stop before it, not include an empty entry.
	sshID := "ca-ssh"
	insertCA(t, db, sshID, "ssh", nil, nil)
	insertCA(t, db, "ca-under-ssh", "under-ssh", &sshID, child)

	chain, err := caChain(db, "ca-under-ssh")
	if err != nil {
		t.Fatalf("caChain: %v", err)
	}
	if len(chain) != 1 || chain[0].Subject.CommonName != "child" {
		t.Fatalf("caChain returned %d certificates, want just the child", len(chain))
	}
}

// TestCAChainRejectsUnparseableCertificate checks a corrupt stored PEM is an
// error, not a silently shortened chain: a chain that is quietly missing its
// root produces tokens that fail path validation at the verifier, far from the
// cause.
func TestCAChainRejectsUnparseableCertificate(t *testing.T) {
	db := testDB(t)
	if err := db.CreateCA(&models.CA{
		ID: "ca-bad", Label: "bad", KeyType: "rsa2048", PublicKey: "pk",
		Certificate: "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	chain, err := caChain(db, "ca-bad")
	if err == nil {
		t.Fatalf("caChain accepted a corrupt stored certificate and returned %d entries", len(chain))
	}
	if !strings.Contains(err.Error(), "ca-bad") {
		t.Fatalf("error = %q, want it to name the offending CA", err)
	}
}

// TestCAChainTerminatesOnAParentCycle is the hang guard. cas.parent_id is a
// self-referencing foreign key, so a row may legally point at itself (or two
// rows at each other) — through a bad migration, a hand-edited store, or a
// future rotation bug. Walking such a chain without remembering where it has
// been never terminates and appends a certificate every iteration, so
// LoadAuthorityConfig would hang at server startup while consuming memory
// without bound. internal/ca/ct.go's issuerChainDER already guards this with a
// `seen` set; caChain must too.
func TestCAChainTerminatesOnAParentCycle(t *testing.T) {
	db := testDB(t)
	a := selfSignedCert(t, "a")
	b := selfSignedCert(t, "b")

	selfID := "ca-self"
	insertCA(t, db, selfID, "self", &selfID, a)

	// A two-node cycle, built with the store's dedicated test seam (which exists
	// for exactly this scenario — see database.SetCAParentForTest).
	aID := "ca-a"
	insertCA(t, db, aID, "a", nil, a)
	insertCA(t, db, "ca-b", "b", &aID, b)
	if err := db.SetCAParentForTest("ca-a", "ca-b"); err != nil {
		t.Fatalf("SetCAParentForTest: %v", err)
	}

	for _, id := range []string{selfID, "ca-a", "ca-b"} {
		t.Run(id, func(t *testing.T) {
			type result struct {
				chain []*x509.Certificate
				err   error
			}
			done := make(chan result, 1)
			go func() {
				chain, err := caChain(db, id)
				done <- result{chain, err}
			}()
			select {
			case r := <-done:
				if r.err != nil {
					t.Fatalf("caChain: %v", r.err)
				}
				// The exact truncation point does not matter; terminating with a
				// bounded chain does.
				if len(r.chain) == 0 || len(r.chain) > 4 {
					t.Fatalf("caChain returned %d certificates, want a small bounded chain", len(r.chain))
				}
			case <-time.After(10 * time.Second):
				t.Fatal("caChain did not terminate: the parent-chain walk loops forever on a cycle")
			}
		})
	}
}

// ---- LoadAuthorityConfig, database path ------------------------------------

// TestLoadAuthorityConfigAppendsCAChain covers the branch that exists only for a
// leaf-only certificate file: the issuing CA's stored chain is appended so
// certReq responses carry a verifiable path.
func TestLoadAuthorityConfigAppendsCAChain(t *testing.T) {
	db := testDB(t)
	root := selfSignedCert(t, "root")
	inter := selfSignedCert(t, "intermediate")
	rootID := "ca-root"
	interID := "ca-inter"
	insertCA(t, db, rootID, "root-label", nil, root)
	insertCA(t, db, interID, "inter-label", &rootID, inter)

	tsaLeaf := selfSignedCert(t, "tsa-leaf")
	path := writePEMFile(t, "leaf.pem", pemCert(tsaLeaf))

	for _, tc := range []struct {
		name string
		ref  config.TSAConfig
	}{
		{"by ca_id", config.TSAConfig{CAID: interID}},
		{"by ca_label", config.TSAConfig{CALabel: "inter-label"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := tc.ref
			ref.CertificateFile = path
			cfg, err := LoadAuthorityConfig(db, ref)
			if err != nil {
				t.Fatalf("LoadAuthorityConfig: %v", err)
			}
			want := []string{"tsa-leaf", "intermediate", "root"}
			if len(cfg.Chain) != len(want) {
				t.Fatalf("Chain has %d certificates, want %d", len(cfg.Chain), len(want))
			}
			for i, cn := range want {
				if cfg.Chain[i].Subject.CommonName != cn {
					t.Fatalf("Chain[%d] CN = %q, want %q", i, cfg.Chain[i].Subject.CommonName, cn)
				}
			}
			if cfg.Certificate != cfg.Chain[0] {
				t.Fatal("Certificate must be the TSA leaf, i.e. Chain[0]")
			}
		})
	}
}

// TestLoadAuthorityConfigCAResolutionErrors checks a leaf-only file plus a bad
// CA reference fails at startup. Falling through with a leaf-only chain would
// produce tokens that no client can build a path from, discovered only at
// verification time.
func TestLoadAuthorityConfigCAResolutionErrors(t *testing.T) {
	db := testDB(t)
	insertCA(t, db, "ca-ssh", "ssh-only", nil, nil)
	tsaLeaf := selfSignedCert(t, "tsa-leaf")
	path := writePEMFile(t, "leaf.pem", pemCert(tsaLeaf))

	tests := []struct {
		name    string
		ref     config.TSAConfig
		wantErr string
	}{
		{"unknown ca_id", config.TSAConfig{CAID: "nope"}, "not found"},
		{"unknown ca_label", config.TSAConfig{CALabel: "nope"}, "not found"},
		{"ca_label points at an SSH-only CA", config.TSAConfig{CALabel: "ssh-only"}, "not an X.509 issuer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref := tc.ref
			ref.CertificateFile = path
			cfg, err := LoadAuthorityConfig(db, ref)
			if err == nil {
				t.Fatalf("LoadAuthorityConfig accepted a bad CA reference: chain=%d", len(cfg.Chain))
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
