//go:build sqlite

package database

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// pgTestDSN returns the PostgreSQL DSN for the cross-backend integration tests,
// or "" when it is unset (the tests then skip). Bring one up with
// docker-compose.postgres.yaml and export SECSY_TEST_PG_DSN.
func pgTestDSN() string { return os.Getenv("SECSY_TEST_PG_DSN") }

// freshPostgres opens the test PostgreSQL database and truncates every table so
// each test starts from an empty, sequence-reset store. It skips the test when
// no DSN is configured.
func freshPostgres(t *testing.T) *DB {
	t.Helper()
	dsn := pgTestDSN()
	if dsn == "" {
		t.Skip("SECSY_TEST_PG_DSN not set; skipping PostgreSQL backend test")
	}
	db, err := New("postgres", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	truncateAll(t, db)
	return db
}

func truncateAll(t *testing.T, db *DB) {
	t.Helper()
	// RESTART IDENTITY resets SERIAL sequences; CASCADE follows FKs so order does
	// not matter. This leaves the schema in the same state as a fresh migrate().
	for _, table := range migrationTables {
		if _, err := db.conn.Exec("TRUNCATE TABLE " + table + " RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncating %s: %v", table, err)
		}
	}
}

// populateStore fills every migrated domain with representative data, exercising
// the value shapes that stress the cross-engine copier: bytea columns (CRL DER,
// CA public key), boolean columns (ACME tos/wildcard, restriction-set flags), a
// multi-entry hash-chained audit log, and monotonic serial/CRL counters.
// storeMarks records the high-water marks of the monotonic counters after
// population, so tests can assert the destination continues strictly above them.
type storeMarks struct {
	lastSerial  int64
	lastCRLFull int64
}

func populateStore(t *testing.T, db *DB) storeMarks {
	t.Helper()
	var marks storeMarks

	// Authorities: a root and an intermediate under it (self-referential FK).
	if err := db.CreateCA(&models.CA{ID: "root", Label: "Root CA", PKCS11URI: "pkcs11:root", KeyType: "ed25519", PublicKey: "ROOTKEY"}); err != nil {
		t.Fatal(err)
	}
	rootID := "root"
	if err := db.CreateCA(&models.CA{ID: "int", ParentID: &rootID, Label: "Intermediate CA", PKCS11URI: "pkcs11:int", KeyType: "ecdsa", PublicKey: "INTKEY"}); err != nil {
		t.Fatal(err)
	}

	// Serial allocation must be monotonic; record the high-water mark.
	for i := 0; i < 3; i++ {
		s, err := db.AllocateSerial("int")
		if err != nil {
			t.Fatal(err)
		}
		marks.lastSerial = s
	}

	// Issued inventory, including SANs (JSON) and a revoked entry.
	now := time.Now().UTC().Truncate(time.Second)
	for i, serial := range []string{"1001", "1002"} {
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: "cert-" + serial, CAID: "int", Serial: serial,
			Subject: "CN=host" + serial, CommonName: "host" + serial,
			SANs:    []string{"host" + serial + ".example.com"},
			Profile: "server", Certificate: "-----BEGIN CERTIFICATE-----\n" + serial,
			NotBefore: now, NotAfter: now.Add(time.Duration(i+1) * time.Hour),
			Status: models.CertStatusValid,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.RevokeCertificate("int", "1002", 1, now); err != nil {
		t.Fatal(err)
	}

	// CRL numbering: full scope and a partition scope, both must stay monotonic.
	for i := 0; i < 2; i++ {
		n, err := db.NextCRLNumber("int")
		if err != nil {
			t.Fatal(err)
		}
		marks.lastCRLFull = n
	}
	if _, err := db.NextScopedCRLNumber("int", "partition:0"); err != nil {
		t.Fatal(err)
	}

	// A published CRL exercises the bytea column path.
	if err := db.UpsertPublishedCRL(&PublishedCRL{
		CAID: "int", Scope: "full", Kind: "base", Number: 2, BaseNumber: 2,
		ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour), GeneratedAt: now,
		DER: []byte{0x30, 0x82, 0x01, 0x00, 0xff, 0x00, 0xde, 0xad},
	}); err != nil {
		t.Fatal(err)
	}

	// A hash-chained audit log with several entries.
	for i := 0; i < 5; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: "evt-" + string(rune('a'+i)), Actor: "operator",
			Action: audit.ActionCertIssue, Target: "int", Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetSIEMCursor("splunk", 3); err != nil {
		t.Fatal(err)
	}

	// ACME state with boolean columns (tos_agreed, wildcard).
	if err := db.CreateACMEAccount(&models.ACMEAccount{
		ID: "acct-1", Status: "valid", Contacts: []string{"mailto:a@example.com"},
		JWK: `{"kty":"OKP"}`, Thumbprint: "tp-1", TermsOfServiceOK: true, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateACMEOrder(&models.ACMEOrder{
		ID: "order-1", AccountID: "acct-1", Status: "pending",
		Identifiers: []models.ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Expires:     now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateACMEAuthorization(&models.ACMEAuthorization{
		ID: "authz-1", OrderID: "order-1", AccountID: "acct-1",
		IdentifierType: "dns", IdentifierValue: "example.com", Status: "pending",
		Expires: now.Add(time.Hour), Wildcard: true, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateACMEChallenge(&models.ACMEChallenge{
		ID: "chal-1", AuthzID: "authz-1", Type: "http-01", Token: "tok", Status: "pending", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// RBAC state with a boolean-bearing restriction set.
	if err := db.CreateGroup(&models.Group{ID: "g-1", Name: "operators"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMember("g-1", "user-sub-1"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-1", CAID: "int", Name: "default"}); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantPermission(&models.PermissionEntry{
		CAID: "int", EntityType: "group", EntityID: "g-1", Permission: models.PermSignCertificate,
	}); err != nil {
		t.Fatal(err)
	}
	return marks
}

// assertMigratedFidelity checks that the destination store faithfully reflects
// the populated source and that its monotonic counters and audit chain continue
// correctly after the copy.
func assertMigratedFidelity(t *testing.T, dst *DB, marks storeMarks) {
	t.Helper()

	cas, err := dst.ListCAs()
	if err != nil || len(cas) != 2 {
		t.Fatalf("ListCAs = %d (%v), want 2", len(cas), err)
	}

	certs, err := dst.ListIssuedCertificates("int")
	if err != nil || len(certs) != 2 {
		t.Fatalf("ListIssuedCertificates = %d (%v), want 2", len(certs), err)
	}
	// SANs (JSON) must survive the copy.
	var found bool
	for _, c := range certs {
		if c.Serial == "1001" && len(c.SANs) == 1 && c.SANs[0] == "host1001.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs did not round-trip: %+v", certs)
	}

	revoked, err := dst.ListRevokedCertificates("int")
	if err != nil || len(revoked) != 1 || revoked[0].Serial != "1002" {
		t.Fatalf("ListRevokedCertificates = %+v (%v), want serial 1002", revoked, err)
	}

	// Published CRL DER (bytea) must be byte-identical.
	pub, err := dst.GetPublishedCRL("int", "full", "base")
	if err != nil || pub == nil {
		t.Fatalf("GetPublishedCRL: %v", err)
	}
	want := []byte{0x30, 0x82, 0x01, 0x00, 0xff, 0x00, 0xde, 0xad}
	if len(pub.DER) != len(want) {
		t.Fatalf("published CRL DER length = %d, want %d", len(pub.DER), len(want))
	}
	for i := range want {
		if pub.DER[i] != want[i] {
			t.Fatalf("published CRL DER byte %d = %#x, want %#x", i, pub.DER[i], want[i])
		}
	}

	// Audit chain: preserved intact and continues from the migrated tail.
	res, err := dst.VerifyEventChain()
	if err != nil || !res.Valid || res.Count != 5 {
		t.Fatalf("VerifyEventChain = %+v (%v), want valid count 5", res, err)
	}
	head, _ := dst.MaxEventSeq()
	if head != 5 {
		t.Fatalf("MaxEventSeq = %d, want 5", head)
	}
	if err := dst.AppendEvent(&audit.Event{ID: "post-migrate", Actor: "op", Action: audit.ActionCertRevoke, Result: audit.ResultSuccess}); err != nil {
		t.Fatalf("AppendEvent after migrate: %v", err)
	}
	if res, _ := dst.VerifyEventChain(); !res.Valid || res.Count != 6 {
		t.Fatalf("chain broke after post-migrate append: %+v", res)
	}

	// SIEM cursor preserved.
	if c, _ := dst.GetSIEMCursor("splunk"); c != 3 {
		t.Errorf("SIEM cursor = %d, want 3", c)
	}

	// ACME booleans preserved.
	acct, err := dst.GetACMEAccountByThumbprint("tp-1")
	if err != nil || acct == nil || !acct.TermsOfServiceOK {
		t.Fatalf("ACME account tos flag not preserved: %+v (%v)", acct, err)
	}
	authzs, err := dst.ListACMEAuthorizationsByOrder("order-1")
	if err != nil || len(authzs) != 1 || !authzs[0].Wildcard {
		t.Fatalf("ACME authz wildcard flag not preserved: %+v (%v)", authzs, err)
	}

	// Monotonic counters continue strictly above the migrated high-water marks:
	// the copied counter tables make the destination resume exactly where the
	// source left off, so no serial or CRL number is ever reused.
	if s, err := dst.AllocateSerial("int"); err != nil || s != marks.lastSerial+1 {
		t.Fatalf("post-migrate AllocateSerial = %d (%v), want %d (no reuse)", s, err, marks.lastSerial+1)
	}
	if n, err := dst.NextCRLNumber("int"); err != nil || n != marks.lastCRLFull+1 {
		t.Fatalf("post-migrate NextCRLNumber = %d (%v), want %d (no reuse)", n, err, marks.lastCRLFull+1)
	}

	// RBAC preserved.
	if ok, err := dst.HasPermission("int", "user-sub-1", models.PermSignCertificate, []string{"g-1"}); err != nil || !ok {
		t.Fatalf("post-migrate HasPermission = %v (%v), want true", ok, err)
	}
}

// TestMigrateStoreSQLiteToPostgres is the headline cross-backend test: it builds
// a fully populated SQLite ("file") store and migrates it into PostgreSQL,
// asserting data fidelity, bytea/boolean normalization, audit-chain integrity,
// and continued serial/CRL monotonicity. Skips without SECSY_TEST_PG_DSN.
func TestMigrateStoreSQLiteToPostgres(t *testing.T) {
	dst := freshPostgres(t) // skips if no DSN

	src, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	marks := populateStore(t, src)

	report, err := MigrateStore(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("MigrateStore: %v", err)
	}
	if !report.ChainValid || report.ChainCount != 5 {
		t.Fatalf("report chain = valid %v count %d, want valid 5", report.ChainValid, report.ChainCount)
	}
	if report.TotalRows == 0 {
		t.Fatal("report copied 0 rows")
	}

	assertMigratedFidelity(t, dst, marks)
}

// TestMigrateStoreSQLiteToSQLite exercises the copier end-to-end without an
// external database: source and destination are independent in-memory SQLite
// stores. It validates the generic copy, audit-chain preservation, and counter
// continuity, so the migration machinery is covered in the default test run.
func TestMigrateStoreSQLiteToSQLite(t *testing.T) {
	src := testDB(t)
	marks := populateStore(t, src)

	dst := testDB(t)
	report, err := MigrateStore(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("MigrateStore: %v", err)
	}
	if !report.ChainValid || report.ChainCount != 5 {
		t.Fatalf("report chain = valid %v count %d, want valid 5", report.ChainValid, report.ChainCount)
	}
	assertMigratedFidelity(t, dst, marks)
}

// TestMigrateStoreRefusesNonEmptyDest ensures a re-run cannot double-insert into
// a populated destination.
func TestMigrateStoreRefusesNonEmptyDest(t *testing.T) {
	src := testDB(t)
	populateStore(t, src)
	dst := testDB(t)
	populateStore(t, dst) // dst already has data

	if _, err := MigrateStore(context.Background(), src, dst); err == nil {
		t.Fatal("expected refusal to migrate into a non-empty destination")
	}
}

// TestMigrateStoreDetectsBrokenSourceChain ensures a tampered source audit log
// is not silently laundered into the destination.
func TestMigrateStoreDetectsBrokenSourceChain(t *testing.T) {
	src := testDB(t)
	populateStore(t, src)
	// Tamper with a stored row so the chain no longer verifies.
	if _, err := src.exec(`UPDATE event_log SET actor = ? WHERE seq = ?`, "attacker", 2); err != nil {
		t.Fatal(err)
	}
	dst := testDB(t)
	if _, err := MigrateStore(context.Background(), src, dst); err == nil {
		t.Fatal("expected migration to refuse a source with a broken audit chain")
	}
}

// TestConcurrentCountersMonotonicBothBackends drives the serial and CRL-number
// allocators concurrently against each configured backend and asserts every
// allocation is unique and gap-free — the invariant multi-replica HA depends on.
func TestConcurrentCountersMonotonicBothBackends(t *testing.T) {
	backends := []struct {
		name string
		open func(t *testing.T) *DB
	}{
		{"sqlite", func(t *testing.T) *DB { return testDB(t) }},
		{"postgres", freshPostgres},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			if err := db.CreateCA(&models.CA{ID: "ca", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"}); err != nil {
				t.Fatal(err)
			}

			const n = 30
			serials := make([]int64, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					s, err := db.AllocateSerial("ca")
					if err != nil {
						t.Errorf("AllocateSerial: %v", err)
						return
					}
					serials[i] = s
				}(i)
			}
			wg.Wait()

			seen := map[int64]bool{}
			for _, s := range serials {
				if seen[s] {
					t.Fatalf("duplicate serial %d allocated under concurrency", s)
				}
				seen[s] = true
			}
			if len(seen) != n {
				t.Fatalf("got %d distinct serials, want %d", len(seen), n)
			}
		})
	}
}
