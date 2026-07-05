//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestRelaxACMEAuthzOrderIDNullable_SQLiteRebuild verifies the Task 134 migration
// that relaxes acme_authorizations.order_id from NOT NULL to nullable on a
// pre-existing SQLite database. It simulates the old schema, seeds an order-bound
// authorization with a challenge, and confirms the FK-safe table rebuild:
//   - preserves the order-bound authorization and (critically) does not
//     cascade-delete its challenge rows,
//   - makes standalone (NULL order_id) pre-authorizations insertable afterwards,
//   - is idempotent when run again on the already-migrated schema.
func TestRelaxACMEAuthzOrderIDNullable_SQLiteRebuild(t *testing.T) {
	db, err := New("sqlite", t.TempDir()+"/old.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Recreate the pre-Task-134 schema: order_id NOT NULL. foreign_keys is toggled
	// off for the swap exactly as the migration does.
	old := []string{
		`PRAGMA foreign_keys=OFF`,
		`DROP TABLE acme_authorizations`,
		`CREATE TABLE acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			expires TIMESTAMP NOT NULL,
			wildcard INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id)`,
		`PRAGMA foreign_keys=ON`,
	}
	for _, stmt := range old {
		if _, err := db.conn.Exec(stmt); err != nil {
			t.Fatalf("recreate old schema %q: %v", stmt[:20], err)
		}
	}

	// Seed an account, order, order-bound authorization, and a challenge on it.
	if err := db.CreateACMEAccount(&models.ACMEAccount{ID: "acct1", JWK: "{}", Thumbprint: "tp1"}); err != nil {
		t.Fatalf("CreateACMEAccount: %v", err)
	}
	if err := db.CreateACMEOrder(&models.ACMEOrder{
		ID: "order1", AccountID: "acct1", Status: models.ACMEOrderStatusPending, Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateACMEOrder: %v", err)
	}
	if err := db.CreateACMEAuthorization(&models.ACMEAuthorization{
		ID: "authz1", OrderID: "order1", AccountID: "acct1", IdentifierType: "dns",
		IdentifierValue: "a.example", Status: "pending", Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateACMEAuthorization: %v", err)
	}
	if err := db.CreateACMEChallenge(&models.ACMEChallenge{
		ID: "chall1", AuthzID: "authz1", Type: "http-01", Token: "tok", Status: "pending",
	}); err != nil {
		t.Fatalf("CreateACMEChallenge: %v", err)
	}

	// Precondition: a standalone (NULL order_id) insert must fail on the old schema.
	standalone := &models.ACMEAuthorization{
		ID: "authz2", OrderID: "", AccountID: "acct1", IdentifierType: "dns",
		IdentifierValue: "b.example", Status: "pending", Expires: time.Now().Add(time.Hour),
	}
	if err := db.CreateACMEAuthorization(standalone); err == nil {
		t.Fatal("expected a NOT NULL violation inserting a standalone authorization on the old schema")
	}

	// Run the migration.
	db.relaxACMEAuthzOrderIDNullable()

	// The order-bound authorization survives unchanged...
	if a, err := db.GetACMEAuthorization("authz1"); err != nil || a == nil || a.OrderID != "order1" {
		t.Fatalf("order-bound authorization lost/altered after rebuild: %+v (%v)", a, err)
	}
	// ...and its challenge was NOT cascade-deleted by the DROP TABLE.
	if challs, err := db.ListACMEChallengesByAuthz("authz1"); err != nil || len(challs) != 1 {
		t.Fatalf("challenge cascade-deleted during rebuild: got %d (%v)", len(challs), err)
	}

	// A standalone pre-authorization is now insertable and stored with NULL order_id.
	if err := db.CreateACMEAuthorization(standalone); err != nil {
		t.Fatalf("standalone authorization still rejected after migration: %v", err)
	}
	if got, err := db.GetACMEAuthorization("authz2"); err != nil || got == nil || got.OrderID != "" {
		t.Fatalf("standalone authorization not stored with an empty order id: %+v (%v)", got, err)
	}

	// Idempotency: a second run is a no-op that preserves the data.
	db.relaxACMEAuthzOrderIDNullable()
	if got, err := db.GetACMEAuthorization("authz2"); err != nil || got == nil {
		t.Fatalf("data lost after an idempotent re-run: %+v (%v)", got, err)
	}
}

// TestFindReusableACMEPreAuthorization verifies the reuse query only returns
// unclaimed, unexpired, identifier-matching standalone pre-authorizations, and
// that ClaimACMEPreAuthorization is an atomic single-winner link.
func TestFindReusableACMEPreAuthorization(t *testing.T) {
	db, err := New("sqlite", t.TempDir()+"/reuse.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.CreateACMEAccount(&models.ACMEAccount{ID: "acct", JWK: "{}", Thumbprint: "tp"}); err != nil {
		t.Fatalf("CreateACMEAccount: %v", err)
	}
	now := time.Now().UTC()
	mk := func(id, val, status string, expires time.Time, wildcard bool) {
		t.Helper()
		if err := db.CreateACMEAuthorization(&models.ACMEAuthorization{
			ID: id, OrderID: "", AccountID: "acct", IdentifierType: "dns",
			IdentifierValue: val, Status: status, Expires: expires, Wildcard: wildcard,
		}); err != nil {
			t.Fatalf("seed authz %s: %v", id, err)
		}
	}
	mk("valid1", "reuse.example", models.ACMEAuthzStatusValid, now.Add(time.Hour), false)
	mk("expired", "gone.example", models.ACMEAuthzStatusValid, now.Add(-time.Hour), false)
	mk("wild", "wild.example", models.ACMEAuthzStatusValid, now.Add(time.Hour), true)

	// A matching, live, non-wildcard pre-authorization is returned.
	got, err := db.FindReusableACMEPreAuthorization("acct", "dns", "reuse.example", false, now)
	if err != nil || got == nil || got.ID != "valid1" {
		t.Fatalf("FindReusable = %+v (%v), want valid1", got, err)
	}
	// An expired one is not.
	if got, _ := db.FindReusableACMEPreAuthorization("acct", "dns", "gone.example", false, now); got != nil {
		t.Fatalf("expired authorization returned: %+v", got)
	}
	// A wildcard mismatch (order asks non-wildcard) is not.
	if got, _ := db.FindReusableACMEPreAuthorization("acct", "dns", "wild.example", false, now); got != nil {
		t.Fatalf("wildcard authorization returned for non-wildcard lookup: %+v", got)
	}

	// Claiming is atomic: the first claim wins, a second finds it already taken.
	if err := db.CreateACMEOrder(&models.ACMEOrder{ID: "o1", AccountID: "acct", Status: models.ACMEOrderStatusPending, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatalf("CreateACMEOrder: %v", err)
	}
	won, err := db.ClaimACMEPreAuthorization("valid1", "o1")
	if err != nil || !won {
		t.Fatalf("first claim = %v (%v), want true", won, err)
	}
	if again, _ := db.ClaimACMEPreAuthorization("valid1", "o1"); again {
		t.Fatal("second claim unexpectedly succeeded; claim is not single-winner")
	}
	// Once claimed it is no longer reusable.
	if got, _ := db.FindReusableACMEPreAuthorization("acct", "dns", "reuse.example", false, now); got != nil {
		t.Fatalf("claimed authorization still reusable: %+v", got)
	}
}

// TestACMEPreAuthorization_Postgres runs the pre-authorization storage path — a
// standalone (NULL order_id) authorization, the reuse query, and the atomic claim
// — against real PostgreSQL, exercising the stricter type handling (bool binding,
// IN list, timestamp comparison, NULL scan) the SQLite tests cannot. It also
// verifies the DROP NOT NULL relax migration is correct and idempotent on PG.
func TestACMEPreAuthorization_Postgres(t *testing.T) {
	db := freshPostgres(t)

	if err := db.CreateACMEAccount(&models.ACMEAccount{ID: "acct", JWK: "{}", Thumbprint: "tp"}); err != nil {
		t.Fatalf("CreateACMEAccount: %v", err)
	}
	now := time.Now().UTC()

	// A standalone pre-authorization stores and scans back with an empty order id.
	if err := db.CreateACMEAuthorization(&models.ACMEAuthorization{
		ID: "pa1", OrderID: "", AccountID: "acct", IdentifierType: "dns",
		IdentifierValue: "pg.example", Status: models.ACMEAuthzStatusValid, Expires: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateACMEAuthorization (standalone): %v", err)
	}
	if got, err := db.GetACMEAuthorization("pa1"); err != nil || got == nil || got.OrderID != "" {
		t.Fatalf("standalone authz scan = %+v (%v), want empty order id", got, err)
	}

	// Reuse query + atomic claim.
	got, err := db.FindReusableACMEPreAuthorization("acct", "dns", "pg.example", false, now)
	if err != nil || got == nil || got.ID != "pa1" {
		t.Fatalf("FindReusable = %+v (%v), want pa1", got, err)
	}
	if err := db.CreateACMEOrder(&models.ACMEOrder{ID: "po1", AccountID: "acct", Status: models.ACMEOrderStatusPending, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatalf("CreateACMEOrder: %v", err)
	}
	if won, err := db.ClaimACMEPreAuthorization("pa1", "po1"); err != nil || !won {
		t.Fatalf("claim = %v (%v), want true", won, err)
	}
	if again, _ := db.ClaimACMEPreAuthorization("pa1", "po1"); again {
		t.Fatal("second claim succeeded; claim is not single-winner on PG")
	}

	// Relax migration: simulate the pre-Task-134 NOT NULL constraint, confirm a
	// standalone insert is rejected, then relax and confirm it is accepted. Uses a
	// distinct order so the SET NOT NULL succeeds (no NULL order_id rows exist yet).
	if _, err := db.conn.Exec(`UPDATE acme_authorizations SET order_id = 'po1' WHERE order_id IS NULL`); err != nil {
		t.Fatalf("pre-clean NULLs: %v", err)
	}
	if _, err := db.conn.Exec(`ALTER TABLE acme_authorizations ALTER COLUMN order_id SET NOT NULL`); err != nil {
		t.Fatalf("simulate old NOT NULL schema: %v", err)
	}
	if err := db.CreateACMEAuthorization(&models.ACMEAuthorization{
		ID: "pa2", OrderID: "", AccountID: "acct", IdentifierType: "dns",
		IdentifierValue: "pg2.example", Status: models.ACMEAuthzStatusPending, Expires: now.Add(time.Hour),
	}); err == nil {
		t.Fatal("expected NOT NULL violation on the simulated old PG schema")
	}
	db.relaxACMEAuthzOrderIDNullable()
	if err := db.CreateACMEAuthorization(&models.ACMEAuthorization{
		ID: "pa2", OrderID: "", AccountID: "acct", IdentifierType: "dns",
		IdentifierValue: "pg2.example", Status: models.ACMEAuthzStatusPending, Expires: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("standalone insert still rejected after PG relax: %v", err)
	}
	// Idempotent second run.
	db.relaxACMEAuthzOrderIDNullable()
}
