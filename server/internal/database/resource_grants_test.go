//go:build sqlite

package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// failingScanner stands in for a row whose columns cannot be decoded. The
// engines coerce rather than reject most malformed values, so a stub is the
// only way to reach the scan-failure branch.
var errScanFailed = errors.New("scan failed")

type failingScanner struct{ err error }

func (f failingScanner) Scan(...any) error { return f.err }

// Task 191 database-layer tests for resource-scoped grants — the rows that let a
// group administer exactly one sub-CA. They run on SQLite always and on
// PostgreSQL when SECSY_TEST_PG_DSN is set, because the upsert on the natural
// key and the IN-list expansion are the two places where the two engines' SQL
// could diverge.
//
// The ancestry walk gets its own coverage: every per-CA authorization decision
// runs it, so it must terminate on a corrupted parent chain rather than spin
// inside an authorization check.

func seedGrantCA(t *testing.T, db *DB, id string, parent string) {
	t.Helper()
	ca := &models.CA{ID: id, Label: id, PKCS11URI: "pkcs11:" + id, KeyType: "ecdsa-p256", PublicKey: "k"}
	if parent != "" {
		ca.ParentID = &parent
	}
	if err := db.CreateCA(ca); err != nil {
		t.Fatalf("CreateCA(%s): %v", id, err)
	}
}

func caRes(id string) rbac.Resource {
	return rbac.Resource{Type: rbac.ResourceCA, ID: id}
}

func keyRes(name string) rbac.Resource {
	return rbac.Resource{Type: rbac.ResourceSigningKey, ID: name}
}

func putGrant(t *testing.T, db *DB, id string, res rbac.Resource, entityType, entityID string, role rbac.ResourceRole, scope rbac.GrantScope) *models.ResourceGrant {
	t.Helper()
	g := &models.ResourceGrant{
		ID: id, ResourceType: res.Type, ResourceID: res.ID,
		EntityType: entityType, EntityID: entityID, Role: role, Scope: scope,
		CreatedBy: "root",
	}
	if err := db.PutResourceGrant(g); err != nil {
		t.Fatalf("PutResourceGrant(%s): %v", id, err)
	}
	return g
}

func testResourceGrantStore(t *testing.T, db *DB) {
	seedGrantCA(t, db, "root-ca", "")
	seedGrantCA(t, db, "sub-ca", "root-ca")

	// A grant stored with no scope comes back normalized to "self": the caller
	// must not have to guess whether an empty column means self or subtree.
	before := time.Now().UTC().Add(-time.Second)
	putGrant(t, db, "g-1", caRes("sub-ca"), rbac.EntityGroup, "payments", rbac.ResourceRoleCAAdmin, "")

	got, err := db.ListResourceGrants(caRes("sub-ca"))
	if err != nil || len(got) != 1 {
		t.Fatalf("ListResourceGrants = %+v (err %v), want 1 row", got, err)
	}
	stored := got[0]
	if stored.Scope != rbac.ScopeSelf {
		t.Errorf("scope = %q, want %q", stored.Scope, rbac.ScopeSelf)
	}
	if stored.EntityType != rbac.EntityGroup || stored.EntityID != "payments" ||
		stored.Role != rbac.ResourceRoleCAAdmin || stored.CreatedBy != "root" {
		t.Errorf("stored grant = %+v, want the payments/ca-admin grant created by root", stored)
	}
	if stored.CreatedAt.Before(before) || stored.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v (%v), want a UTC timestamp at or after %v", stored.CreatedAt, stored.CreatedAt.Location(), before)
	}
	if rule := stored.Grant(); rule.Resource != caRes("sub-ca") || rule.Scope != rbac.ScopeSelf {
		t.Errorf("projected rule = %+v, want a self-scoped grant on ca/sub-ca", rule)
	}

	// Re-granting the same entity the same role with a wider scope is an update,
	// not a second row — otherwise the evaluator would see the narrow rule and
	// the widened one side by side and the operator could not tell which applies.
	widened := &models.ResourceGrant{
		ID: "g-1-again", ResourceType: rbac.ResourceCA, ResourceID: "sub-ca",
		EntityType: rbac.EntityGroup, EntityID: "payments", Role: rbac.ResourceRoleCAAdmin,
		Scope: rbac.ScopeSubtree, CreatedAt: time.Date(2026, 8, 25, 9, 0, 0, 0, time.FixedZone("CEST", 2*3600)),
		CreatedBy: "ops",
	}
	if err := db.PutResourceGrant(widened); err != nil {
		t.Fatalf("PutResourceGrant (widen): %v", err)
	}
	got, err = db.ListResourceGrants(caRes("sub-ca"))
	if err != nil || len(got) != 1 {
		t.Fatalf("after widening: %+v (err %v), want still 1 row", got, err)
	}
	if got[0].Scope != rbac.ScopeSubtree || got[0].CreatedBy != "ops" {
		t.Errorf("widened grant = %+v, want scope subtree created by ops", got[0])
	}
	// An explicitly supplied timestamp is preserved, normalized to UTC.
	if !got[0].CreatedAt.Equal(widened.CreatedAt) || got[0].CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v (%v), want %v in UTC", got[0].CreatedAt, got[0].CreatedAt.Location(), widened.CreatedAt.UTC())
	}

	// A malformed grant is refused at the store, not silently written: a row the
	// evaluator drops would show up in `grant list` as authority that does
	// nothing.
	bad := &models.ResourceGrant{
		ID: "g-bad", ResourceType: rbac.ResourceCA, ResourceID: "sub-ca",
		EntityType: rbac.EntityUser, EntityID: "alice", Role: rbac.ResourceRoleKeyAdmin,
	}
	if err := db.PutResourceGrant(bad); err == nil || !strings.Contains(err.Error(), "invalid resource grant") {
		t.Errorf("PutResourceGrant(key role on a CA) error = %v, want an invalid-grant rejection", err)
	}
	badScope := &models.ResourceGrant{
		ID: "g-bad-2", ResourceType: rbac.ResourceSigningKey, ResourceID: "release",
		EntityType: rbac.EntityUser, EntityID: "alice", Role: rbac.ResourceRoleKeyAdmin,
		Scope: rbac.ScopeSubtree,
	}
	if err := db.PutResourceGrant(badScope); err == nil || !strings.Contains(err.Error(), "invalid resource grant") {
		t.Errorf("PutResourceGrant(subtree on a key) error = %v, want an invalid-grant rejection", err)
	}
	if all, err := db.ListAllResourceGrants(); err != nil || len(all) != 1 {
		t.Fatalf("after the two rejections: %d rows (err %v), want the 1 valid grant", len(all), err)
	}

	// A second entity on the same resource, plus grants on a different CA and on
	// a signing key, so the multi-resource lookup has something to discriminate.
	putGrant(t, db, "g-2", caRes("sub-ca"), rbac.EntityUser, "alice", rbac.ResourceRoleCAIssuer, rbac.ScopeSelf)
	putGrant(t, db, "g-3", caRes("root-ca"), rbac.EntityGroup, "platform", rbac.ResourceRoleCAAuditor, rbac.ScopeSubtree)
	putGrant(t, db, "g-4", keyRes("release"), rbac.EntityUser, "bob", rbac.ResourceRoleKeySigner, "")

	// ListResourceGrantsAt is the authorization path's query: a resource plus its
	// ancestors, in one round trip per type. Duplicates and unusable resources
	// are dropped rather than widening the IN list or erroring the request.
	at, err := db.ListResourceGrantsAt([]rbac.Resource{
		caRes("sub-ca"), caRes("root-ca"), caRes("sub-ca"),
		keyRes("release"),
		{Type: "not-a-type", ID: "x"},   // unknown type
		{Type: rbac.ResourceCA, ID: ""}, // empty id
	})
	if err != nil {
		t.Fatalf("ListResourceGrantsAt: %v", err)
	}
	if len(at) != 4 {
		t.Fatalf("ListResourceGrantsAt returned %d grants (%+v), want 4", len(at), at)
	}
	seen := map[string]bool{}
	for _, g := range at {
		seen[g.Grant().Key()] = true
	}
	for _, want := range []string{
		"ca/sub-ca|group|payments|ca-admin",
		"ca/sub-ca|user|alice|ca-issuer",
		"ca/root-ca|group|platform|ca-auditor",
		"signing-key/release|user|bob|key-signer",
	} {
		if !seen[want] {
			t.Errorf("ListResourceGrantsAt missing %s (got %v)", want, seen)
		}
	}

	// Asking about a resource nobody was granted returns nothing, not everything.
	if at, err := db.ListResourceGrantsAt([]rbac.Resource{caRes("unheard-of")}); err != nil || len(at) != 0 {
		t.Errorf("ListResourceGrantsAt(ungranted) = %+v (err %v), want empty", at, err)
	}
	if at, err := db.ListResourceGrantsAt(nil); err != nil || len(at) != 0 {
		t.Errorf("ListResourceGrantsAt(nil) = %+v (err %v), want empty", at, err)
	}

	// ListAllResourceGrants is what the evaluator loads; its order is fixed so a
	// review diff is stable.
	all, err := db.ListAllResourceGrants()
	if err != nil || len(all) != 4 {
		t.Fatalf("ListAllResourceGrants = %d rows (err %v), want 4", len(all), err)
	}
	var keys []string
	for _, g := range all {
		keys = append(keys, g.Grant().Key())
	}
	want := []string{
		"ca/root-ca|group|platform|ca-auditor",
		"ca/sub-ca|group|payments|ca-admin",
		"ca/sub-ca|user|alice|ca-issuer",
		"signing-key/release|user|bob|key-signer",
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("ListAllResourceGrants order = %v, want %v", keys, want)
			break
		}
	}

	// Revoking one grant reports that something was actually removed; revoking it
	// again reports that nothing was, so the API can answer 404 instead of
	// confirming a revocation that did nothing.
	removed, err := db.DeleteResourceGrant(caRes("sub-ca"), rbac.EntityUser, "alice", rbac.ResourceRoleCAIssuer)
	if err != nil || !removed {
		t.Fatalf("DeleteResourceGrant = %v (err %v), want true", removed, err)
	}
	removed, err = db.DeleteResourceGrant(caRes("sub-ca"), rbac.EntityUser, "alice", rbac.ResourceRoleCAIssuer)
	if err != nil || removed {
		t.Fatalf("second DeleteResourceGrant = %v (err %v), want false", removed, err)
	}

	// Deleting the resource clears every grant on it — a CA id that is later
	// reused must not inherit the previous owner's authority — and leaves the
	// grants on other resources alone.
	if err := db.DeleteResourceGrantsFor(caRes("sub-ca")); err != nil {
		t.Fatalf("DeleteResourceGrantsFor: %v", err)
	}
	if got, err := db.ListResourceGrants(caRes("sub-ca")); err != nil || len(got) != 0 {
		t.Errorf("grants on sub-ca after delete = %+v (err %v), want none", got, err)
	}
	all, err = db.ListAllResourceGrants()
	if err != nil || len(all) != 2 {
		t.Fatalf("remaining grants = %d (err %v), want 2 (root-ca and the signing key)", len(all), err)
	}
	// Clearing a resource that holds no grants is a no-op, not an error.
	if err := db.DeleteResourceGrantsFor(caRes("sub-ca")); err != nil {
		t.Errorf("DeleteResourceGrantsFor on an empty resource: %v", err)
	}
}

func testCAAncestors(t *testing.T, db *DB) {
	seedGrantCA(t, db, "root", "")
	seedGrantCA(t, db, "mid", "root")
	seedGrantCA(t, db, "leaf", "mid")

	// Nearest first — this is the order a subtree grant is resolved in.
	anc, err := db.GetCAAncestors("leaf")
	if err != nil || len(anc) != 2 || anc[0] != "mid" || anc[1] != "root" {
		t.Fatalf("GetCAAncestors(leaf) = %v (err %v), want [mid root]", anc, err)
	}
	if anc, err := db.GetCAAncestors("root"); err != nil || len(anc) != 0 {
		t.Errorf("GetCAAncestors(root) = %v (err %v), want none", anc, err)
	}
	// An unknown CA has no ancestors and is not an error: authorization asks
	// about ids that may have just been deleted.
	if anc, err := db.GetCAAncestors("gone"); err != nil || len(anc) != 0 {
		t.Errorf("GetCAAncestors(unknown) = %v (err %v), want none", anc, err)
	}

	// A corrupted hierarchy must not spin an authorization check: close the
	// chain into a cycle and the walk still terminates, reporting only the
	// distinct ancestors it saw before coming back around.
	if err := db.SetCAParentForTest("root", "leaf"); err != nil {
		t.Fatalf("SetCAParentForTest: %v", err)
	}
	anc, err = db.GetCAAncestors("leaf")
	if err != nil || len(anc) != 2 || anc[0] != "mid" || anc[1] != "root" {
		t.Fatalf("GetCAAncestors on a cycle = %v (err %v), want [mid root]", anc, err)
	}
}

func testCAAncestorsDepthBound(t *testing.T, db *DB) {
	// A chain deeper than the walk's bound is truncated rather than followed to
	// the end: inherited authority stops, the request does not.
	const chain = 40
	prev := ""
	for i := range chain {
		id := "deep-" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		seedGrantCA(t, db, id, prev)
		prev = id
	}
	anc, err := db.GetCAAncestors(prev)
	if err != nil {
		t.Fatalf("GetCAAncestors: %v", err)
	}
	if len(anc) != 32 {
		t.Fatalf("GetCAAncestors on a %d-deep chain returned %d ancestors, want the 32 the walk is bounded to", chain, len(anc))
	}
}

// testResourceGrantStoreErrors proves the store surfaces backend failures
// instead of reporting an empty grant set — a swallowed error here reads as
// "this principal holds no grants", which is a silent denial at best and, for
// code that treats the absence of rows as "unconstrained", a silent grant.
func testResourceGrantStoreErrors(t *testing.T, db *DB) {
	seedGrantCA(t, db, "err-ca", "")
	putGrant(t, db, "g-err", caRes("err-ca"), rbac.EntityUser, "alice", rbac.ResourceRoleCAAdmin, "")

	// A row that will not decode propagates the failure instead of yielding a
	// zero-valued grant (which would name no entity and authorize nothing, or —
	// worse — an empty entity id that a comparison could match).
	if _, err := scanResourceGrant(failingScanner{err: errScanFailed}); !errors.Is(err, errScanFailed) {
		t.Errorf("scanResourceGrant error = %v, want %v", err, errScanFailed)
	}

	// With the backend gone, every read and write reports the failure.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := db.ListResourceGrants(caRes("err-ca")); err == nil {
		t.Errorf("ListResourceGrants on a closed store returned no error")
	}
	if _, err := db.ListResourceGrantsAt([]rbac.Resource{caRes("err-ca")}); err == nil {
		t.Errorf("ListResourceGrantsAt on a closed store returned no error")
	}
	if _, err := db.ListAllResourceGrants(); err == nil {
		t.Errorf("ListAllResourceGrants on a closed store returned no error")
	}
	if err := db.PutResourceGrant(&models.ResourceGrant{
		ID: "g-x", ResourceType: rbac.ResourceCA, ResourceID: "err-ca",
		EntityType: rbac.EntityUser, EntityID: "alice", Role: rbac.ResourceRoleCAAdmin,
	}); err == nil {
		t.Errorf("PutResourceGrant on a closed store returned no error")
	}
	if _, err := db.DeleteResourceGrant(caRes("err-ca"), rbac.EntityUser, "alice", rbac.ResourceRoleCAAdmin); err == nil {
		t.Errorf("DeleteResourceGrant on a closed store returned no error")
	}
	if err := db.DeleteResourceGrantsFor(caRes("err-ca")); err == nil {
		t.Errorf("DeleteResourceGrantsFor on a closed store returned no error")
	}
	if err := db.SetCAParentForTest("err-ca", "err-ca"); err == nil {
		t.Errorf("SetCAParentForTest on a closed store returned no error")
	}
	if _, err := db.GetCAAncestors("err-ca"); err == nil {
		t.Errorf("GetCAAncestors on a closed store returned no error")
	}
}

func TestResourceGrantStoreSQLite(t *testing.T)    { testResourceGrantStore(t, testDB(t)) }
func TestCAAncestorsSQLite(t *testing.T)           { testCAAncestors(t, testDB(t)) }
func TestCAAncestorsDepthBoundSQLite(t *testing.T) { testCAAncestorsDepthBound(t, testDB(t)) }
func TestResourceGrantStoreErrorsSQLite(t *testing.T) {
	testResourceGrantStoreErrors(t, testDB(t))
}

// --- PostgreSQL (when SECSY_TEST_PG_DSN is set) ---

func TestResourceGrantStorePostgres(t *testing.T) { testResourceGrantStore(t, freshPostgres(t)) }
func TestCAAncestorsPostgres(t *testing.T)        { testCAAncestors(t, freshPostgres(t)) }
func TestCAAncestorsDepthBoundPostgres(t *testing.T) {
	testCAAncestorsDepthBound(t, freshPostgres(t))
}
