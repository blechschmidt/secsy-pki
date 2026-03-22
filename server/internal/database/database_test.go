//go:build sqlite

package database

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCALifecycle(t *testing.T) {
	db := testDB(t)

	ca := &models.CA{
		ID: "ca-1", Label: "Test CA", PKCS11URI: "pkcs11:test",
		KeyType: "ed25519", PublicKey: "ssh-ed25519 AAAA...",
	}
	if err := db.CreateCA(ca); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetCA("ca-1")
	if err != nil || got == nil {
		t.Fatal("GetCA failed")
	}
	if got.Label != "Test CA" {
		t.Errorf("label = %q", got.Label)
	}

	cas, err := db.ListCAs()
	if err != nil || len(cas) != 1 {
		t.Fatal("ListCAs failed")
	}

	// Not found
	got, err = db.GetCA("nonexistent")
	if err != nil || got != nil {
		t.Error("expected nil for nonexistent CA")
	}

	// Delete
	if err := db.DeleteCA("ca-1"); err != nil {
		t.Fatal(err)
	}
	cas, err = db.ListCAs()
	if err != nil || len(cas) != 0 {
		t.Error("expected 0 CAs after delete")
	}
}

func TestCAParentChild(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "root", Label: "Root", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})
	parentID := "root"
	db.CreateCA(&models.CA{ID: "child", ParentID: &parentID, Label: "Child", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	children, err := db.GetChildren("root")
	if err != nil || len(children) != 1 {
		t.Fatalf("GetChildren: %v, %d", err, len(children))
	}
	if children[0].ID != "child" {
		t.Error("wrong child")
	}
}

func TestDefaultRestrictionSet(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})
	rsID := "rs-1"
	db.SetCADefaultRestrictionSet("ca-1", &rsID)

	ca, _ := db.GetCA("ca-1")
	if ca.DefaultRestrictionSetID == nil || *ca.DefaultRestrictionSetID != "rs-1" {
		t.Error("default RS not set")
	}

	db.SetCADefaultRestrictionSet("ca-1", nil)
	ca, _ = db.GetCA("ca-1")
	if ca.DefaultRestrictionSetID != nil {
		t.Error("default RS should be nil")
	}
}

func TestGroupLifecycle(t *testing.T) {
	db := testDB(t)

	g := &models.Group{ID: "g-1", Name: "devs"}
	if err := db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetGroup("g-1")
	if err != nil || got == nil || got.Name != "devs" {
		t.Fatal("GetGroup failed")
	}

	groups, err := db.ListGroups()
	if err != nil || len(groups) != 1 {
		t.Fatal("ListGroups failed")
	}

	// Not found
	got, _ = db.GetGroup("nonexistent")
	if got != nil {
		t.Error("expected nil")
	}

	db.DeleteGroup("g-1")
	groups, _ = db.ListGroups()
	if len(groups) != 0 {
		t.Error("expected 0 groups")
	}
}

func TestGroupMembers(t *testing.T) {
	db := testDB(t)
	db.CreateGroup(&models.Group{ID: "g-1", Name: "devs"})

	db.AddGroupMember("g-1", "user-1")
	db.AddGroupMember("g-1", "user-2")
	db.AddGroupMember("g-1", "user-1") // duplicate

	members, _ := db.GetGroupMembers("g-1")
	if len(members) != 2 {
		t.Fatalf("members = %d", len(members))
	}

	groups, _ := db.GetUserGroups("user-1")
	if len(groups) != 1 || groups[0] != "g-1" {
		t.Errorf("user groups = %v", groups)
	}

	db.RemoveGroupMember("g-1", "user-1")
	members, _ = db.GetGroupMembers("g-1")
	if len(members) != 1 {
		t.Errorf("after remove: %d", len(members))
	}
}

func TestPermissions(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	p := &models.PermissionEntry{
		ID: "p-1", CAID: "ca-1", EntityType: "user",
		EntityID: "user-1", Permission: models.PermSignCertificate,
	}
	if err := db.GrantPermission(p); err != nil {
		t.Fatal(err)
	}

	perms, _ := db.GetPermissions("ca-1")
	if len(perms) != 1 {
		t.Fatalf("perms = %d", len(perms))
	}

	has, _ := db.HasPermission("ca-1", "user-1", models.PermSignCertificate, nil)
	if !has {
		t.Error("should have permission")
	}

	has, _ = db.HasPermission("ca-1", "user-1", models.PermManagePermissions, nil)
	if has {
		t.Error("should not have manage permission")
	}

	has, _ = db.HasPermission("ca-1", "user-2", models.PermSignCertificate, nil)
	if has {
		t.Error("user-2 should not have permission")
	}

	// Group permission
	db.CreateGroup(&models.Group{ID: "g-1", Name: "devs"})
	db.GrantPermission(&models.PermissionEntry{
		ID: "p-2", CAID: "ca-1", EntityType: "group",
		EntityID: "g-1", Permission: models.PermSignCertificate,
	})
	has, _ = db.HasPermission("ca-1", "user-3", models.PermSignCertificate, []string{"g-1"})
	if !has {
		t.Error("group member should have permission")
	}

	db.RevokePermission("ca-1", "user", "user-1", models.PermSignCertificate)
	perms, _ = db.GetPermissions("ca-1")
	if len(perms) != 1 {
		t.Errorf("after revoke: %d", len(perms))
	}
}

func TestRestrictionSetLifecycle(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	maxVal := int64(3600)
	rs := &models.RestrictionSet{
		ID: "rs-1", CAID: "ca-1", Name: "Standard",
		MaxValiditySecs:   &maxVal,
		AllowedPrincipals: []string{"admin", "deploy"},
		AllowedCertTypes:  []string{"user"},
		ForceKeyIDEmail:   true,
		RequireReason:     true,
		DenyExtensions:    true,
		DenyCriticalOptions: true,
		AllowedExtensions: []string{"permit-pty"},
	}
	if err := db.CreateRestrictionSet(rs); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetRestrictionSet("rs-1")
	if err != nil || got == nil {
		t.Fatal("GetRestrictionSet failed")
	}
	if got.Name != "Standard" || !got.ForceKeyIDEmail || !got.RequireReason {
		t.Errorf("rs = %+v", got)
	}
	if !got.DenyExtensions || !got.DenyCriticalOptions {
		t.Error("deny flags not set")
	}
	if len(got.AllowedPrincipals) != 2 {
		t.Errorf("principals = %v", got.AllowedPrincipals)
	}

	// Update
	got.Name = "Updated"
	got.RequireReason = false
	db.UpdateRestrictionSet(got)
	got, _ = db.GetRestrictionSet("rs-1")
	if got.Name != "Updated" || got.RequireReason {
		t.Errorf("after update: %+v", got)
	}

	// List
	sets, _ := db.ListRestrictionSets("ca-1")
	if len(sets) != 1 {
		t.Fatalf("sets = %d", len(sets))
	}

	// Not found
	got, _ = db.GetRestrictionSet("nonexistent")
	if got != nil {
		t.Error("expected nil")
	}

	// Delete
	db.DeleteRestrictionSet("rs-1")
	sets, _ = db.ListRestrictionSets("ca-1")
	if len(sets) != 0 {
		t.Error("expected 0 sets")
	}
}

func TestRestrictionSetX509(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	maxVal := int64(86400)
	pathLen := 0
	rs := &models.RestrictionSet{
		ID: "rs-x509", CAID: "ca-1", Name: "X509 Policy",
		Type:                models.RestrictionSetX509,
		MaxValiditySecs:     &maxVal,
		AllowedKeyUsages:    []string{"digitalSignature", "keyEncipherment"},
		AllowedExtKeyUsages: []string{"serverAuth", "clientAuth"},
		AllowedSANTypes:     []string{"dns", "ip"},
		AllowedSANPatterns:  []string{"*.example.com", "10.0.0.0/8"},
		AllowedSubjectFields: []string{"CN", "O"},
		MaxPathLength:       &pathLen,
		DenyCA:              true,
	}
	if err := db.CreateRestrictionSet(rs); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetRestrictionSet("rs-x509")
	if err != nil || got == nil {
		t.Fatal("GetRestrictionSet failed")
	}
	if got.Type != models.RestrictionSetX509 {
		t.Errorf("type = %q, want x509", got.Type)
	}
	if !got.DenyCA {
		t.Error("deny_ca should be true")
	}
	if len(got.AllowedKeyUsages) != 2 {
		t.Errorf("key_usages = %v", got.AllowedKeyUsages)
	}
	if len(got.AllowedExtKeyUsages) != 2 {
		t.Errorf("ext_key_usages = %v", got.AllowedExtKeyUsages)
	}
	if len(got.AllowedSANTypes) != 2 {
		t.Errorf("san_types = %v", got.AllowedSANTypes)
	}
	if len(got.AllowedSANPatterns) != 2 {
		t.Errorf("san_patterns = %v", got.AllowedSANPatterns)
	}
	if len(got.AllowedSubjectFields) != 2 {
		t.Errorf("subject_fields = %v", got.AllowedSubjectFields)
	}
	if got.MaxPathLength == nil || *got.MaxPathLength != 0 {
		t.Errorf("max_path_length = %v", got.MaxPathLength)
	}

	// List should show type
	sets, _ := db.ListRestrictionSets("ca-1")
	if len(sets) != 1 || sets[0].Type != models.RestrictionSetX509 {
		t.Errorf("list type = %v", sets)
	}

	// Update
	got.AllowedKeyUsages = []string{"digitalSignature"}
	got.DenyCA = false
	db.UpdateRestrictionSet(got)
	got, _ = db.GetRestrictionSet("rs-x509")
	if len(got.AllowedKeyUsages) != 1 || got.DenyCA {
		t.Errorf("after update: %+v", got)
	}

	db.DeleteRestrictionSet("rs-x509")
}

func TestRestrictionSetDefaultType(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	// Create without explicit type — should default to "ssh"
	rs := &models.RestrictionSet{ID: "rs-default", CAID: "ca-1", Name: "Default"}
	db.CreateRestrictionSet(rs)

	got, _ := db.GetRestrictionSet("rs-default")
	if got.Type != models.RestrictionSetSSH {
		t.Errorf("default type = %q, want ssh", got.Type)
	}
}

func TestEffectiveRestrictionSet(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})
	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-default", CAID: "ca-1", Name: "Default"})
	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-user", CAID: "ca-1", Name: "User"})

	db.SetCADefaultRestrictionSet("ca-1", strPtr("rs-default"))

	// Default
	rs, _ := db.GetEffectiveRestrictionSet("ca-1", "user-1", nil)
	if rs == nil || rs.Name != "Default" {
		t.Error("should get default RS")
	}

	// User override
	db.GrantPermission(&models.PermissionEntry{
		ID: "p-1", CAID: "ca-1", EntityType: "user", EntityID: "user-1",
		Permission: models.PermSignCertificate, RestrictionSetID: strPtr("rs-user"),
	})
	rs, _ = db.GetEffectiveRestrictionSet("ca-1", "user-1", nil)
	if rs == nil || rs.Name != "User" {
		t.Error("should get user-specific RS")
	}

	// No RS for user without override
	rs, _ = db.GetEffectiveRestrictionSet("ca-1", "user-2", nil)
	if rs == nil || rs.Name != "Default" {
		t.Error("should fall back to default")
	}
}

func strPtr(s string) *string { return &s }

func TestAuditLog(t *testing.T) {
	db := testDB(t)

	e := &models.AuditLogEntry{
		ID: "a-1", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "test", CertType: "user", Serial: "12345",
		PublicKey:  "ssh-ed25519 AAAA...",
		Principals: []string{"admin"},
	}
	if err := db.CreateAuditLogEntry(e); err != nil {
		t.Fatal(err)
	}

	entries, total, err := db.ListAuditLog("", 10, 0)
	if err != nil || total != 1 || len(entries) != 1 {
		t.Fatalf("list: %d %d %v", total, len(entries), err)
	}

	entries, total, _ = db.ListAuditLog("ca-1", 10, 0)
	if total != 1 {
		t.Error("filter by ca_id failed")
	}

	entries, total, _ = db.ListAuditLog("other", 10, 0)
	if total != 0 {
		t.Error("should be 0 for other ca")
	}
}

func TestAccessLog(t *testing.T) {
	db := testDB(t)

	db.CreateAccessLogEntry(&models.AccessLogEntry{
		ID: "al-1", UserSub: "user-1", Method: "GET", Path: "/api/cas", Status: 200, IP: "127.0.0.1",
	})

	entries, total, err := db.ListAccessLog(10, 0)
	if err != nil || total != 1 || len(entries) != 1 {
		t.Fatalf("access log: %d %d %v", total, len(entries), err)
	}
}

func TestHSMAuditEntries(t *testing.T) {
	db := testDB(t)

	entries := []models.HSMAuditEntry{
		{Number: 1, Command: 0xff, Length: 0xffff, SessionKey: 0xffff, TargetKey: 0xffff, SecondKey: 0xffff, Result: 0xff, Tick: 0xffffffff, Hash: "aabb"},
		{Number: 2, Command: 0x6a, Length: 6, SessionKey: 1, TargetKey: 0x50dd, SecondKey: 0xffff, Result: 0xea, Tick: 1000, Hash: "ccdd"},
	}
	if err := db.StoreHSMAuditEntries(entries); err != nil {
		t.Fatal(err)
	}

	export, err := db.ExportCombinedAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(export.HSMEntries) != 2 {
		t.Errorf("hsm entries = %d", len(export.HSMEntries))
	}
}

func TestPlaceholderConversion(t *testing.T) {
	db := &DB{driver: "postgres"}
	got := db.ph("SELECT * FROM t WHERE a = ? AND b = ? AND c = ?")
	want := "SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3"
	if got != want {
		t.Errorf("ph = %q, want %q", got, want)
	}

	db2 := &DB{driver: "sqlite"}
	got2 := db2.ph("SELECT * FROM t WHERE a = ?")
	if got2 != "SELECT * FROM t WHERE a = ?" {
		t.Errorf("sqlite ph = %q", got2)
	}
}

func TestIsPostgres(t *testing.T) {
	if (&DB{driver: "sqlite"}).isPostgres() {
		t.Error("sqlite is not postgres")
	}
	if !(&DB{driver: "postgres"}).isPostgres() {
		t.Error("postgres is postgres")
	}
	if !(&DB{driver: "postgresql"}).isPostgres() {
		t.Error("postgresql is postgres")
	}
}
