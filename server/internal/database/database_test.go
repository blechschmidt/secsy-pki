//go:build sqlite

package database

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Aliases to avoid stuttering and make test code more concise
var (
	ed25519GenerateKey      = ed25519.GenerateKey
	sshNewPublicKey         = ssh.NewPublicKey
	sshMarshalAuthorizedKey = ssh.MarshalAuthorizedKey
	sshNewSignerFromSigner  = ssh.NewSignerFromSigner
	randReader              = rand.Reader
)

type sshCertificate = ssh.Certificate
type sshPermissions = ssh.Permissions

const sshUserCert = ssh.UserCert

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
	db.SetCADefaultRestrictionSet("ca-1", "ssh", &rsID)

	ca, _ := db.GetCA("ca-1")
	if ca.DefaultSSHRestrictionSetID == nil || *ca.DefaultSSHRestrictionSetID != "rs-1" {
		t.Error("default SSH RS not set")
	}

	db.SetCADefaultRestrictionSet("ca-1", "ssh", nil)
	ca, _ = db.GetCA("ca-1")
	if ca.DefaultSSHRestrictionSetID != nil {
		t.Error("default SSH RS should be nil")
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
		MaxValiditySecs:     &maxVal,
		AllowedPrincipals:   []string{"admin", "deploy"},
		AllowedCertTypes:    []string{"user"},
		ForceKeyIDEmail:     true,
		RequireReason:       true,
		DenyExtensions:      true,
		DenyCriticalOptions: true,
		AllowedExtensions:   []string{"permit-pty"},
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

	// List (includes 4 built-in global sets + 1 CA-specific)
	sets, _ := db.ListRestrictionSets("ca-1")
	caSpecific := 0
	for _, s := range sets {
		if s.CAID == "ca-1" {
			caSpecific++
		}
	}
	if caSpecific != 1 {
		t.Fatalf("ca-specific sets = %d, want 1", caSpecific)
	}

	// Not found
	got, _ = db.GetRestrictionSet("nonexistent")
	if got != nil {
		t.Error("expected nil")
	}

	// Delete
	db.DeleteRestrictionSet("rs-1")
	sets, _ = db.ListRestrictionSets("ca-1")
	caSpecific = 0
	for _, s := range sets {
		if s.CAID == "ca-1" {
			caSpecific++
		}
	}
	if caSpecific != 0 {
		t.Errorf("expected 0 ca-specific sets, got %d", caSpecific)
	}
}

func TestRestrictionSetX509(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	maxVal := int64(86400)
	pathLen := 0
	rs := &models.RestrictionSet{
		ID: "rs-x509", CAID: "ca-1", Name: "X509 Policy",
		Type:                 models.RestrictionSetX509,
		MaxValiditySecs:      &maxVal,
		AllowedKeyUsages:     []string{"digitalSignature", "keyEncipherment"},
		AllowedExtKeyUsages:  []string{"serverAuth", "clientAuth"},
		AllowedSANTypes:      []string{"dns", "ip"},
		AllowedSANPatterns:   []string{"*.example.com", "10.0.0.0/8"},
		AllowedSubjectFields: []string{"CN", "O"},
		MaxPathLength:        &pathLen,
		DenyCA:               true,
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

	// List should include x509 set
	sets, _ := db.ListRestrictionSets("ca-1")
	found := false
	for _, s := range sets {
		if s.ID == "rs-x509" && s.Type == models.RestrictionSetX509 {
			found = true
		}
	}
	if !found {
		t.Errorf("x509 set not found in list: %v", sets)
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

	db.SetCADefaultRestrictionSet("ca-1", "ssh", strPtr("rs-default"))

	// Default
	rs, _ := db.GetEffectiveRestrictionSet("ca-1", "user-1", nil, "ssh")
	if rs == nil || rs.Name != "Default" {
		t.Error("should get default RS")
	}

	// User override
	db.GrantPermission(&models.PermissionEntry{
		ID: "p-1", CAID: "ca-1", EntityType: "user", EntityID: "user-1",
		Permission: models.PermSignCertificate, SSHRestrictionSetID: strPtr("rs-user"),
	})
	rs, _ = db.GetEffectiveRestrictionSet("ca-1", "user-1", nil, "ssh")
	if rs == nil || rs.Name != "User" {
		t.Error("should get user-specific RS")
	}

	// No RS for user without override
	rs, _ = db.GetEffectiveRestrictionSet("ca-1", "user-2", nil, "ssh")
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

	_, total, _ = db.ListAuditLog("ca-1", 10, 0)
	if total != 1 {
		t.Error("filter by ca_id failed")
	}

	_, total, _ = db.ListAuditLog("other", 10, 0)
	if total != 0 {
		t.Error("should be 0 for other ca")
	}
}

func TestAccessLog(t *testing.T) {
	db := testDB(t)

	db.CreateAccessLogEntry(&models.AccessLogEntry{
		ID: "al-1", UserSub: "user-1", Method: "GET", Path: "/api/keys", Status: 200, IP: "127.0.0.1",
	})

	entries, total, err := db.ListAccessLog(10, 0)
	if err != nil || total != 1 || len(entries) != 1 {
		t.Fatalf("access log: %d %d %v", total, len(entries), err)
	}
}

// TestAccessLogRequestID verifies the correlation request ID round-trips
// through the access log.
func TestAccessLogRequestID(t *testing.T) {
	db := testDB(t)

	db.CreateAccessLogEntry(&models.AccessLogEntry{
		ID: "al-req", UserSub: "user-1", Method: "GET", Path: "/api/keys",
		Status: 200, IP: "127.0.0.1", RequestID: "req-abc-123",
	})

	entries, _, err := db.ListAccessLog(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("access log: %d %v", len(entries), err)
	}
	if entries[0].RequestID != "req-abc-123" {
		t.Errorf("RequestID = %q, want req-abc-123", entries[0].RequestID)
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

func TestListAllRestrictionSets(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA1", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})
	db.CreateCA(&models.CA{ID: "ca-2", Label: "CA2", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-a", CAID: "ca-1", Name: "A"})
	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-b", CAID: "ca-2", Name: "B"})
	db.CreateRestrictionSet(&models.RestrictionSet{
		ID: "rs-c", CAID: "ca-2", Name: "C", Type: models.RestrictionSetX509,
		AllowedKeyUsages: []string{"digitalSignature"},
	})

	all, err := db.ListAllRestrictionSets()
	if err != nil {
		t.Fatal(err)
	}

	// Should include 4 builtins + 3 custom
	if len(all) != 7 {
		t.Fatalf("ListAllRestrictionSets: got %d, want 7", len(all))
	}

	// Verify both CAs are represented
	caIDs := map[string]int{}
	for _, rs := range all {
		if rs.CAID != "" {
			caIDs[rs.CAID]++
		}
	}
	if caIDs["ca-1"] != 1 {
		t.Errorf("ca-1 sets = %d, want 1", caIDs["ca-1"])
	}
	if caIDs["ca-2"] != 2 {
		t.Errorf("ca-2 sets = %d, want 2", caIDs["ca-2"])
	}

	// ListRestrictionSets for ca-1 should NOT include ca-2 specific sets
	ca1Sets, _ := db.ListRestrictionSets("ca-1")
	for _, s := range ca1Sets {
		if s.CAID == "ca-2" {
			t.Errorf("ca-1 list should not contain ca-2 set %q", s.ID)
		}
	}
}

func TestFindExistingCertificate(t *testing.T) {
	db := testDB(t)

	pubKey := "ssh-ed25519 AAAA..."
	now := time.Now().UTC().Truncate(time.Second)

	// Insert an audit entry without certificate
	db.CreateAuditLogEntry(&models.AuditLogEntry{
		ID: "a-nocert", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "k1", CertType: "user", Serial: "100",
		PublicKey: pubKey, ValidAfter: now, ValidBefore: now.Add(time.Hour),
		Principals: []string{"admin"},
	})

	// Should not find anything because certificate is NULL
	found, err := db.FindExistingCertificate("ca-1", pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Error("should not find cert when certificate is NULL")
	}

	// Search for wrong CA
	found, err = db.FindExistingCertificate("ca-999", pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Error("should not find cert for wrong CA")
	}

	// Search for wrong public key
	found, err = db.FindExistingCertificate("ca-1", "ssh-rsa OTHER...")
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Error("should not find cert for wrong public key")
	}
}

func TestLinkLatestHSMSignEntry(t *testing.T) {
	db := testDB(t)

	// Create an audit log entry to reference
	db.CreateAuditLogEntry(&models.AuditLogEntry{
		ID: "sign-1", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "k1", CertType: "user", Serial: "100",
		PublicKey: "ssh-ed25519 AAAA...",
	})

	// Store HSM entries with sign commands (0x6a = Sign_Pkcs1, 0x56 = Sign_Ecdsa)
	entries := []models.HSMAuditEntry{
		{Number: 1, Command: 0x01, Length: 10, SessionKey: 1, TargetKey: 2, SecondKey: 0xffff, Result: 0, Tick: 100, Hash: "aa"},
		{Number: 2, Command: 0x6a, Length: 6, SessionKey: 1, TargetKey: 3, SecondKey: 0xffff, Result: 0, Tick: 200, Hash: "bb"},
		{Number: 3, Command: 0x56, Length: 8, SessionKey: 1, TargetKey: 4, SecondKey: 0xffff, Result: 0, Tick: 300, Hash: "cc"},
	}
	if err := db.StoreHSMAuditEntries(entries); err != nil {
		t.Fatal(err)
	}

	// Link should update the latest sign command (number=3, command=0x56)
	if err := db.LinkLatestHSMSignEntry("sign-1"); err != nil {
		t.Fatal(err)
	}

	export, err := db.ExportCombinedAuditLog()
	if err != nil {
		t.Fatal(err)
	}

	linked := 0
	for _, e := range export.HSMEntries {
		if e.SignAuditID != nil && *e.SignAuditID == "sign-1" {
			linked++
			if e.Number != 3 {
				t.Errorf("linked entry number = %d, want 3", e.Number)
			}
		}
	}
	if linked != 1 {
		t.Errorf("linked entries = %d, want 1", linked)
	}

	// Calling again should be a no-op (entry 3 already linked, entry 2 is next unlinked sign)
	db.CreateAuditLogEntry(&models.AuditLogEntry{
		ID: "sign-2", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "k2", CertType: "user", Serial: "101",
		PublicKey: "ssh-ed25519 BBBB...",
	})
	if err := db.LinkLatestHSMSignEntry("sign-2"); err != nil {
		t.Fatal(err)
	}

	export, _ = db.ExportCombinedAuditLog()
	linked = 0
	for _, e := range export.HSMEntries {
		if e.SignAuditID != nil {
			linked++
		}
	}
	if linked != 2 {
		t.Errorf("total linked entries = %d, want 2", linked)
	}
}

func TestInsertOrIgnore(t *testing.T) {
	// Test SQL generation for sqlite
	db := &DB{driver: "sqlite"}
	got := db.insertOrIgnore("mytable", "a, b", "?, ?")
	want := "INSERT OR IGNORE INTO mytable (a, b) VALUES (?, ?)"
	if got != want {
		t.Errorf("sqlite insertOrIgnore = %q, want %q", got, want)
	}

	// Test SQL generation for postgres
	dbPg := &DB{driver: "postgres"}
	got = dbPg.insertOrIgnore("mytable", "a, b", "?, ?")
	want = "INSERT INTO mytable (a, b) VALUES ($1, $2) ON CONFLICT DO NOTHING"
	if got != want {
		t.Errorf("postgres insertOrIgnore = %q, want %q", got, want)
	}
}

func TestUpsert(t *testing.T) {
	// Test SQL generation for sqlite
	db := &DB{driver: "sqlite"}
	got := db.upsert("mytable", "a, b, c", "?, ?, ?", "a", "b = excluded.b, c = excluded.c")
	want := "INSERT INTO mytable (a, b, c) VALUES (?, ?, ?) ON CONFLICT(a) DO UPDATE SET b = excluded.b, c = excluded.c"
	if got != want {
		t.Errorf("sqlite upsert = %q, want %q", got, want)
	}

	// Test SQL generation for postgres
	dbPg := &DB{driver: "postgres"}
	got = dbPg.upsert("mytable", "a, b, c", "?, ?, ?", "a", "b = excluded.b, c = excluded.c")
	want = "INSERT INTO mytable (a, b, c) VALUES ($1, $2, $3) ON CONFLICT(a) DO UPDATE SET b = excluded.b, c = excluded.c"
	if got != want {
		t.Errorf("postgres upsert = %q, want %q", got, want)
	}
}

func TestEffectiveRestrictionSetX509(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	db.CreateRestrictionSet(&models.RestrictionSet{
		ID: "rs-x509-default", CAID: "ca-1", Name: "X509 Default", Type: models.RestrictionSetX509,
	})
	db.CreateRestrictionSet(&models.RestrictionSet{
		ID: "rs-x509-user", CAID: "ca-1", Name: "X509 User", Type: models.RestrictionSetX509,
	})

	db.SetCADefaultRestrictionSet("ca-1", "x509", strPtr("rs-x509-default"))

	// Default x509
	rs, err := db.GetEffectiveRestrictionSet("ca-1", "user-1", nil, "x509")
	if err != nil {
		t.Fatal(err)
	}
	if rs == nil || rs.Name != "X509 Default" {
		t.Error("should get x509 default RS")
	}

	// User override for x509
	db.GrantPermission(&models.PermissionEntry{
		ID: "p-x509", CAID: "ca-1", EntityType: "user", EntityID: "user-1",
		Permission: models.PermSignCertificate, X509RestrictionSetID: strPtr("rs-x509-user"),
	})
	rs, err = db.GetEffectiveRestrictionSet("ca-1", "user-1", nil, "x509")
	if err != nil {
		t.Fatal(err)
	}
	if rs == nil || rs.Name != "X509 User" {
		t.Error("should get x509 user-specific RS")
	}

	// User without override falls back to default
	rs, _ = db.GetEffectiveRestrictionSet("ca-1", "user-2", nil, "x509")
	if rs == nil || rs.Name != "X509 Default" {
		t.Error("should fall back to x509 default")
	}
}

func TestEffectiveRestrictionSetGroupOverride(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})
	db.CreateGroup(&models.Group{ID: "g-1", Name: "devs"})

	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-default", CAID: "ca-1", Name: "Default"})
	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-group", CAID: "ca-1", Name: "Group"})

	db.SetCADefaultRestrictionSet("ca-1", "ssh", strPtr("rs-default"))

	// Grant group permission with RS override
	db.GrantPermission(&models.PermissionEntry{
		ID: "p-grp", CAID: "ca-1", EntityType: "group", EntityID: "g-1",
		Permission: models.PermSignCertificate, SSHRestrictionSetID: strPtr("rs-group"),
	})

	// User in the group should get the group RS
	rs, err := db.GetEffectiveRestrictionSet("ca-1", "user-1", []string{"g-1"}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if rs == nil || rs.Name != "Group" {
		t.Errorf("should get group RS, got %v", rs)
	}

	// User NOT in any group should fall back to default
	rs, _ = db.GetEffectiveRestrictionSet("ca-1", "user-2", nil, "ssh")
	if rs == nil || rs.Name != "Default" {
		t.Error("should fall back to default")
	}
}

func TestEffectiveRestrictionSetNoDefault(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	// No default RS set, no user override
	rs, err := db.GetEffectiveRestrictionSet("ca-1", "user-1", nil, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if rs != nil {
		t.Errorf("should be nil when no default and no override, got %+v", rs)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests
// ---------------------------------------------------------------------------

func TestFindExistingCertificateWithCert(t *testing.T) {
	db := testDB(t)

	// Generate a real ed25519 key pair so we have a valid SSH public key
	pub, priv, err := ed25519GenerateKey(randReader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := sshNewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyStr := strings.TrimSpace(string(sshMarshalAuthorizedKey(sshPub)))

	// Create a signed SSH certificate so we have a valid certificate blob
	cert := &sshCertificate{
		Key:             sshPub,
		Serial:          12345,
		CertType:        sshUserCert,
		KeyId:           "test@example.com",
		ValidPrincipals: []string{"admin"},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: sshPermissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	caSigner, err := sshNewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SignCert(randReader, caSigner); err != nil {
		t.Fatal(err)
	}
	certStr := strings.TrimSpace(string(sshMarshalAuthorizedKey(cert)))

	now := time.Now().UTC().Truncate(time.Second)

	// Insert an audit entry WITH a certificate
	if err := db.CreateAuditLogEntry(&models.AuditLogEntry{
		ID: "a-withcert", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "test@example.com", CertType: "user", Serial: "12345",
		PublicKey:   pubKeyStr,
		Certificate: certStr,
		ValidAfter:  now, ValidBefore: now.Add(time.Hour),
		Principals: []string{"admin"},
		Extensions: map[string]string{"permit-pty": ""},
	}); err != nil {
		t.Fatal(err)
	}

	// Should find the certificate
	found, err := db.FindExistingCertificate("ca-1", pubKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatal("should find cert when certificate is present")
	}
	if found.ID != "a-withcert" {
		t.Errorf("found ID = %q, want a-withcert", found.ID)
	}
	if found.Serial != "12345" {
		t.Errorf("found serial = %q, want 12345", found.Serial)
	}
	if len(found.Principals) != 1 || found.Principals[0] != "admin" {
		t.Errorf("found principals = %v", found.Principals)
	}
	if found.Certificate == "" {
		t.Error("found certificate should not be empty")
	}
	if found.Extensions == nil || found.Extensions["permit-pty"] != "" {
		t.Errorf("found extensions = %v", found.Extensions)
	}
}

func TestCreateAuditLogEntryWithCertAndFields(t *testing.T) {
	db := testDB(t)

	pub, priv, err := ed25519GenerateKey(randReader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := sshNewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyStr := strings.TrimSpace(string(sshMarshalAuthorizedKey(sshPub)))

	// Create a signed certificate
	cert := &sshCertificate{
		Key:             sshPub,
		Serial:          99999,
		CertType:        sshUserCert,
		KeyId:           "user@example.com",
		ValidPrincipals: []string{"deploy", "admin"},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(24 * time.Hour).Unix()),
	}
	caSigner, err := sshNewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SignCert(randReader, caSigner); err != nil {
		t.Fatal(err)
	}
	certStr := strings.TrimSpace(string(sshMarshalAuthorizedKey(cert)))

	now := time.Now().UTC().Truncate(time.Second)
	rsID := "rs-test"

	// Create audit log entry with all fields populated
	e := &models.AuditLogEntry{
		ID: "a-full", UserSub: "user-1", UserEmail: "user@example.com",
		UserName: "Test User", CAID: "ca-1", CALabel: "Test CA",
		KeyID: "user@example.com", CertType: "user", Serial: "99999",
		PublicKey:        pubKeyStr,
		Certificate:      certStr,
		ValidAfter:       now,
		ValidBefore:      now.Add(24 * time.Hour),
		Principals:       []string{"deploy", "admin"},
		Extensions:       map[string]string{"permit-pty": "", "permit-agent-forwarding": ""},
		CriticalOptions:  map[string]string{"source-address": "10.0.0.0/8"},
		RestrictionSetID: &rsID,
	}
	if err := db.CreateAuditLogEntry(e); err != nil {
		t.Fatal(err)
	}

	// Verify via ListAuditLog
	entries, total, err := db.ListAuditLog("ca-1", 10, 0)
	if err != nil || total != 1 {
		t.Fatalf("list: total=%d err=%v", total, err)
	}
	got := entries[0]
	if got.UserEmail != "user@example.com" {
		t.Errorf("email = %q", got.UserEmail)
	}
	if got.UserName != "Test User" {
		t.Errorf("name = %q", got.UserName)
	}
	if len(got.Principals) != 2 {
		t.Errorf("principals = %v", got.Principals)
	}
	if got.Extensions["permit-pty"] != "" {
		t.Errorf("extensions = %v", got.Extensions)
	}
	if got.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("critical_options = %v", got.CriticalOptions)
	}
	if got.Certificate == "" {
		t.Error("certificate should be present")
	}
	if got.RestrictionSetID == nil || *got.RestrictionSetID != "rs-test" {
		t.Errorf("restriction_set_id = %v", got.RestrictionSetID)
	}
}

func TestExportCombinedAuditLogWithSignOps(t *testing.T) {
	db := testDB(t)

	// Create audit log entries (sign operations)
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		db.CreateAuditLogEntry(&models.AuditLogEntry{
			ID: fmt.Sprintf("sign-%d", i), UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
			KeyID: fmt.Sprintf("key-%d", i), CertType: "user", Serial: fmt.Sprintf("%d", 100+i),
			PublicKey: "ssh-ed25519 AAAA...", ValidAfter: now, ValidBefore: now.Add(time.Hour),
		})
	}

	// Create HSM entries with sign commands linked to sign operations
	hsmEntries := []models.HSMAuditEntry{
		{Number: 1, Command: 0x6a, Length: 6, SessionKey: 1, TargetKey: 2, SecondKey: 0xffff, Result: 0, Tick: 100, Hash: "aa"},
		{Number: 2, Command: 0x56, Length: 8, SessionKey: 1, TargetKey: 3, SecondKey: 0xffff, Result: 0, Tick: 200, Hash: "bb"},
		{Number: 3, Command: 0x01, Length: 4, SessionKey: 1, TargetKey: 1, SecondKey: 0xffff, Result: 0, Tick: 300, Hash: "cc"},
	}
	if err := db.StoreHSMAuditEntries(hsmEntries); err != nil {
		t.Fatal(err)
	}

	// Link sign entries
	db.LinkLatestHSMSignEntry("sign-0")

	export, err := db.ExportCombinedAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(export.HSMEntries) != 3 {
		t.Errorf("HSM entries = %d, want 3", len(export.HSMEntries))
	}
	if len(export.SignOps) != 3 {
		t.Errorf("sign ops = %d, want 3", len(export.SignOps))
	}

	// Verify at least one HSM entry is linked
	linked := 0
	for _, e := range export.HSMEntries {
		if e.SignAuditID != nil {
			linked++
		}
	}
	if linked < 1 {
		t.Error("expected at least one linked HSM entry")
	}
}

func TestListCAsMultiple(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 5; i++ {
		db.CreateCA(&models.CA{
			ID: fmt.Sprintf("ca-%d", i), Label: fmt.Sprintf("CA %d", i),
			PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k",
		})
	}

	cas, err := db.ListCAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 5 {
		t.Errorf("ListCAs = %d, want 5", len(cas))
	}
}

func TestGetChildrenMultiple(t *testing.T) {
	db := testDB(t)

	db.CreateCA(&models.CA{ID: "root", Label: "Root", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})
	rootID := "root"
	for i := 0; i < 3; i++ {
		db.CreateCA(&models.CA{
			ID: fmt.Sprintf("child-%d", i), ParentID: &rootID,
			Label: fmt.Sprintf("Child %d", i), PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k",
		})
	}

	children, err := db.GetChildren("root")
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 3 {
		t.Errorf("GetChildren = %d, want 3", len(children))
	}

	// No children for leaf
	children, err = db.GetChildren("child-0")
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 0 {
		t.Errorf("leaf children = %d, want 0", len(children))
	}
}

func TestListGroupsMultiple(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 4; i++ {
		db.CreateGroup(&models.Group{ID: fmt.Sprintf("g-%d", i), Name: fmt.Sprintf("Group %d", i)})
	}

	groups, err := db.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Errorf("ListGroups = %d, want 4", len(groups))
	}
}

func TestGetGroupMembersMultiple(t *testing.T) {
	db := testDB(t)

	db.CreateGroup(&models.Group{ID: "g-1", Name: "team"})
	db.CreateGroup(&models.Group{ID: "g-2", Name: "admins"})

	for i := 0; i < 5; i++ {
		db.AddGroupMember("g-1", fmt.Sprintf("user-%d", i))
	}
	db.AddGroupMember("g-2", "user-0")
	db.AddGroupMember("g-2", "user-1")

	members, err := db.GetGroupMembers("g-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 5 {
		t.Errorf("g-1 members = %d, want 5", len(members))
	}

	members, err = db.GetGroupMembers("g-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Errorf("g-2 members = %d, want 2", len(members))
	}
}

func TestGetUserGroupsMultiple(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 3; i++ {
		db.CreateGroup(&models.Group{ID: fmt.Sprintf("g-%d", i), Name: fmt.Sprintf("Group %d", i)})
		db.AddGroupMember(fmt.Sprintf("g-%d", i), "user-multi")
	}

	groups, err := db.GetUserGroups("user-multi")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 {
		t.Errorf("user groups = %d, want 3", len(groups))
	}
}

func TestGetPermissionsMultiple(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	perms := []models.PermissionEntry{
		{ID: "p-1", CAID: "ca-1", EntityType: "user", EntityID: "user-1", Permission: models.PermSignCertificate},
		{ID: "p-2", CAID: "ca-1", EntityType: "user", EntityID: "user-1", Permission: models.PermManagePermissions},
		{ID: "p-3", CAID: "ca-1", EntityType: "user", EntityID: "user-2", Permission: models.PermSignCertificate},
	}
	for _, p := range perms {
		if err := db.GrantPermission(&p); err != nil {
			t.Fatal(err)
		}
	}

	got, err := db.GetPermissions("ca-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("permissions = %d, want 3", len(got))
	}
}

func TestHasPermissionGroupPath(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	db.CreateGroup(&models.Group{ID: "g-1", Name: "devs"})
	db.CreateGroup(&models.Group{ID: "g-2", Name: "admins"})

	// Only g-2 has permission
	db.GrantPermission(&models.PermissionEntry{
		ID: "p-grp", CAID: "ca-1", EntityType: "group",
		EntityID: "g-2", Permission: models.PermManagePermissions,
	})

	// User in g-1 only -- should not have permission
	has, err := db.HasPermission("ca-1", "user-x", models.PermManagePermissions, []string{"g-1"})
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("user in g-1 should not have MANAGE_PERMISSIONS")
	}

	// User in g-2 -- should have permission
	has, err = db.HasPermission("ca-1", "user-x", models.PermManagePermissions, []string{"g-2"})
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("user in g-2 should have MANAGE_PERMISSIONS")
	}

	// User in both groups -- should have permission (via g-2)
	has, err = db.HasPermission("ca-1", "user-x", models.PermManagePermissions, []string{"g-1", "g-2"})
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("user in g-1+g-2 should have MANAGE_PERMISSIONS via g-2")
	}
}

func TestCreateAndUpdateRestrictionSetX509(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	maxVal := int64(7200)
	pathLen := 1
	rs := &models.RestrictionSet{
		ID: "rs-x509-new", CAID: "ca-1", Name: "X509 New",
		Type:                 models.RestrictionSetX509,
		MaxValiditySecs:      &maxVal,
		AllowedKeyUsages:     []string{"digitalSignature"},
		AllowedExtKeyUsages:  []string{"serverAuth"},
		AllowedSANTypes:      []string{"dns"},
		AllowedSANPatterns:   []string{"*.example.com"},
		AllowedSubjectFields: []string{"CN"},
		MaxPathLength:        &pathLen,
		DenyCA:               false,
	}
	if err := db.CreateRestrictionSet(rs); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetRestrictionSet("rs-x509-new")
	if err != nil || got == nil {
		t.Fatal("GetRestrictionSet failed")
	}
	if got.Type != models.RestrictionSetX509 {
		t.Errorf("type = %q", got.Type)
	}
	if len(got.AllowedKeyUsages) != 1 {
		t.Errorf("key_usages = %v", got.AllowedKeyUsages)
	}
	if got.MaxPathLength == nil || *got.MaxPathLength != 1 {
		t.Errorf("max_path_length = %v", got.MaxPathLength)
	}

	// Update x509 restriction set
	got.AllowedKeyUsages = []string{"digitalSignature", "keyEncipherment"}
	got.AllowedExtKeyUsages = []string{"serverAuth", "clientAuth"}
	got.DenyCA = true
	newPathLen := 0
	got.MaxPathLength = &newPathLen
	if err := db.UpdateRestrictionSet(got); err != nil {
		t.Fatal(err)
	}

	got, _ = db.GetRestrictionSet("rs-x509-new")
	if len(got.AllowedKeyUsages) != 2 {
		t.Errorf("after update key_usages = %v", got.AllowedKeyUsages)
	}
	if !got.DenyCA {
		t.Error("after update deny_ca should be true")
	}
	if got.MaxPathLength == nil || *got.MaxPathLength != 0 {
		t.Errorf("after update max_path_length = %v", got.MaxPathLength)
	}
}

func TestCreateAuditLogEntryDuplicateCertHash(t *testing.T) {
	db := testDB(t)

	pub, priv, err := ed25519GenerateKey(randReader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := sshNewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyStr := strings.TrimSpace(string(sshMarshalAuthorizedKey(sshPub)))

	cert := &sshCertificate{
		Key: sshPub, Serial: 1, CertType: sshUserCert,
		KeyId: "k", ValidAfter: uint64(time.Now().Unix()),
		ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	caSigner, err := sshNewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert.SignCert(randReader, caSigner)
	certStr := strings.TrimSpace(string(sshMarshalAuthorizedKey(cert)))

	now := time.Now().UTC().Truncate(time.Second)

	// First insert should succeed
	err = db.CreateAuditLogEntry(&models.AuditLogEntry{
		ID: "a-dup1", UserSub: "u", CAID: "ca-1", CALabel: "CA",
		KeyID: "k", CertType: "user", Serial: "1",
		PublicKey: pubKeyStr, Certificate: certStr,
		ValidAfter: now, ValidBefore: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Second insert with same cert should fail (UNIQUE on ca_id, cert_hash)
	err = db.CreateAuditLogEntry(&models.AuditLogEntry{
		ID: "a-dup2", UserSub: "u", CAID: "ca-1", CALabel: "CA",
		KeyID: "k", CertType: "user", Serial: "2",
		PublicKey: pubKeyStr, Certificate: certStr,
		ValidAfter: now, ValidBefore: now.Add(time.Hour),
	})
	if err == nil {
		t.Error("expected error for duplicate cert_hash on same CA")
	}
}

func TestCertBlobToAuthorizedKeyEdgeCases(t *testing.T) {
	// Empty blob
	result := certBlobToAuthorizedKey(nil)
	if result != "" {
		t.Errorf("nil blob: got %q, want empty", result)
	}

	result = certBlobToAuthorizedKey([]byte{})
	if result != "" {
		t.Errorf("empty blob: got %q, want empty", result)
	}

	// Unparseable blob should return empty string (not the raw bytes)
	result = certBlobToAuthorizedKey([]byte("not-a-valid-ssh-key"))
	if result != "" {
		t.Errorf("unparseable blob: got %q, want empty", result)
	}
}

func TestPubKeyToBlobFallback(t *testing.T) {
	// Empty key
	blob := pubKeyToBlob("")
	if blob != nil {
		t.Errorf("empty key: got %v, want nil", blob)
	}

	// Unparseable key should return the raw string as-is
	blob = pubKeyToBlob("not-a-valid-ssh-key")
	if string(blob) != "not-a-valid-ssh-key" {
		t.Errorf("unparseable key fallback: got %q, want %q", string(blob), "not-a-valid-ssh-key")
	}
}

func TestBlobToAuthorizedKeyFallback(t *testing.T) {
	// Empty blob
	result := blobToAuthorizedKey(nil)
	if result != "" {
		t.Errorf("nil blob: got %q, want empty", result)
	}

	result = blobToAuthorizedKey([]byte{})
	if result != "" {
		t.Errorf("empty blob: got %q, want empty", result)
	}

	// Unparseable blob should return raw string fallback
	result = blobToAuthorizedKey([]byte("raw-fallback-data"))
	if result != "raw-fallback-data" {
		t.Errorf("unparseable blob: got %q, want %q", result, "raw-fallback-data")
	}
}

func TestCreateAuditLogEntryEdgeCases(t *testing.T) {
	db := testDB(t)

	// Entry with extensions and critical options
	e := &models.AuditLogEntry{
		ID: "a-ext", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "k1", CertType: "user", Serial: "200",
		PublicKey:       "ssh-ed25519 AAAA...",
		Principals:      []string{"admin", "deploy"},
		Extensions:      map[string]string{"permit-pty": "", "permit-agent-forwarding": ""},
		CriticalOptions: map[string]string{"source-address": "10.0.0.0/8"},
	}
	if err := db.CreateAuditLogEntry(e); err != nil {
		t.Fatal(err)
	}

	entries, total, err := db.ListAuditLog("ca-1", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d/%d", len(entries), total)
	}

	got := entries[0]
	if len(got.Principals) != 2 {
		t.Errorf("principals = %v, want 2", got.Principals)
	}
	if len(got.Extensions) != 2 {
		t.Errorf("extensions = %v, want 2 entries", got.Extensions)
	}
	if got.Extensions["permit-pty"] != "" {
		t.Errorf("permit-pty = %q, want empty", got.Extensions["permit-pty"])
	}
	if len(got.CriticalOptions) != 1 {
		t.Errorf("critical_options = %v, want 1 entry", got.CriticalOptions)
	}
	if got.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("source-address = %q", got.CriticalOptions["source-address"])
	}

	// Entry with empty principals, extensions, and critical options
	e2 := &models.AuditLogEntry{
		ID: "a-empty", UserSub: "user-2", CAID: "ca-1", CALabel: "CA",
		KeyID: "k2", CertType: "host", Serial: "201",
		PublicKey: "ssh-ed25519 BBBB...",
	}
	if err := db.CreateAuditLogEntry(e2); err != nil {
		t.Fatal(err)
	}

	_, total, _ = db.ListAuditLog("ca-1", 10, 0)
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}

	// Entry with user email and name fields
	e3 := &models.AuditLogEntry{
		ID: "a-meta", UserSub: "user-3", UserEmail: "user@example.com",
		UserName: "Test User", CAID: "ca-2", CALabel: "CA2",
		KeyID: "k3", CertType: "user", Serial: "202",
		PublicKey: "ssh-ed25519 CCCC...",
	}
	if err := db.CreateAuditLogEntry(e3); err != nil {
		t.Fatal(err)
	}

	entries, _, _ = db.ListAuditLog("ca-2", 10, 0)
	if len(entries) != 1 {
		t.Fatalf("ca-2 entries = %d, want 1", len(entries))
	}
	if entries[0].UserEmail != "user@example.com" {
		t.Errorf("user_email = %q", entries[0].UserEmail)
	}
	if entries[0].UserName != "Test User" {
		t.Errorf("user_name = %q", entries[0].UserName)
	}
}

func TestCreateAuditLogEntryWithRestrictionSetID(t *testing.T) {
	db := testDB(t)

	rsID := "rs-ref"
	e := &models.AuditLogEntry{
		ID: "a-rs", UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
		KeyID: "k1", CertType: "user", Serial: "300",
		PublicKey:        "ssh-ed25519 AAAA...",
		RestrictionSetID: &rsID,
	}
	if err := db.CreateAuditLogEntry(e); err != nil {
		t.Fatal(err)
	}

	entries, _, _ := db.ListAuditLog("ca-1", 10, 0)
	if len(entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	if entries[0].RestrictionSetID == nil || *entries[0].RestrictionSetID != "rs-ref" {
		t.Errorf("restriction_set_id = %v", entries[0].RestrictionSetID)
	}
}

func TestInsertOrIgnoreIdempotent(t *testing.T) {
	db := testDB(t)

	// Use the actual insertOrIgnore through group members (which uses it)
	db.CreateGroup(&models.Group{ID: "g-idem", Name: "idempotent"})
	if err := db.AddGroupMember("g-idem", "user-1"); err != nil {
		t.Fatal(err)
	}
	// Adding the same member again should not error
	if err := db.AddGroupMember("g-idem", "user-1"); err != nil {
		t.Fatalf("duplicate insert should be ignored: %v", err)
	}

	members, _ := db.GetGroupMembers("g-idem")
	if len(members) != 1 {
		t.Errorf("members = %d, want 1 (duplicate should be ignored)", len(members))
	}
}

func TestStoreHSMAuditEntriesBatch(t *testing.T) {
	db := testDB(t)

	// Store multiple entries in a single batch
	entries := []models.HSMAuditEntry{
		{Number: 10, Command: 0x6a, Length: 6, SessionKey: 1, TargetKey: 2, SecondKey: 0xffff, Result: 0, Tick: 500, Hash: "xxyy"},
		{Number: 11, Command: 0x56, Length: 8, SessionKey: 1, TargetKey: 3, SecondKey: 0xffff, Result: 0, Tick: 600, Hash: "zzww"},
	}
	if err := db.StoreHSMAuditEntries(entries); err != nil {
		t.Fatal(err)
	}

	export, _ := db.ExportCombinedAuditLog()
	if len(export.HSMEntries) != 2 {
		t.Errorf("hsm entries = %d, want 2", len(export.HSMEntries))
	}

	// Verify ordering by number ASC
	if export.HSMEntries[0].Number != 10 || export.HSMEntries[1].Number != 11 {
		t.Errorf("ordering: got numbers %d, %d", export.HSMEntries[0].Number, export.HSMEntries[1].Number)
	}
}

func TestAuditLogPagination(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 5; i++ {
		db.CreateAuditLogEntry(&models.AuditLogEntry{
			ID: fmt.Sprintf("a-%d", i), UserSub: "user-1", CAID: "ca-1", CALabel: "CA",
			KeyID: fmt.Sprintf("k%d", i), CertType: "user", Serial: fmt.Sprintf("%d", i),
			PublicKey: fmt.Sprintf("key-%d", i),
		})
	}

	// Page 1: limit 2, offset 0
	entries, total, err := db.ListAuditLog("", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(entries) != 2 {
		t.Errorf("page 1 entries = %d, want 2", len(entries))
	}

	// Page 2: limit 2, offset 2
	entries, total, _ = db.ListAuditLog("", 2, 2)
	if total != 5 || len(entries) != 2 {
		t.Errorf("page 2: total=%d entries=%d", total, len(entries))
	}

	// Page 3: limit 2, offset 4
	entries, total, _ = db.ListAuditLog("", 2, 4)
	if total != 5 || len(entries) != 1 {
		t.Errorf("page 3: total=%d entries=%d", total, len(entries))
	}
}

func TestAccessLogPagination(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 3; i++ {
		db.CreateAccessLogEntry(&models.AccessLogEntry{
			ID: fmt.Sprintf("al-%d", i), UserSub: "user-1",
			Method: "GET", Path: fmt.Sprintf("/api/%d", i), Status: 200, IP: "127.0.0.1",
		})
	}

	entries, total, err := db.ListAccessLog(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(entries) != 2 {
		t.Errorf("page 1: total=%d entries=%d", total, len(entries))
	}

	entries, total, _ = db.ListAccessLog(2, 2)
	if total != 3 || len(entries) != 1 {
		t.Errorf("page 2: total=%d entries=%d", total, len(entries))
	}
}

func TestDefaultRestrictionSetX509(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	rsID := "rs-x509"
	db.SetCADefaultRestrictionSet("ca-1", "x509", &rsID)

	ca, _ := db.GetCA("ca-1")
	if ca.DefaultX509RestrictionSetID == nil || *ca.DefaultX509RestrictionSetID != "rs-x509" {
		t.Error("default X509 RS not set")
	}

	db.SetCADefaultRestrictionSet("ca-1", "x509", nil)
	ca, _ = db.GetCA("ca-1")
	if ca.DefaultX509RestrictionSetID != nil {
		t.Error("default X509 RS should be nil")
	}
}

func TestRestrictionSetDenyAll(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	rs := &models.RestrictionSet{
		ID: "rs-deny", CAID: "ca-1", Name: "Deny All", DenyAll: true,
	}
	if err := db.CreateRestrictionSet(rs); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetRestrictionSet("rs-deny")
	if err != nil {
		t.Fatal(err)
	}
	if !got.DenyAll {
		t.Error("DenyAll should be true")
	}
}

func TestBuiltinRestrictionSets(t *testing.T) {
	db := testDB(t)

	// The migration should have created 4 built-in restriction sets
	for _, id := range []string{BuiltinPermitAllSSH, BuiltinDenyAllSSH, BuiltinPermitAllX509, BuiltinDenyAllX509} {
		rs, err := db.GetRestrictionSet(id)
		if err != nil {
			t.Fatalf("GetRestrictionSet(%q): %v", id, err)
		}
		if rs == nil {
			t.Errorf("builtin %q not found", id)
		}
	}

	// Verify deny_all flags
	deny, _ := db.GetRestrictionSet(BuiltinDenyAllSSH)
	if !deny.DenyAll {
		t.Error("builtin deny-all-ssh should have DenyAll=true")
	}
	permit, _ := db.GetRestrictionSet(BuiltinPermitAllSSH)
	if permit.DenyAll {
		t.Error("builtin permit-all-ssh should have DenyAll=false")
	}
}

func TestDeleteRestrictionSetClearsCADefault(t *testing.T) {
	db := testDB(t)
	db.CreateCA(&models.CA{ID: "ca-1", Label: "CA", PKCS11URI: "p", KeyType: "ed25519", PublicKey: "k"})

	db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-del", CAID: "ca-1", Name: "To Delete"})
	db.SetCADefaultRestrictionSet("ca-1", "ssh", strPtr("rs-del"))

	ca, _ := db.GetCA("ca-1")
	if ca.DefaultSSHRestrictionSetID == nil || *ca.DefaultSSHRestrictionSetID != "rs-del" {
		t.Fatal("precondition: default should be set")
	}

	db.DeleteRestrictionSet("rs-del")

	ca, _ = db.GetCA("ca-1")
	if ca.DefaultSSHRestrictionSetID != nil {
		t.Errorf("default should be cleared after deleting RS, got %v", *ca.DefaultSSHRestrictionSetID)
	}
}
