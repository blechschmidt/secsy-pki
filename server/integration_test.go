package integration_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	serverURL      = "https://localhost:8443"
	keycloakURL    = "http://localhost:8080"
	rootUser       = "root"
	rootPass       = "integration-test-password"
	keycloakRealm  = "secsy-pki"
	keycloakClient = "secsy-pki"
	testUser       = "testuser"
	testUserPass   = "testpassword"
)

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TEST") != "1" {
		fmt.Println("Skipping integration tests (set INTEGRATION_TEST=1 to run)")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func rootClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func rootRequest(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, serverURL+path, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(rootUser, rootPass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := rootClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func oidcRequest(t *testing.T, token, method, path string, body interface{}) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, serverURL+path, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := rootClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func parseJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("Failed to parse JSON response: %v, body: %s", err, string(data))
	}
}

func getKeycloakToken(t *testing.T) string {
	t.Helper()
	data := fmt.Sprintf(
		"grant_type=password&client_id=%s&username=%s&password=%s",
		keycloakClient, testUser, testUserPass,
	)
	resp, err := http.Post(
		keycloakURL+"/realms/"+keycloakRealm+"/protocol/openid-connect/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data),
	)
	if err != nil {
		t.Fatalf("Failed to get Keycloak token: %v", err)
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse Keycloak token: %v, body: %s", err, string(body))
	}
	if result.AccessToken == "" {
		t.Fatalf("Empty access token from Keycloak, body: %s", string(body))
	}
	return result.AccessToken
}

// --- Tests ---

func TestHealthEndpoint(t *testing.T) {
	client := rootClient()
	resp, err := client.Get(serverURL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestRootAuth(t *testing.T) {
	resp := rootRequest(t, "GET", "/api/me", nil)
	var user map[string]interface{}
	parseJSON(t, resp, &user)
	if user["sub"] != "root" {
		t.Errorf("Expected sub=root, got %v", user["sub"])
	}
	if user["is_root"] != true {
		t.Errorf("Expected is_root=true, got %v", user["is_root"])
	}
}

func TestInvalidAuth(t *testing.T) {
	req, _ := http.NewRequest("GET", serverURL+"/api/me", nil)
	req.SetBasicAuth("root", "wrongpassword")
	resp, err := rootClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("Expected 401, got %d", resp.StatusCode)
	}
}

func TestCALifecycle(t *testing.T) {
	// Create CA
	resp := rootRequest(t, "POST", "/api/keys", map[string]interface{}{
		"label":      "test-ca",
		"pkcs11_uri": "pkcs11:token=secsy-pki-root;object=secsy-pki-root-ca-priv;type=private",
		"key_type":   "ecdsa-sha2-nistp384",
		"public_key": "test-public-key",
	})
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201, got %d: %s", resp.StatusCode, body)
	}
	var ca map[string]interface{}
	parseJSON(t, resp, &ca)
	caID := ca["id"].(string)

	// List CAs
	resp = rootRequest(t, "GET", "/api/keys", nil)
	var cas []map[string]interface{}
	parseJSON(t, resp, &cas)
	if len(cas) == 0 {
		t.Fatal("Expected at least 1 CA")
	}

	// Get CA
	resp = rootRequest(t, "GET", "/api/keys/"+caID, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Delete CA
	resp = rootRequest(t, "DELETE", "/api/keys/"+caID, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestGroupLifecycle(t *testing.T) {
	// Create group
	resp := rootRequest(t, "POST", "/api/groups", map[string]string{"name": "test-group"})
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201, got %d: %s", resp.StatusCode, body)
	}
	var group map[string]interface{}
	parseJSON(t, resp, &group)
	groupID := group["id"].(string)

	// Add member
	resp = rootRequest(t, "POST", "/api/groups/"+groupID+"/members", map[string]string{"user_sub": "user-123"})
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Get members
	resp = rootRequest(t, "GET", "/api/groups/"+groupID+"/members", nil)
	var members []string
	parseJSON(t, resp, &members)
	if len(members) != 1 || members[0] != "user-123" {
		t.Fatalf("Expected [user-123], got %v", members)
	}

	// Remove member
	resp = rootRequest(t, "DELETE", "/api/groups/"+groupID+"/members/user-123", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Delete group
	resp = rootRequest(t, "DELETE", "/api/groups/"+groupID, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestPermissionMatrix(t *testing.T) {
	// Create CA
	resp := rootRequest(t, "POST", "/api/keys", map[string]interface{}{
		"label":      "perm-test-ca",
		"pkcs11_uri": "pkcs11:token=test;object=test;type=private",
		"key_type":   "ed25519",
		"public_key": "test-key",
	})
	var ca map[string]interface{}
	parseJSON(t, resp, &ca)
	caID := ca["id"].(string)

	// Create group
	resp = rootRequest(t, "POST", "/api/groups", map[string]string{"name": "perm-test-group"})
	var group map[string]interface{}
	parseJSON(t, resp, &group)
	groupID := group["id"].(string)

	// Grant user permission
	resp = rootRequest(t, "POST", "/api/keys/"+caID+"/permissions", map[string]interface{}{
		"entity_type": "user",
		"entity_id":   "user-456",
		"permission":  "SIGN_CERTIFICATE",
	})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Grant group permission
	resp = rootRequest(t, "POST", "/api/keys/"+caID+"/permissions", map[string]interface{}{
		"entity_type": "group",
		"entity_id":   groupID,
		"permission":  "MANAGE_PERMISSIONS",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Get permissions
	resp = rootRequest(t, "GET", "/api/keys/"+caID+"/permissions", nil)
	var perms []map[string]interface{}
	parseJSON(t, resp, &perms)
	if len(perms) != 2 {
		t.Fatalf("Expected 2 permissions, got %d", len(perms))
	}

	// Revoke permission
	resp = rootRequest(t, "DELETE", "/api/keys/"+caID+"/permissions", map[string]interface{}{
		"entity_type": "user",
		"entity_id":   "user-456",
		"permission":  "SIGN_CERTIFICATE",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Cleanup
	rootRequest(t, "DELETE", "/api/keys/"+caID, nil)
	rootRequest(t, "DELETE", "/api/groups/"+groupID, nil)
}

// generateTestKey creates an ed25519 key pair using ssh-keygen and returns the public key.
func generateTestKey(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	keyPath := tmpDir + "/id_test"
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q")
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh-keygen failed: %v", err)
	}
	pubData, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pubData))
}

func TestSignCertificateFlow(t *testing.T) {
	// Create CA
	resp := rootRequest(t, "POST", "/api/keys", map[string]interface{}{
		"label":      "sign-test-ca",
		"pkcs11_uri": "pkcs11:token=secsy-pki-root;object=secsy-pki-root-ca-priv;type=private",
		"key_type":   "ecdsa-sha2-nistp384",
		"public_key": "n/a",
	})
	var ca map[string]interface{}
	parseJSON(t, resp, &ca)
	caID := ca["id"].(string)
	defer rootRequest(t, "DELETE", "/api/keys/"+caID, nil)

	// Generate a key pair locally
	pubKey := generateTestKey(t)

	// Sign the public key
	resp = rootRequest(t, "POST", "/api/keys/"+caID+"/sign", map[string]interface{}{
		"public_key":   pubKey,
		"cert_type":    "user",
		"principals":   []string{"testuser"},
		"valid_before": "+1d",
		"key_id":       "test-cert",
	})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, body)
	}
	var signResult map[string]string
	parseJSON(t, resp, &signResult)
	if signResult["certificate"] == "" {
		t.Fatal("Expected non-empty certificate")
	}
	if !strings.Contains(signResult["certificate"], "cert") {
		t.Error("Certificate doesn't look like an SSH certificate")
	}
}

func TestOIDCAuth(t *testing.T) {
	token := getKeycloakToken(t)

	resp := oidcRequest(t, token, "GET", "/api/me", nil)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, body)
	}
	var user map[string]interface{}
	parseJSON(t, resp, &user)
	if user["is_root"] == true {
		t.Error("OIDC user should not be root")
	}
}

func TestOIDCPermissionDenied(t *testing.T) {
	token := getKeycloakToken(t)

	// Create CA as root
	resp := rootRequest(t, "POST", "/api/keys", map[string]interface{}{
		"label":      "oidc-perm-test",
		"pkcs11_uri": "pkcs11:token=test;object=test;type=private",
		"key_type":   "ed25519",
		"public_key": "test-key",
	})
	var ca map[string]interface{}
	parseJSON(t, resp, &ca)
	caID := ca["id"].(string)
	defer rootRequest(t, "DELETE", "/api/keys/"+caID, nil)

	// OIDC user should be denied signing without permission
	resp = oidcRequest(t, token, "POST", "/api/keys/"+caID+"/sign", map[string]interface{}{
		"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test",
	})
	if resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestOIDCWithPermissionGrant(t *testing.T) {
	token := getKeycloakToken(t)

	// Get OIDC user info
	resp := oidcRequest(t, token, "GET", "/api/me", nil)
	var user map[string]interface{}
	parseJSON(t, resp, &user)
	userSub := user["sub"].(string)

	// Create CA as root
	resp = rootRequest(t, "POST", "/api/keys", map[string]interface{}{
		"label":      "oidc-grant-test",
		"pkcs11_uri": "pkcs11:token=secsy-pki-root;object=secsy-pki-root-ca-priv;type=private",
		"key_type":   "ecdsa-sha2-nistp384",
		"public_key": "n/a",
	})
	var ca map[string]interface{}
	parseJSON(t, resp, &ca)
	caID := ca["id"].(string)
	defer rootRequest(t, "DELETE", "/api/keys/"+caID, nil)

	// Grant SIGN_CERTIFICATE to OIDC user
	resp = rootRequest(t, "POST", "/api/keys/"+caID+"/permissions", map[string]interface{}{
		"entity_type": "user",
		"entity_id":   userSub,
		"permission":  "SIGN_CERTIFICATE",
	})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("grant perm failed: %d: %s", resp.StatusCode, body)
	}

	// Generate key locally
	pubKey := generateTestKey(t)

	// Now OIDC user should be able to sign
	resp = oidcRequest(t, token, "POST", "/api/keys/"+caID+"/sign", map[string]interface{}{
		"public_key":   pubKey,
		"cert_type":    "user",
		"principals":   []string{"testuser"},
		"valid_before": "+1d",
	})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestSSHCertVerifyWithOpenSSH(t *testing.T) {
	// This test verifies the signed certificate works with OpenSSH
	// by running ssh-keygen -L against it

	// Create CA
	resp := rootRequest(t, "POST", "/api/keys", map[string]interface{}{
		"label":      "openssh-test",
		"pkcs11_uri": "pkcs11:token=secsy-pki-root;object=secsy-pki-root-ca-priv;type=private",
		"key_type":   "ecdsa-sha2-nistp384",
		"public_key": "n/a",
	})
	var ca map[string]interface{}
	parseJSON(t, resp, &ca)
	caID := ca["id"].(string)
	defer rootRequest(t, "DELETE", "/api/keys/"+caID, nil)

	// Generate key
	pubKey := generateTestKey(t)

	// Sign
	resp = rootRequest(t, "POST", "/api/keys/"+caID+"/sign", map[string]interface{}{
		"public_key":   pubKey,
		"cert_type":    "user",
		"principals":   []string{"testuser"},
		"valid_before": "+1d",
		"key_id":       "openssh-verify-test",
	})
	var signResult map[string]string
	parseJSON(t, resp, &signResult)

	// Write cert to temp file and verify with ssh-keygen
	tmpFile, err := os.CreateTemp("", "ssh-cert-*.pub")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(signResult["certificate"])
	tmpFile.Close()

	// Verify with ssh-keygen -L
	cmd := exec.Command("ssh-keygen", "-L", "-f", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L failed: %v\nOutput: %s", err, output)
	}

	outStr := string(output)
	if !strings.Contains(outStr, "openssh-verify-test") {
		t.Errorf("Certificate doesn't contain expected key_id, output: %s", outStr)
	}
	if !strings.Contains(outStr, "testuser") {
		t.Errorf("Certificate doesn't contain expected principal, output: %s", outStr)
	}
}

// Unused but documents the wait function pattern
var _ = time.Sleep
var _ = fmt.Sprintf
