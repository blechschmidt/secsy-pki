package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sshPkg "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type Config struct {
	APIURL             string `yaml:"api_url"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

func main() {
	// Parse our flags and collect remaining args for ssh
	var caName, reason string
	var noCache bool
	var sshArgs []string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--ca" && i+1 < len(args):
			caName = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--ca="):
			caName = strings.TrimPrefix(args[i], "--ca=")
		case args[i] == "--reason" && i+1 < len(args):
			reason = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--reason="):
			reason = strings.TrimPrefix(args[i], "--reason=")
		case args[i] == "--nocache":
			noCache = true
		default:
			sshArgs = append(sshArgs, args[i])
		}
	}

	if caName == "" {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ssh --ca <ca-name> [--reason <reason>] [--nocache] [ssh arguments...]")
		fmt.Fprintln(os.Stderr, "\nWraps ssh with automatic certificate generation via Secsy PKI.")
		fmt.Fprintln(os.Stderr, "Authenticates via OIDC (opens browser), signs your SSH key, and connects.")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		fmt.Fprintln(os.Stderr, "  --ca <name>      CA to sign with (required)")
		fmt.Fprintln(os.Stderr, "  --reason <text>   Reason for the certificate (prompted if CA requires it)")
		fmt.Fprintln(os.Stderr, "  --nocache         Skip certificate cache, always request a new one")
		fmt.Fprintln(os.Stderr, "\nConfig: ~/.ssh/secsy.yaml")
		fmt.Fprintln(os.Stderr, "  api_url: https://secsy-pki.example.com:8443")
		os.Exit(1)
	}

	// Load config
	cfg, err := loadConfig()
	if err != nil {
		fatal("Failed to load config (~/.ssh/secsy.yaml): %v", err)
	}

	// Find the user's SSH key
	keyPath, pubKey := findSSHKey()
	if keyPath == "" {
		fatal("No SSH key found in ~/.ssh (looked for id_ed25519, id_ecdsa, id_rsa)")
	}
	fmt.Fprintf(os.Stderr, "secsy-ssh: using key %s\n", keyPath)

	// Extract the SSH username
	sshUser := extractSSHUser(sshArgs)
	if sshUser == "" {
		sshUser = os.Getenv("USER")
	}

	// Check cache first
	cacheKey := computeCacheKey(os.Args[1:])
	if !noCache {
		if cached := loadCachedCert(cacheKey); cached != "" {
			fmt.Fprintf(os.Stderr, "secsy-ssh: using cached certificate\n")
			runSSH(keyPath, cached, sshArgs)
			return
		}
	}

	// Get OIDC token via browser flow
	token, err := oidcLogin(cfg)
	if err != nil {
		fatal("OIDC login failed: %v", err)
	}

	// Find the CA by name
	caID, err := findCA(cfg, token, caName)
	if err != nil {
		fatal("Failed to find CA %q: %v", caName, err)
	}

	// Check if the CA requires a reason (fetch restrictions)
	if reason == "" {
		rs, _ := getRestrictions(cfg, token, caID)
		if rs != nil && rs.RequireReason {
			fmt.Fprint(os.Stderr, "secsy-ssh: this CA requires a reason. Enter reason: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				reason = strings.TrimSpace(scanner.Text())
			}
			if reason == "" {
				fatal("Reason is required by this CA")
			}
		}
	}

	// Sign the public key
	certStr, err := signKey(cfg, token, caID, pubKey, sshUser, reason)
	if err != nil {
		fatal("Failed to sign key: %v", err)
	}

	// Cache the certificate
	cacheCert(cacheKey, certStr)

	// Run SSH
	runSSH(keyPath, certStr, sshArgs)
}

func runSSH(keyPath, certStr string, sshArgs []string) {
	// Use memfd_create to hold the certificate in memory only — no disk writes
	fd, err := memfdCreate("secsy-ssh-cert")
	if err != nil {
		fatal("Failed to create memfd: %v", err)
	}
	certFile := os.NewFile(fd, "secsy-ssh-cert")
	certFile.WriteString(certStr)
	// Seek back so ssh can read it, keep the fd open
	certFile.Seek(0, 0)

	// ExtraFiles makes the fd available to the child process as fd 3+index
	// Index 0 in ExtraFiles = fd 3 in the child
	childFd := 3 // stdin=0, stdout=1, stderr=2, first extra=3
	certPath := fmt.Sprintf("/proc/self/fd/%d", childFd)
	fmt.Fprintf(os.Stderr, "secsy-ssh: certificate in memory\n")

	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fatal("ssh not found in PATH")
	}

	fullArgs := []string{
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
	}
	fullArgs = append(fullArgs, sshArgs...)

	cmd := exec.Command(sshBin, fullArgs...)
	cmd.ExtraFiles = []*os.File{certFile}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

// --- Cache ---

func cacheDir() string {
	// Use XDG_RUNTIME_DIR if available, otherwise /tmp/secsy-ssh-<uid>
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		d := filepath.Join(dir, "secsy-ssh")
		os.MkdirAll(d, 0700)
		return d
	}
	d := filepath.Join(os.TempDir(), fmt.Sprintf("secsy-ssh-%d", os.Getuid()))
	os.MkdirAll(d, 0700)
	return d
}

func computeCacheKey(args []string) string {
	h := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	return fmt.Sprintf("%x", h[:16])
}

func loadCachedCert(key string) string {
	path := filepath.Join(cacheDir(), key+".pub")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	cert := strings.TrimSpace(string(data))

	// Parse the certificate and check ValidBefore
	pub, _, _, _, err := sshPkg.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		os.Remove(path)
		return ""
	}
	sshCert, ok := pub.(*sshPkg.Certificate)
	if !ok {
		os.Remove(path)
		return ""
	}
	expiry := time.Unix(int64(sshCert.ValidBefore), 0)
	if time.Now().After(expiry) {
		os.Remove(path)
		return ""
	}
	return cert
}

func cacheCert(key, cert string) {
	path := filepath.Join(cacheDir(), key+".pub")
	os.WriteFile(path, []byte(cert), 0600)
}

// --- Config ---

func loadConfig() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "secsy.yaml"))
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("api_url is required in ~/.ssh/secsy.yaml")
	}
	return &cfg, nil
}

// --- SSH key ---

func findSSHKey() (keyPath string, pubKey string) {
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")

	// Prefer well-known key types in order, then fall back to any id_* key
	preferred := []string{"id_ed25519", "id_ecdsa", "id_rsa"}
	for _, name := range preferred {
		if kp, pk := tryKey(sshDir, name); kp != "" {
			return kp, pk
		}
	}

	// Scan for any id_* key not in the preferred list
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return "", ""
	}
	seen := map[string]bool{"id_ed25519": true, "id_ecdsa": true, "id_rsa": true}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "id_") || strings.HasSuffix(name, ".pub") || seen[name] {
			continue
		}
		if kp, pk := tryKey(sshDir, name); kp != "" {
			return kp, pk
		}
	}
	return "", ""
}

func tryKey(sshDir, name string) (string, string) {
	privPath := filepath.Join(sshDir, name)
	pubPath := privPath + ".pub"
	if _, err := os.Stat(privPath); err != nil {
		return "", ""
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return "", ""
	}
	return privPath, strings.TrimSpace(string(pubData))
}

func extractSSHUser(args []string) string {
	for i, arg := range args {
		if arg == "-l" && i+1 < len(args) {
			return args[i+1]
		}
		if !strings.HasPrefix(arg, "-") && strings.Contains(arg, "@") {
			return strings.SplitN(arg, "@", 2)[0]
		}
	}
	return ""
}

// --- API ---

func httpClient(cfg *Config) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
		},
	}
}

func apiGet(cfg *Config, token, path string) ([]byte, error) {
	req, _ := http.NewRequest("GET", cfg.APIURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient(cfg).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func apiPost(cfg *Config, token, path string, payload interface{}) ([]byte, error) {
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", cfg.APIURL+path, strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient(cfg).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func findCA(cfg *Config, token, caName string) (string, error) {
	body, err := apiGet(cfg, token, "/api/cas")
	if err != nil {
		return "", err
	}
	var cas []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(body, &cas); err != nil {
		return "", err
	}
	for _, ca := range cas {
		if strings.EqualFold(ca.Label, caName) || ca.ID == caName {
			return ca.ID, nil
		}
	}
	available := make([]string, len(cas))
	for i, ca := range cas {
		available[i] = ca.Label
	}
	return "", fmt.Errorf("CA %q not found (available: %s)", caName, strings.Join(available, ", "))
}

type restrictionSet struct {
	ForceKeyIDEmail bool `json:"force_key_id_email"`
	RequireReason   bool `json:"require_reason"`
}

func getRestrictions(cfg *Config, token, caID string) (*restrictionSet, error) {
	body, err := apiGet(cfg, token, "/api/cas/"+caID+"/my-restrictions")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(body)) == "null" {
		return nil, nil
	}
	var rs restrictionSet
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func signKey(cfg *Config, token, caID, pubKey, principal, reason string) (string, error) {
	principals := []string{}
	if principal != "" {
		principals = []string{principal}
	}
	payload := map[string]interface{}{
		"public_key":   pubKey,
		"cert_type":    "user",
		"principals":   principals,
		"valid_before": "+1d",
	}
	if reason != "" {
		payload["reason"] = reason
	}
	body, err := apiPost(cfg, token, "/api/cas/"+caID+"/sign", payload)
	if err != nil {
		return "", err
	}
	var resp struct {
		Certificate string `json:"certificate"`
		KeyID       string `json:"key_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if resp.Certificate == "" {
		return "", fmt.Errorf("empty certificate in response")
	}
	fmt.Fprintf(os.Stderr, "secsy-ssh: certificate key_id=%s\n", resp.KeyID)
	return resp.Certificate, nil
}

// --- OIDC ---

func oidcLogin(cfg *Config) (string, error) {
	resp, err := httpClient(cfg).Get(cfg.APIURL + "/api/auth/config")
	if err != nil {
		return "", fmt.Errorf("getting auth config: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var authCfg struct {
		OIDCEnabled bool   `json:"oidc_enabled"`
		IssuerURL   string `json:"issuer_url"`
		ClientID    string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &authCfg); err != nil {
		return "", fmt.Errorf("parsing auth config: %w", err)
	}
	if !authCfg.OIDCEnabled {
		return "", fmt.Errorf("OIDC is not enabled on the server")
	}

	discoResp, err := httpClient(cfg).Get(authCfg.IssuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}
	defer discoResp.Body.Close()
	discoBody, _ := io.ReadAll(discoResp.Body)

	var disco struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(discoBody, &disco); err != nil {
		return "", fmt.Errorf("parsing discovery: %w", err)
	}

	verifierBytes := make([]byte, 32)
	if _, err := io.ReadFull(cryptoRandReader(), verifierBytes); err != nil {
		return "", err
	}
	codeVerifier := base64URLEncode(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64URLEncode(challengeHash[:])

	const callbackPort = 18329
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", callbackPort))
	if err != nil {
		return "", fmt.Errorf("starting callback server on port %d: %w", callbackPort, err)
	}
	callbackURL := fmt.Sprintf("http://localhost:%d/callback", callbackPort)

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("no code in callback: %s", r.URL.Query().Get("error_description"))
			w.Write([]byte("Login failed. Check the terminal."))
			return
		}
		codeChan <- code
		w.Write([]byte("<html><body><h2>Login successful!</h2><p>You can close this window.</p><script>window.close()</script></body></html>"))
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	defer srv.Shutdown(context.Background())

	state := base64URLEncode(verifierBytes[:16])
	authURL := disco.AuthEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {authCfg.ClientID},
		"redirect_uri":          {callbackURL},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	fmt.Fprintf(os.Stderr, "secsy-ssh: opening browser for login...\n")
	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "secsy-ssh: could not open browser, visit this URL:\n%s\n", authURL)
	}

	var code string
	select {
	case code = <-codeChan:
	case err := <-errChan:
		return "", err
	case <-time.After(120 * time.Second):
		return "", fmt.Errorf("login timed out after 2 minutes")
	}

	tokenResp, err := http.PostForm(disco.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {authCfg.ClientID},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer tokenResp.Body.Close()
	tokenBody, _ := io.ReadAll(tokenResp.Body)

	var tokens struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		ErrDesc string `json:"error_description"`
	}
	if err := json.Unmarshal(tokenBody, &tokens); err != nil {
		return "", fmt.Errorf("parsing tokens: %w", err)
	}
	if tokens.IDToken == "" {
		return "", fmt.Errorf("no id_token: %s %s", tokens.Error, tokens.ErrDesc)
	}

	fmt.Fprintf(os.Stderr, "secsy-ssh: OIDC login successful\n")
	return tokens.IDToken, nil
}

// --- Helpers ---

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func cryptoRandReader() io.Reader {
	return cryptoRandReaderImpl{}
}

type cryptoRandReaderImpl struct{}

func (cryptoRandReaderImpl) Read(p []byte) (n int, err error) {
	return cryptoRead(p)
}

func openBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "secsy-ssh: "+format+"\n", args...)
	os.Exit(1)
}
