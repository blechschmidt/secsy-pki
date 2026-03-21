package main

import (
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

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIURL             string `yaml:"api_url"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

func main() {
	// Parse --ca flag and collect remaining args for ssh
	var caName string
	var sshArgs []string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--ca" && i+1 < len(args) {
			caName = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ca=") {
			caName = strings.TrimPrefix(args[i], "--ca=")
		} else {
			sshArgs = append(sshArgs, args[i])
		}
	}

	if caName == "" {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ssh --ca <ca-name> [ssh arguments...]")
		fmt.Fprintln(os.Stderr, "\nWraps ssh with automatic certificate generation via Secsy PKI.")
		fmt.Fprintln(os.Stderr, "Authenticates via OIDC (opens browser), signs your SSH key, and connects.")
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

	// Sign the public key
	certStr, err := signKey(cfg, token, caID, pubKey)
	if err != nil {
		fatal("Failed to sign key: %v", err)
	}

	// Write the certificate to a temp file
	certFile, err := os.CreateTemp("", "secsy-ssh-cert-*.pub")
	if err != nil {
		fatal("Failed to create temp file: %v", err)
	}
	certFile.WriteString(certStr)
	certFile.Close()
	defer os.Remove(certFile.Name())

	fmt.Fprintf(os.Stderr, "secsy-ssh: certificate written to %s\n", certFile.Name())

	// Run ssh with the certificate
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fatal("ssh not found in PATH")
	}

	fullArgs := []string{
		"-i", keyPath,
		"-o", "CertificateFile=" + certFile.Name(),
	}
	fullArgs = append(fullArgs, sshArgs...)

	cmd := exec.Command(sshBin, fullArgs...)
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

func findSSHKey() (keyPath string, pubKey string) {
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")

	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		privPath := filepath.Join(sshDir, name)
		pubPath := privPath + ".pub"
		if _, err := os.Stat(privPath); err != nil {
			continue
		}
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			continue
		}
		return privPath, strings.TrimSpace(string(pubData))
	}
	return "", ""
}

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

func signKey(cfg *Config, token, caID, pubKey string) (string, error) {
	body, err := apiPost(cfg, token, "/api/cas/"+caID+"/sign", map[string]interface{}{
		"public_key":   pubKey,
		"cert_type":    "user",
		"principals":   []string{},
		"valid_before": "+1d",
	})
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

// OIDC login via browser with PKCE
func oidcLogin(cfg *Config) (string, error) {
	// Get auth config from the server
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

	// Discover OIDC endpoints
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

	// Generate PKCE code verifier and challenge
	verifierBytes := make([]byte, 32)
	if _, err := io.ReadFull(cryptoRandReader(), verifierBytes); err != nil {
		return "", err
	}
	codeVerifier := base64URLEncode(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64URLEncode(challengeHash[:])

	// Start local callback server on a fixed port
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

	// Build authorization URL
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

	// Open browser
	fmt.Fprintf(os.Stderr, "secsy-ssh: opening browser for login...\n")
	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "secsy-ssh: could not open browser, visit this URL:\n%s\n", authURL)
	}

	// Wait for the callback
	var code string
	select {
	case code = <-codeChan:
	case err := <-errChan:
		return "", err
	case <-time.After(120 * time.Second):
		return "", fmt.Errorf("login timed out after 2 minutes")
	}

	// Exchange code for tokens
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
