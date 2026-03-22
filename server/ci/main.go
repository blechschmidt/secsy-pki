// Secsy PKI CI pipeline using Dagger
//
// Runs unit tests with SoftHSM and integration tests with KeyCloak.

package main

import (
	"context"
	"dagger/ci/internal/dagger"
)

type Ci struct{}

// Test runs all unit and integration tests with SoftHSM and KeyCloak
func (m *Ci) Test(ctx context.Context, source *dagger.Directory) (string, error) {
	keycloak := dag.Container().
		From("quay.io/keycloak/keycloak:26.0").
		WithExposedPort(8080, dagger.ContainerWithExposedPortOpts{
			ExperimentalSkipHealthcheck: true,
		}).
		WithEnvVariable("KC_BOOTSTRAP_ADMIN_USERNAME", "admin").
		WithEnvVariable("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin").
		WithEnvVariable("KC_HEALTH_ENABLED", "true").
		WithMountedDirectory("/opt/keycloak/data/import", source.Directory("testdata/keycloak")).
		WithExec([]string{"start-dev", "--import-realm"}, dagger.ContainerWithExecOpts{
			UseEntrypoint: true,
		}).
		AsService()

	return dag.Container().
		From("golang:1.25-bookworm").
		// Install SoftHSM and build dependencies
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "softhsm2", "opensc", "libpcsclite-dev", "openssh-client"}).
		// Initialize SoftHSM token
		WithExec([]string{"softhsm2-util", "--init-token", "--slot", "0", "--label", "secsy-test", "--pin", "1234", "--so-pin", "5678"}).
		// Generate an ECDSA key on SoftHSM for testing
		WithExec([]string{"pkcs11-tool", "--module", "/usr/lib/softhsm/libsofthsm2.so", "--login", "--pin", "1234",
			"--keypairgen", "--key-type", "EC:prime256v1", "--label", "test-ca", "--id", "01"}).
		// Mount source code
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		// Set up KeyCloak service
		WithServiceBinding("keycloak", keycloak).
		// Generate TLS certs for the server
		WithExec([]string{"bash", "-c", `
			mkdir -p certs
			openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			  -keyout certs/server.key -out certs/server.crt -days 1 -nodes \
			  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
		`}).
		// Write test config
		WithExec([]string{"bash", "-c", `cat > /tmp/test-config.yaml << 'YAML'
server:
  host: "0.0.0.0"
  port: 8443
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
database:
  driver: "sqlite"
  dsn: "/tmp/test.db"
oidc:
  issuer_url: "http://keycloak:8080/realms/secsy-pki"
  client_id: "secsy-pki"
root_user:
  username: "root"
  password: "test-password"
pkcs11:
  module_path: "/usr/lib/softhsm/libsofthsm2.so"
  pin: "1234"
  token_label: "secsy-test"
YAML`}).
		// Wait for KeyCloak to be ready
		WithExec([]string{"bash", "-c", `
			for i in $(seq 1 60); do
				curl -sf http://keycloak:8080/realms/secsy-pki/.well-known/openid-configuration > /dev/null 2>&1 && break
				sleep 2
			done
		`}).
		// Run unit tests with coverage
		WithExec([]string{"go", "test", "-tags", "sqlite", "-coverprofile=/tmp/unit-cover.out", "-count=1", "-v", "./internal/..."}).
		// Build the server
		WithExec([]string{"go", "build", "-tags", "sqlite", "-o", "/tmp/secsy-server", "./cmd/server"}).
		// Start the server and run integration tests
		WithExec([]string{"bash", "-c", `
			/tmp/secsy-server -config /tmp/test-config.yaml &
			SERVER_PID=$!
			sleep 3

			# Wait for server
			for i in $(seq 1 15); do
				curl -sfk https://localhost:8443/api/health > /dev/null 2>&1 && break
				sleep 1
			done

			# Seed a CA
			curl -sk -u root:test-password -X POST https://localhost:8443/api/keys \
			  -H 'Content-Type: application/json' \
			  -d '{"label":"Test CA","pkcs11_uri":"pkcs11:token=secsy-test;object=test-ca;type=private","key_type":"ecdsa-sha2-nistp256","public_key":"n/a"}'

			# Run integration tests
			INTEGRATION_TEST=1 go test -tags sqlite -coverprofile=/tmp/integ-cover.out -count=1 -v -timeout 120s ./... 2>&1
			TEST_EXIT=$?

			kill $SERVER_PID 2>/dev/null
			exit $TEST_EXIT
		`}).
		// Print coverage summary
		WithExec([]string{"bash", "-c", `
			echo "=== Unit Test Coverage ==="
			go tool cover -func=/tmp/unit-cover.out 2>/dev/null | tail -1
			echo ""
			echo "=== Integration Test Coverage ==="
			go tool cover -func=/tmp/integ-cover.out 2>/dev/null | tail -1 || true
		`}).
		Stdout(ctx)
}

// Build verifies the project compiles with and without SQLite
func (m *Ci) Build(ctx context.Context, source *dagger.Directory) (string, error) {
	return dag.Container().
		From("golang:1.25-bookworm").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "libpcsclite-dev"}).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		// Build with SQLite
		WithExec([]string{"go", "build", "-tags", "sqlite", "-o", "/tmp/server-sqlite", "./cmd/server"}).
		// Build without SQLite (PostgreSQL only)
		WithExec([]string{"go", "build", "-o", "/tmp/server-pg", "./cmd/server"}).
		// Build verify tool
		WithExec([]string{"go", "build", "-o", "/tmp/secsy-verify", "./cmd/verify"}).
		// Build secsy-ssh
		WithExec([]string{"go", "build", "-o", "/tmp/secsy-ssh", "./cmd/secsy-ssh"}).
		WithExec([]string{"echo", "All builds successful"}).
		Stdout(ctx)
}
