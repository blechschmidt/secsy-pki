#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "==> Starting test infrastructure..."
docker compose -f docker-compose.test.yaml up -d

echo "==> Waiting for KeyCloak to be ready..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:8080/realms/ssh-pki/.well-known/openid-configuration > /dev/null 2>&1; then
        echo "    KeyCloak is ready."
        break
    fi
    if [ "$i" = "60" ]; then
        echo "    ERROR: KeyCloak failed to start within 60 seconds."
        docker compose -f docker-compose.test.yaml logs keycloak
        docker compose -f docker-compose.test.yaml down
        exit 1
    fi
    sleep 2
done

echo "==> Creating test config..."
cat > /tmp/ssh-pki-test-config.yaml << EOF
server:
  host: "0.0.0.0"
  port: 8443
  tls_cert: "${PROJECT_DIR}/certs/server.crt"
  tls_key: "${PROJECT_DIR}/certs/server.key"

database:
  driver: "sqlite"
  dsn: "/tmp/ssh-pki-test.db"

oidc:
  issuer_url: "http://localhost:8080/realms/ssh-pki"
  client_id: "ssh-pki"
  client_secret: "test-client-secret"
  redirect_url: "https://localhost:8443/api/auth/callback"

root_user:
  username: "root"
  password: "integration-test-password"

pkcs11:
  module_path: "/usr/lib/pkcs11/libsofthsm2.so"
  pin: "1234"
  token_label: "ssh-pki-root"
EOF

echo "==> Starting SSH PKI server..."
rm -f /tmp/ssh-pki-test.db
go build -o /tmp/ssh-pki-server ./cmd/server
/tmp/ssh-pki-server -config /tmp/ssh-pki-test-config.yaml &
SERVER_PID=$!

# Wait for server to start
sleep 2
for i in $(seq 1 15); do
    if curl -sfk https://localhost:8443/api/health > /dev/null 2>&1; then
        echo "    Server is ready."
        break
    fi
    if [ "$i" = "15" ]; then
        echo "    ERROR: Server failed to start."
        kill $SERVER_PID 2>/dev/null
        docker compose -f docker-compose.test.yaml down
        exit 1
    fi
    sleep 1
done

echo "==> Running integration tests..."
INTEGRATION_TEST=1 go test -v -count=1 -timeout 120s ./... 2>&1
TEST_EXIT=$?

echo "==> Cleaning up..."
kill $SERVER_PID 2>/dev/null
docker compose -f docker-compose.test.yaml down
rm -f /tmp/ssh-pki-test.db /tmp/ssh-pki-test-config.yaml /tmp/ssh-pki-server

if [ $TEST_EXIT -eq 0 ]; then
    echo "==> All integration tests passed!"
else
    echo "==> Some integration tests failed."
fi
exit $TEST_EXIT
