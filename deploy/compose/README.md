# Docker Compose stack

A working secsy-pki deployment in two commands, for evaluation and development.

```bash
cp .env.example .env        # then change the PIN and the passwords
docker compose up -d
docker compose logs -f server
```

The walkthrough — what the services do, how to reach the API over verified TLS,
how to run the CLI against a running stack, and what to change for production —
is [docs/deployment/container.md](../../docs/deployment/container.md).

| File | Role |
|------|------|
| `docker-compose.yaml` | The stack: a one-shot `bootstrap` plus the `server` |
| `docker-compose.postgres.yaml` | Overlay swapping SQLite for PostgreSQL |
| `config.yaml` | The server config, mounted read-only. Holds no secrets |
| `bootstrap.sh` | Idempotent: initializes the PKCS#11 token and the CA hierarchy |
| `.env.example` | Template for the PIN and passwords. `.env` is gitignored |

PostgreSQL instead of SQLite — no change to `config.yaml`, because the driver and
DSN come from the environment:

```bash
docker compose -f docker-compose.yaml -f docker-compose.postgres.yaml up -d
```

## What this is not

**SoftHSM is not an HSM.** It ships in the image so this stack runs anywhere, but
its token store is a directory of files in a Docker volume, and the CA private
keys are exactly as protected as that volume. For a real deployment point
`SECSY_PKCS11_MODULE` at a vendor module (or use the `-yubihsm` image) and
provision the token as a [key ceremony](../../docs/hsm/key-ceremony.md) rather
than from a container entrypoint.

The `.env` defaults are also deliberately unusable as-is: the stack fails to start
until the PIN and passwords are changed, rather than coming up with values
published in this repository.

For Kubernetes, use the [Helm chart](../helm/secsy-pki/) instead — it covers
HSM module mounts, PINs from Secrets, probes and multi-replica coordination.
