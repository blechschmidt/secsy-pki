# Unix-domain-socket listeners

The HTTP (REST + console) and gRPC surfaces can be exposed **only over a Unix
domain socket** instead of a TCP port. Setting a socket path moves that listener
off the network entirely: no port is bound, nothing outside the host can reach
it, and **who may connect is decided by the socket's ownership and permission
bits** rather than by a firewall.

This suits the deployments where the PKI is a *local signing oracle* rather than
a network service:

- a **reverse proxy or API gateway** on the same host or in the same pod
  terminates TLS and is the only legitimate client;
- a **sidecar** (cert-manager shim, agent, exporter) talks to the PKI over the
  pod's shared `emptyDir`;
- a **single-host deployment** where the console and CLI are used locally and no
  port should be reachable at all — not even on loopback, which every other
  local user and every container sharing the network namespace can reach.

## Enabling it

```yaml
server:
  unix_socket:
    path: /run/secsy/api.sock     # absolute; setting it disables the TCP listener
    mode: "0660"                  # default 0600 (owner only)
    group: "secsy"                # optional: group name or numeric GID

grpc:
  enabled: true
  unix_socket:
    path: /run/secsy/grpc.sock    # must differ from the HTTP socket
    mode: "0660"
    group: "secsy"
```

`server.host` / `server.port` and `grpc.address` are **ignored** for a listener
that has a socket path: the feature is deliberately exclusive — "also listen on
a port" would defeat the point of choosing a socket.

Both paths may also come from the environment, which is convenient when the
runtime, not the config file, decides the mount point:

```
SECSY_SERVER_UNIX_SOCKET=/run/secsy/api.sock
SECSY_GRPC_UNIX_SOCKET=/run/secsy/grpc.sock
```

## TLS is optional here — and that is not a downgrade

Everywhere else the server **fails closed** without TLS: it refuses to start
unless `SECSY_ALLOW_INSECURE_HTTP=1` says an operator accepts cleartext behind a
trusted terminating proxy ([security review](../security/security-review.md)).
That rule protects bytes crossing a network. A Unix socket crosses no network:
the kernel copies the request from one local process to another, and a
certificate could not name a host to authenticate anyway. So **cleartext over a
socket needs no opt-in**, and the socket's mode replaces the certificate as the
confidentiality boundary.

What does *not* change: **every route still authenticates exactly as it does over
TLS**. Opening the socket to a user grants them the ability to *reach* the API,
not to use it — Basic/Bearer/token/mTLS credentials, RBAC, tenant scoping,
four-eyes approvals, and the audit chain all behave identically.

You can still serve TLS on the socket (set `server.tls_cert`/`tls_key` or
`server.tls.self_issue` as usual) for a client that insists on it; mutual-TLS
operator binding also keeps working.

## Permissions

| Setting | Meaning |
|---------|---------|
| `mode` unset | **0600** — only the user the server runs as can connect. The default fails closed: an unset mode never widens access. |
| `mode: "0660"` + `group:` | The intended shape for a sidecar or proxy under a different account: put that account in the group. |
| `mode: "0666"` | Every local account may connect (still authenticated). `secsy-ca doctor` warns; prefer a group. |

Two details are handled for you:

- **No permission race.** `bind(2)` takes no mode argument, so a socket is created
  with `0777 &^ umask` — world-connectable under a typical `umask 022` for the
  window before `chmod`. The server binds under a `0777` umask (socket created
  `0000`, connectable by nobody) and then chmods to the configured mode, so the
  socket is never briefly more permissive than configured.
- **The parent directory matters.** Anyone who can write the directory can unlink
  the socket and bind their own in its place, and clients would then hand their
  credentials to the impostor. Put the socket in a directory only the server's
  user (or root) can write — `/run/secsy`, mode `0750`, not bare `/tmp`. Doctor
  warns about a world-writable directory without the sticky bit.

The socket's parent directory must already exist; the server will not create it
and guess at its permissions.

## Restart behaviour

A cleanly stopped server unlinks its socket. A process killed with `SIGKILL`
leaves the socket inode behind, and a naive `bind` would then fail with
`EADDRINUSE` forever. The server therefore **reclaims a stale socket** — but only
after proving it is stale:

- a connect attempt must fail (nothing is listening) — a socket a live instance
  is serving is reported as *already in use* rather than stolen from it;
- the path must actually be a socket — a mistyped path pointing at a regular
  file is refused, never unlinked.

## Talking to a socket listener

```bash
# REST / console
curl --unix-socket /run/secsy/api.sock http://localhost/healthz
curl --unix-socket /run/secsy/api.sock -u root:… http://localhost/api/keys

# gRPC — "unix://" is a native gRPC target, and secsy-ca defaults it to
# plaintext because there is no network to protect and no hostname to verify.
secsy-ca grpc -addr unix:///run/secsy/grpc.sock -operation demo -ca <ca-id> -basic root:…
grpcurl -plaintext -unix /run/secsy/grpc.sock list
```

Naming any TLS material (`-cacert`, `-client-cert`) still selects TLS, for a
deployment that terminates it on the socket.

## Who is calling: peer credentials

The kernel gives an unnamed Unix-socket client an empty address, which Go renders
as `@`. Left alone, every local caller would share one rate-limit bucket and one
indistinguishable line in the audit log. Instead each accepted connection reports
the peer's **user ID** — read from the kernel with `SO_PEERCRED`, so a client
cannot forge it — as its remote address:

```json
{"msg":"http_request","route":"POST /api/ca/init-root","status":201,"remote_ip":"unix/0"}
```

`unix/<uid>` is the local analogue of a source IP, and it flows to the same
places one does: the JSON access log, the `ip` column of the tamper-evident audit
chain, and the per-source [rate-limit](../security/rate-limiting.md) buckets — so
two local accounts sharing a socket are metered separately.

## Operational notes

- **Health probes.** Kubernetes cannot HTTP-probe a socket. Use an `exec` probe
  (`curl --unix-socket /run/secsy/api.sock http://localhost/healthz`) or keep a
  TCP listener for a deployment that needs HTTP probes. Prometheus likewise
  scrapes `/metrics` over TCP, so a socket-only deployment needs a local
  exporter/proxy to expose it ([observability](../operations/observability.md)).
- **ACME, EST, SCEP, CMP, OCSP and CRL** are all served on the HTTP listener. In
  socket-only mode they are reachable only through whatever proxies the socket —
  which is the intent when a gateway fronts the PKI, and a misconfiguration when
  device enrollment is supposed to reach it directly.
- **Path length.** `sun_path` is a fixed 108-byte kernel buffer (104 on the BSDs);
  paths longer than 103 bytes are rejected at config-load time with a clear
  message rather than a bare `invalid argument` from `bind`.
- **Diagnostics.** `secsy-ca doctor` reports `listener.unix_socket` (path,
  permissions, directory safety, and whether anything is bound), and
  `listener.tls` passes instead of failing when the listener is a socket:

  ```
  ✓ pass  listener.tls          no listener TLS, and none required: HTTP is served on the unix
                                socket /run/secsy/api.sock and no TCP port is bound
  ✓ pass  listener.unix_socket  http /run/secsy/api.sock (mode 0660, group secsy): bound and
                                accepting connections; grpc /run/secsy/grpc.sock (mode 0660): …
  ```

## See also

- [Kubernetes deployment](kubernetes.md) — sharing a socket with a sidecar
  through a pod `emptyDir`, and probe options.
- [Self-managed serving-TLS certificate](serving-cert.md) — the TCP listener's
  certificate story, still available on a socket.
- [Operator authentication](../security/authentication.md) — the credentials the
  socket does *not* replace.
- [Rate limiting & abuse protection](../security/rate-limiting.md) — what
  `unix/<uid>` keys.
- [gRPC API](../protocols/grpc-api.md) — the surface behind `grpc.unix_socket`.

---

↩ Back to [deployment & scaling](README.md) · [documentation map](../README.md)
