// Package pgdriver registers the PostgreSQL database/sql driver used by every
// PostgreSQL-backed component (the store, the leader-election session, and the
// backup restore-verification scratch databases).
//
// It exists so the driver choice is made in exactly one place. Blank-import it
// from any package that calls sql.Open("postgres", ...):
//
//	import _ "github.com/blechschmidt/secsy-pki/server/internal/pgdriver"
//
// # Why pgx rather than lib/pq
//
// The driver underneath is github.com/jackc/pgx/v5 in its database/sql
// compatibility mode (pgx/v5/stdlib). It replaced github.com/lib/pq, which is
// in maintenance mode upstream and accumulated a set of protocol-parsing
// advisories — unbounded memory consumption and panics on malformed backend
// frames (GO-2026-6170 … GO-2026-6173), a SCRAM iteration-count CPU DoS
// (GO-2026-6168), disclosure of the wrong .pgpass credential when hostaddr is
// set (GO-2026-6169), and GSS authentication that completes without mutual
// proof (GO-2026-6166) — none of which have, or will get, a fixed release.
//
// Those bugs are reachable from a hostile or MITM'd PostgreSQL endpoint, which
// is precisely the boundary a CA must not trust blindly: the store holds the
// hash-chained audit log, the revocation state, and the CA inventory. Pinning
// an unfixable driver there was not an option, so the dependency moved rather
// than being suppressed in the vulnerability gate.
//
// # Driver name
//
// pgx/v5/stdlib registers itself as "pgx" and "pgx/v5". This package
// additionally registers it as "postgres" — the name used in config files,
// Helm values, and DSNs throughout the deployment — so the migration is
// invisible to operators and no existing configuration has to change.
//
// # Behavioural notes
//
// pgx defaults to the extended query protocol with server-side prepared
// statement caching. That is correct for a direct connection and for session
// pooling, but a transaction-pooling proxy (PgBouncer in transaction mode,
// pgcat) cannot carry prepared statements across the pooled backend. Deployments
// behind such a proxy should append
//
//	default_query_exec_mode=simple_protocol
//
// to the DSN, which pgx honours natively.
package pgdriver

import (
	"database/sql"

	"github.com/jackc/pgx/v5/stdlib"
)

// DriverName is the database/sql driver name this package registers, and the
// value config files carry as database.driver.
const DriverName = "postgres"

func init() {
	sql.Register(DriverName, stdlib.GetDefaultDriver())
}
