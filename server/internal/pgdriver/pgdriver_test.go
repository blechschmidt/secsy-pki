package pgdriver

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestDriverRegisteredAsPostgres pins the contract the rest of the deployment
// depends on: the driver is reachable under the name "postgres". Config files,
// Helm values, `secsy-ca db -to-driver postgres`, the leader-election session
// and the backup restore-verification scratch databases all name it literally,
// so losing the registration would break every PostgreSQL deployment at once —
// and only at runtime, since nothing else references this package's symbols.
func TestDriverRegisteredAsPostgres(t *testing.T) {
	if !slices.Contains(sql.Drivers(), DriverName) {
		t.Fatalf("driver %q not registered; sql.Drivers() = %v", DriverName, sql.Drivers())
	}
	// sql.Open must hand back a usable handle for the registered name. It does
	// not dial (nor even parse the DSN — pgx defers both to first use), so this
	// reaches no server; DSN grammar is covered below against the parser the
	// driver actually applies on connect.
	db, err := sql.Open(DriverName, "postgres://secsy@db.example.com/secsy_pki")
	if err != nil {
		t.Fatalf("sql.Open(%q, ...) = %v", DriverName, err)
	}
	_ = db.Close()
}

// TestSupportedDSNFormsParse guards the operator-visible half of the lib/pq →
// pgx migration: every DSN form that used to work must still work, so no
// existing config has to change. pgconn.ParseConfig is the parser pgx applies
// when the pool first dials, so asserting against it — rather than against
// sql.Open, which accepts anything — is what actually proves the DSN is valid.
func TestSupportedDSNFormsParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
	}{
		{"url", "postgres://secsy:secret@db.example.com:5432/secsy_pki?sslmode=require"},
		{"url postgresql scheme", "postgresql://secsy@db.example.com/secsy_pki"},
		{"keyword value", "host=db.example.com user=secsy password=secret dbname=secsy_pki sslmode=require"},
		// The documented workaround for transaction-pooling proxies (PgBouncer in
		// transaction mode) must actually parse, or the guidance is a trap.
		{"simple protocol override", "postgres://secsy@pgbouncer:6432/secsy_pki?default_query_exec_mode=simple_protocol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pgconn.ParseConfig(tc.dsn); err != nil {
				t.Fatalf("ParseConfig(%q) = %v, want accepted", tc.dsn, err)
			}
		})
	}
}

// TestMalformedDSNRejected confirms a bad DSN is a parse error rather than
// something that silently connects somewhere unintended — an sslmode typo must
// not quietly downgrade the transport to the store that holds the audit chain.
func TestMalformedDSNRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
	}{
		{"non-numeric port", "postgres://secsy@db.example.com:not-a-port/secsy_pki"},
		{"unknown sslmode", "postgres://secsy@db.example.com/secsy_pki?sslmode=bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pgconn.ParseConfig(tc.dsn); err == nil {
				t.Fatalf("ParseConfig(%q) accepted a malformed DSN, want error", tc.dsn)
			}
		})
	}
}
