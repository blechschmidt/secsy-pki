//go:build !zlint

package certlint

// This is the default build: the zlint backend is NOT compiled in, so the tree
// carries no dependency on github.com/zmap/zlint or zcrypto. A profile that
// enables zlint still runs the hand-rolled Baseline Requirements checks; the
// zlint findings are simply unavailable. Build with `-tags zlint` to link the
// backend (see internal/certlint/zlint_backend.go and docs/issuance/certlint.md).

const zlintCompiledIn = false

// runZLint is a no-op in the default build. It never errors, so ZLintFindings
// returns no findings and the fail-closed gate relies on the hand-rolled checks.
func runZLint(_ []byte, _ zlintFilter) ([]zlintRaw, error) {
	return nil, nil
}
