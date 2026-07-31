package ers

import (
	"crypto"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// fipsDeprecated reports whether a hash algorithm is deprecated by the FIPS
// crypto policy: only when the fail-closed policy is enforced and the algorithm
// is not on its approved list. This is the default hash-tree-renewal trigger, so
// enabling security.fips (or adding a hash to the non-approved set) drives an
// automatic migration of every Evidence Record still on the weak algorithm.
func fipsDeprecated(h crypto.Hash) bool {
	return fips.PolicyEnforced() && fips.ApprovedHash(h) != nil
}
