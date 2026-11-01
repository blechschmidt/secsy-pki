package ca

import (
	"fmt"
	"strings"
)

// NormalizeCertAlgorithm resolves the operator-facing signature-scheme selector
// used by the REST API, the CLI and the console into a CertAlgorithm. The empty
// string and the explicit classical spellings all mean classical, which is the
// zero value, so a request that omits the field keeps today's behaviour.
//
// The aliases are the names the same thing goes by in the literature: "catalyst"
// and "composite" for the dual-signature hybrid, "ml-dsa" and "post-quantum" for
// the pure post-quantum scheme.
func NormalizeCertAlgorithm(s string) (CertAlgorithm, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "classical", "rsa", "ecdsa", "ed25519":
		return AlgClassical, nil
	case "pqc", "ml-dsa", "mldsa", "post-quantum":
		return AlgPQC, nil
	case "hybrid", "catalyst", "composite":
		return AlgHybrid, nil
	default:
		return AlgClassical, fmt.Errorf("unknown algorithm %q (want classical, pqc, or hybrid)", s)
	}
}
