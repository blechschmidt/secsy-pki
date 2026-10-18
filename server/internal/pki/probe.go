package pki

import (
	"github.com/miekg/pkcs11"
)

// Probe verifies connectivity to the configured PKCS#11 token without requiring
// any particular key to exist. It finds the configured token, opens a session,
// and logs in with the user PIN — the same steps every signing operation
// performs, minus the key lookup. It returns nil when the token is reachable and
// the PIN is accepted, and a descriptive error otherwise. All resources it opens
// are released before returning.
//
// This is intended for readiness probes: a healthy result means the HSM can
// service signing requests right now.
//
// It runs over the process-shared module context (withModuleSession), so
// probing a token that the serving session pool already holds open neither
// disturbs that pool nor reports a spurious failure — and a wrong PIN is still
// reported as one: when the token short-circuits the login with
// CKR_USER_ALREADY_LOGGED_IN, loginShared compares the offered PIN against the
// one that established the live login rather than accepting it unchecked.
func Probe(cfg PKCS11Config) error {
	return withModuleSession(cfg, false, func(*pkcs11.Ctx, pkcs11.SessionHandle) error {
		return nil
	})
}
