package handlers

// Shared plumbing for the operator-operations endpoints added to close the
// CLI→console parity gap (Task 198).
//
// A handful of `secsy-ca` capabilities previously had no REST counterpart at
// all, so the console could not offer them however it was written: preflight
// diagnostics (`doctor`), DR backup/restore verification (`backup`,
// `backup verify-restore`), static-artifact publishing (`publish`), inventory
// retention (`inventory retention`), evidence records (`ers`), key and CA
// adoption (`import-key`, `ca import`), and TSA / code-signing key provisioning
// (`tsa-key`, `signing-key`).
//
// Those commands are config-driven and several need a key provider for a role
// other than "ca", neither of which the API otherwise holds. Rather than thread
// a growing list of setters through the struct, they share one optional
// dependency bundle: when the server installs it every endpoint works, and when
// it is absent (unit tests, the CLI reusing a handler) each answers 503 with a
// clear reason instead of panicking or silently degrading.

import (
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// OpsDeps carries what the operations endpoints need beyond the database and
// the CA key provider.
type OpsDeps struct {
	// Config is the loaded server configuration, shared read-only. The
	// operations endpoints read the same settings the CLI reads (backup
	// destinations, publish targets, retention windows, doctor thresholds), so
	// the console and `secsy-ca` cannot drift into reporting different policy.
	Config *config.Config
	// ProviderFor builds an instrumented key provider for a signing role ("ca",
	// "tsa", "signing", "secret"), mirroring the CLI's per-role provider
	// selection. Callers own the returned provider and must Close it. nil means
	// role-scoped providers are unavailable.
	ProviderFor func(role string) (keyprovider.Provider, error)
	// ConfigPath is the path the configuration was loaded from, reported by the
	// diagnostics endpoint so an operator can tell which file the running
	// process is answering for. Empty is fine.
	ConfigPath string
}

// SetOps installs the operations-endpoint dependency bundle. Passing nil (the
// default) leaves those endpoints reporting 503 "not configured".
func (a *API) SetOps(d *OpsDeps) { a.ops = d }

// opsDeps returns the installed bundle, or nil when the server did not wire it.
func (a *API) opsDeps() *OpsDeps { return a.ops }

// requireOps writes the 503 and reports false when the operations dependencies
// are not installed, so each handler can start with a single guarded line.
func (a *API) requireOps(w http.ResponseWriter, what string) (*OpsDeps, bool) {
	if a.ops == nil || a.ops.Config == nil {
		writeError(w, http.StatusServiceUnavailable,
			"%s is unavailable: this server was started without the operations dependencies", what)
		return nil, false
	}
	return a.ops, true
}

// roleProvider builds a NEW key provider for the given signing role, writing the
// error response itself. Callers must Close the returned provider.
//
// It is the "genuinely different backend" branch of providerForRole
// (keyimport_admin.go) and has no other caller on purpose: a handler that opens a
// provider unconditionally opens a second session pool against a device that may
// not grant one, so every endpoint goes through providerForRole, which reuses the
// serving provider when the role resolves to the same backend.
func (a *API) roleProvider(w http.ResponseWriter, role, what string) (keyprovider.Provider, bool) {
	deps, ok := a.requireOps(w, what)
	if !ok {
		return nil, false
	}
	if deps.ProviderFor == nil {
		writeError(w, http.StatusServiceUnavailable,
			"%s is unavailable: no role-scoped key provider factory is installed", what)
		return nil, false
	}
	p, err := deps.ProviderFor(role)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "opening the %s key provider: %v", role, err)
		return nil, false
	}
	return p, true
}
