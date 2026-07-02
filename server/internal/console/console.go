// Package console serves a minimal, embedded operator web console for the
// enterprise PKI. The single-page app is bundled into the server binary via
// go:embed, so no separate front-end build or deploy is required — the console
// ships wherever the server ships (including the container image / Helm chart).
//
// The console holds no privileges of its own: every data operation it performs
// goes through the existing REST API, which is authenticated, RBAC-gated, and
// audited server-side (see internal/handlers). The browser attaches the
// operator's credentials (basic-auth for the root user, or an OIDC bearer
// token) to each API call, so the console inherits exactly the caller's
// authorization and every mutating action lands in the hash-chained event log.
package console

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var assets embed.FS

// staticFS returns the embedded console assets rooted at the static directory.
func staticFS() fs.FS {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		// Unreachable: the static directory is embedded at build time.
		panic(err)
	}
	return sub
}

// MountPath is the URL prefix the console is served under.
const MountPath = "/console/"

// Register mounts the embedded operator console at /console/. Requests for the
// bare /console are redirected to /console/ by the standard-library ServeMux
// (subtree-pattern redirect) so the app's relative asset URLs resolve.
//
// The assets are static and public — the sensitive operations they drive are
// gated by the API's auth + RBAC + audit middleware, not by hiding the HTML.
func Register(mux *http.ServeMux) {
	fileServer := http.FileServer(http.FS(staticFS()))
	mux.Handle("GET "+MountPath, http.StripPrefix("/console", fileServer))
}
