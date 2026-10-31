package handlers

// REST surface of the raw PKCS#11 inspector (Task 218).
//
// Two endpoints, split by cost rather than by subject:
//
//	GET /api/pkcs11/module   — C_GetInfo, every slot, every token, every
//	                           mechanism. No session, no login, cheap.
//	GET /api/pkcs11/objects  — C_FindObjects over an empty template plus the
//	                           catalogued attributes of each object found.
//	                           One device round trip per object (several, on a
//	                           token that refuses attributes), so the console
//	                           loads it on request rather than on page open.
//
// Both are gated on platform hsm:manage — the same capability that administers
// the device elsewhere (key import, backup, provisioning). The object dump in
// particular names every object on the token, including ones no CA references,
// and the module view reports the token's serial and PIN-attempt state; neither
// is operator-general information.
//
// Neither endpoint can mutate the token: the inspector has no create, modify or
// destroy path, and it never requests private key material (see the policy note
// in internal/pki/pkcs11attrs.go). What it can do is cost device audit-log
// entries on a force-audited YubiHSM, which is why the object dump goes through
// the recording provider's operated() hook — the drain follows the operations.

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// PKCS11InspectResponse is the raw Cryptoki view of the deployment's token(s).
//
// Tokens is a list because a high-availability set is several tokens behind one
// provider, and the whole point of the view is to tell them apart: replicas
// share key labels deliberately, so only the member name and the token serial
// say which device an object is actually on.
type PKCS11InspectResponse struct {
	// Provider is the configured key-provider backend name.
	Provider string `json:"provider"`
	// Tokens is one view per token behind the provider.
	Tokens []keyprovider.TokenView `json:"tokens"`
	// AllAttributes echoes whether the whole attribute catalogue was requested
	// of every object, so a reader knows whether a missing row means "the token
	// does not have it" or "it was not asked for".
	AllAttributes bool `json:"all_attributes,omitempty"`
}

// pkcs11Inspector enforces the gate and resolves the provider's inspection
// capability, writing the response itself when either fails and reporting false
// so the caller simply returns.
func (a *API) pkcs11Inspector(w http.ResponseWriter, r *http.Request) (keyprovider.PKCS11Inspector, bool) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		a.recordEvent(r, audit.ActionHSMInspect, "", "", audit.ResultDenied, "hsm:manage capability required")
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return nil, false
	}
	ins, ok := a.keyProvider.(keyprovider.PKCS11Inspector)
	if !ok {
		a.writeNoPKCS11View(w)
		return nil, false
	}
	return ins, true
}

// writeNoPKCS11View answers the capability question: the request was understood
// and this backend cannot answer it. A software or cloud-KMS deployment
// legitimately has no slots, no CKA_* and no object handles, and 501 naming the
// backend says so — where a 200 carrying an empty view would read as the much
// more alarming "the token holds nothing".
func (a *API) writeNoPKCS11View(w http.ResponseWriter) {
	writeError(w, http.StatusNotImplemented, "the configured key provider (%s) has no PKCS#11 view", a.keyProvider.Name())
}

// inspectFailed maps an inspection error to a response, distinguishing the two
// kinds. ErrInspectUnsupported is the capability answer — and it can only
// surface here rather than at the type assertion above, because the
// instrumented and recording wrappers implement PKCS11Inspector
// unconditionally in order to forward it, so the assertion succeeds for every
// wrapped provider including the ones with no view. Everything else is the
// token or the module failing, which is a 500.
func (a *API) inspectFailed(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, keyprovider.ErrInspectUnsupported) {
		a.writeNoPKCS11View(w)
		return
	}
	writeError(w, http.StatusInternalServerError, "%s: %v", what, err)
}

// inspectOptions reads the inspection knobs off the query string. Every one is
// optional and bounded by the pki package's defaults; an unparsable value is
// ignored rather than rejected, since these only shape a read-only view.
func inspectOptions(r *http.Request) pki.InspectOptions {
	q := r.URL.Query()
	opts := pki.InspectOptions{
		AllAttributes: q.Get("all") == "1" || q.Get("all") == "true",
	}
	if n, err := strconv.Atoi(q.Get("max_objects")); err == nil && n > 0 {
		opts.MaxObjects = n
	}
	if n, err := strconv.Atoi(q.Get("max_value_bytes")); err == nil && n > 0 {
		opts.MaxValueBytes = n
	}
	return opts
}

// InspectPKCS11Module handles GET /api/pkcs11/module: the module, its slots,
// the token in each, and the mechanisms each offers. hsm:manage gated.
//
// Mechanism lists are the bulk of the payload (SoftHSM reports ~180, a YubiHSM
// ~70) and cost a C_GetMechanismInfo call each, so ?mechanisms=0 drops them.
func (a *API) InspectPKCS11Module(w http.ResponseWriter, r *http.Request) {
	ins, ok := a.pkcs11Inspector(w, r)
	if !ok {
		return
	}
	opts := inspectOptions(r)
	if m := r.URL.Query().Get("mechanisms"); m == "0" || m == "false" {
		opts.SkipMechanisms = true
	}
	views, err := ins.InspectPKCS11Module(r.Context(), opts)
	if err != nil {
		a.inspectFailed(w, "reading the PKCS#11 module view", err)
		return
	}
	writeJSON(w, http.StatusOK, PKCS11InspectResponse{Provider: a.keyProvider.Name(), Tokens: views})
}

// InspectPKCS11Objects handles GET /api/pkcs11/objects: every object the
// token's authenticated session can see, with the attributes the standard
// defines for its class — or, with ?all=1, the whole catalogue including the
// attributes the token reports as unsupported. hsm:manage gated.
//
// The mechanism lists are skipped here: GET /api/pkcs11/module already carries
// them, and repeating them per object dump would double the payload for nothing.
func (a *API) InspectPKCS11Objects(w http.ResponseWriter, r *http.Request) {
	ins, ok := a.pkcs11Inspector(w, r)
	if !ok {
		return
	}
	opts := inspectOptions(r)
	opts.SkipMechanisms = true

	views, err := ins.InspectPKCS11(r.Context(), opts)
	if err != nil {
		// Not recorded when the backend simply has no view: nothing was read,
		// and an audit log of "this deployment uses a cloud KMS" is noise.
		if !errors.Is(err, keyprovider.ErrInspectUnsupported) {
			a.recordEvent(r, audit.ActionHSMInspect, "", "", audit.ResultError, err.Error())
		}
		a.inspectFailed(w, "enumerating PKCS#11 objects", err)
		return
	}

	// One audit entry per dump, recording what was read rather than that
	// something was: the object count per token is the part an access review
	// cares about, and it is also what tells a later reader whether the token
	// gained objects between two inspections.
	a.recordEvent(r, audit.ActionHSMInspect, "", "", audit.ResultSuccess, inspectionDetail(views))

	writeJSON(w, http.StatusOK, PKCS11InspectResponse{
		Provider:      a.keyProvider.Name(),
		Tokens:        views,
		AllAttributes: opts.AllAttributes,
	})
}

// inspectionDetail summarises an inspection for the audit log: per token, the
// object count and whether enumeration failed.
func inspectionDetail(views []keyprovider.TokenView) string {
	detail := ""
	for i, v := range views {
		if i > 0 {
			detail += "; "
		}
		name := v.Token
		if name == "" && v.Objects != nil {
			name = v.Objects.TokenLabel
		}
		if name == "" {
			name = "token"
		}
		switch {
		case v.Error != "":
			detail += name + ": error: " + v.Error
		case v.Objects == nil:
			detail += name + ": no objects enumerated"
		default:
			detail += name + ": " + strconv.Itoa(len(v.Objects.Objects)) + " object(s)"
			if v.Objects.Truncated {
				detail += " (truncated)"
			}
		}
	}
	return detail
}
