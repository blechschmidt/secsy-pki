package keyprovider

// The raw PKCS#11 inspection capability (Task 218).
//
// Every other provider capability in this package is phrased in the PKI's own
// vocabulary — sign, wrap, list keys — precisely so a CA does not care whether
// a key lives on a YubiHSM, in Vault or in a file. This one is the exception:
// it is Cryptoki-shaped on purpose, because what an operator needs when the
// token surprises them is the token's own account of itself, not this project's
// summary of it.
//
// It is therefore an optional capability that only the PKCS#11-backed providers
// implement. A cloud-KMS or software deployment has no slots, no CKA_* and no
// object handles, and the honest answer there is "this provider has no PKCS#11
// view" rather than a synthesised one.

import (
	"context"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TokenView is the raw Cryptoki view of one token behind a provider: the module
// as it describes itself, the slots it presents, and the objects on the token
// this deployment resolved to.
type TokenView struct {
	// Token names the member token in a high-availability set; empty for a
	// single-token deployment. An HA set deliberately gives its replicas the
	// same key labels, so the member name is the only thing that distinguishes
	// "this object is on the primary" from "on the standby".
	Token string `json:"token,omitempty"`
	// Healthy reports whether the HA layer currently has this token in
	// rotation. Nil for a single-token deployment, which has no rotation.
	Healthy *bool `json:"healthy,omitempty"`
	// Module is the module/slot/token view (always present on success).
	Module *pki.ModuleInfo `json:"module,omitempty"`
	// Objects is the object dump, absent when only the module view was asked
	// for or when enumeration failed.
	Objects *pki.ObjectSet `json:"objects,omitempty"`
	// Error carries a per-token failure: in an HA set one unreachable replica
	// must not blank the view of the others.
	Error string `json:"error,omitempty"`
}

// PKCS11Inspector is an optional capability implemented by the PKCS#11-backed
// providers (single-token and HA): a read-only Cryptoki view of the token(s)
// behind the provider. Callers type-assert a Provider to it and report that the
// backend has no such view when the assertion fails.
//
// Both methods read only. Neither creates, modifies or destroys an object, and
// neither requests private key material — see the policy note in
// internal/pki/pkcs11attrs.go.
type PKCS11Inspector interface {
	// InspectPKCS11Module reports the module, slot, token and mechanism view
	// without enumerating objects. It needs no session.
	InspectPKCS11Module(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error)
	// InspectPKCS11 additionally enumerates the objects on each token and
	// reads their attributes.
	InspectPKCS11(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error)
}

// ErrInspectUnsupported is returned by the wrappers when the backend they wrap
// has no PKCS#11 view. It is a capability answer, not a fault: a software or
// cloud-KMS deployment is expected to produce it.
var ErrInspectUnsupported = fmt.Errorf("keyprovider: the configured backend has no PKCS#11 view")

// --- single token -----------------------------------------------------------

// InspectPKCS11Module reads the module view WITHOUT going through the session
// pool, deliberately: C_GetInfo, the slot list and the token info need no
// session and no login, and an operator reaching for the slot list is very
// often one whose login does not work — a PIN that no longer resolves, a token
// selector matching nothing, a device that moved slots. Requiring a pool first
// would make the one view that could diagnose those the one view that fails
// with them.
//
// It still takes a reference on the process-shared module context rather than
// loading its own, so when the server does hold a live pool this reuses that
// module and cannot finalize it on the way out (the Task 208 failure mode).
func (p *PKCS11Provider) InspectPKCS11Module(_ context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	mod, err := pki.InspectModule(p.cfg, opts)
	if err != nil {
		return nil, err
	}
	return []TokenView{{Module: mod}}, nil
}

// InspectPKCS11 reads the module view and enumerates the token's objects on a
// borrowed pool session — already logged in, so private objects are visible.
func (p *PKCS11Provider) InspectPKCS11(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	insp, err := pool.Inspect(ctx, opts)
	if err != nil {
		return nil, err
	}
	return []TokenView{{Module: insp.Module, Objects: insp.Objects}}, nil
}

// --- HA set -----------------------------------------------------------------

// InspectPKCS11Module reports one view per member token.
func (p *PKCS11HAProvider) InspectPKCS11Module(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	return p.inspectMembers(ctx, opts, false)
}

// InspectPKCS11 reports one view per member token, each with its objects.
func (p *PKCS11HAProvider) InspectPKCS11(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	return p.inspectMembers(ctx, opts, true)
}

// inspectMembers inspects every member in configured order — not routing order.
// Inspection is the one operation that must NOT fail over: the question is
// "what is on this token", and answering it from a different token would be the
// wrong answer rather than a resilient one. A member that cannot be reached
// contributes a view carrying its error, so a degraded set still shows the rest
// (and shows which replica is the one that is unreachable).
func (p *PKCS11HAProvider) inspectMembers(ctx context.Context, opts pki.InspectOptions, withObjects bool) ([]TokenView, error) {
	views := make([]TokenView, 0, len(p.members))
	for _, m := range p.members {
		healthy := m.isHealthy()
		v := TokenView{Token: m.name, Healthy: &healthy}
		var (
			out []TokenView
			err error
		)
		if withObjects {
			out, err = m.provider.InspectPKCS11(ctx, opts)
		} else {
			out, err = m.provider.InspectPKCS11Module(ctx, opts)
		}
		switch {
		case err != nil:
			v.Error = err.Error()
		case len(out) == 1:
			v.Module = out[0].Module
			v.Objects = out[0].Objects
		}
		views = append(views, v)
	}
	return views, nil
}

// --- wrapper forwarding -----------------------------------------------------
//
// The instrumented and recording wrappers embed Provider, which does not
// surface optional capabilities, so each must forward this one explicitly or
// wrapping would silently remove the inspector from a running server (every
// deployment wraps at least once).

func (p *instrumentedProvider) InspectPKCS11Module(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	ins, ok := p.Provider.(PKCS11Inspector)
	if !ok {
		return nil, ErrInspectUnsupported
	}
	return ins.InspectPKCS11Module(ctx, opts)
}

func (p *instrumentedProvider) InspectPKCS11(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	ins, ok := p.Provider.(PKCS11Inspector)
	if !ok {
		return nil, ErrInspectUnsupported
	}
	return ins.InspectPKCS11(ctx, opts)
}

func (p *recordingProvider) InspectPKCS11Module(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	ins, ok := p.Provider.(PKCS11Inspector)
	if !ok {
		return nil, ErrInspectUnsupported
	}
	return ins.InspectPKCS11Module(ctx, opts)
}

// InspectPKCS11 forwards the object dump and then marks the device as operated.
//
// Enumerating objects and reading their attributes are commands the device
// executes — C_FindObjects is YubiHSM's own 0x48 ListObjects, and each
// attribute read is a GetObjectInfo — so on a force-audited device they consume
// entries in its 62-entry log just as a signature does. A full log is a device
// that refuses to sign, so an inspection has to prompt the same drain every
// other operation does rather than quietly filling the ring.
func (p *recordingProvider) InspectPKCS11(ctx context.Context, opts pki.InspectOptions) ([]TokenView, error) {
	ins, ok := p.Provider.(PKCS11Inspector)
	if !ok {
		return nil, ErrInspectUnsupported
	}
	defer p.operated()
	return ins.InspectPKCS11(ctx, opts)
}

var (
	_ PKCS11Inspector = (*PKCS11Provider)(nil)
	_ PKCS11Inspector = (*PKCS11HAProvider)(nil)
	_ PKCS11Inspector = (*instrumentedProvider)(nil)
	_ PKCS11Inspector = (*recordingProvider)(nil)
)
