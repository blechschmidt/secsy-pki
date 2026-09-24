package handlers

// REST surface for SPIFFE JWT-SVID validation — the counterpart of
// `secsy-ca svid jwt-verify` (Task 198).
// POST /api/ca/{id}/svid/jwt/verify.
//
// POST /api/ca/{id}/svid/jwt (svid.go) mints a JWT-SVID; nothing could check one.
// A relying party that rejects a token has no way to learn *why* — expired, wrong
// audience, signed by a key outside the trust bundle, or a trust domain this
// deployment does not accept all look identical from the outside — and that
// question is the single most common SPIFFE support call. This endpoint answers it
// authoritatively, against the same JWKS trust bundle the minting call returns.
//
// It is pure public-key math: the bundle is assembled from the CA's stored
// certificates and the signature is checked in process, so it keeps working
// through an HSM outage — deliberately, because "can this token still be
// verified?" is exactly what an operator asks while the HSM is down. No key
// provider is opened on this path and no private material is read.

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

// VerifyJWTSVIDRequest is the body of POST /api/ca/{id}/svid/jwt/verify.
type VerifyJWTSVIDRequest struct {
	// Token is the compact JWT-SVID to validate. Required.
	Token string `json:"token"`
	// Audience is the relying party's own identity, which must appear in the
	// token's "aud" set. Required, mirroring the CLI's mandatory -audience: the
	// SPIFFE JWT-SVID spec requires a validator to reject a token not addressed to
	// it, and defaulting this would quietly turn that rule off.
	Audience string `json:"audience"`
	// TrustDomains optionally narrows the trust domains the token's subject may
	// belong to (the CLI's repeatable -trust-domain). Empty uses the deployment's
	// configured allowlist. It can only narrow: the server's own SVID policy is
	// applied regardless, so a request cannot widen what this deployment accepts.
	TrustDomains []string `json:"trust_domains,omitempty"`
}

// VerifyJWTSVIDResponse reports the verdict. On success it carries the validated
// claims — never any key material beyond the public "kid" the token itself
// advertises.
type VerifyJWTSVIDResponse struct {
	// Valid is the verdict. False is accompanied by Reason and HTTP 409.
	Valid bool `json:"valid"`
	// Reason is the failure cause when Valid is false (e.g. an expired token, an
	// absent audience, or a signature from a key outside the trust bundle).
	Reason string `json:"reason,omitempty"`
	// SpiffeID is the validated subject, and TrustDomain/Path its two halves.
	SpiffeID    string `json:"spiffe_id,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
	Path        string `json:"path,omitempty"`
	// Audience is the token's full aud set (the requested audience is one member).
	Audience []string `json:"audience,omitempty"`
	// KeyID is the "kid" header the signature was verified under, and Algorithm the
	// JWS "alg" (e.g. ES256). Both are public token metadata.
	KeyID     string `json:"key_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	// IssuedAt / ExpiresAt are the RFC 3339 iat/exp claims; iat is omitted when the
	// token carries none.
	IssuedAt  string `json:"issued_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// VerifyJWTSVID handles POST /api/ca/{id}/svid/jwt/verify — the REST form of
// `secsy-ca svid jwt-verify`.
//
// Authorization is the per-CA READ gate (authorizeCARead: an assigned role plus
// membership in the CA's tenant, or a resource grant on the CA), not the issue
// gate the minting handler uses. Validating a token mints nothing and touches no
// key; it reads the CA's public trust anchors — the same material
// GET /api/ca/{id}/svid/bundle serves anonymously — so holding it at issuer level
// would only stop auditors from diagnosing the tokens they are auditing. A
// non-member gets 404, matching every other per-CA read.
func (a *API) VerifyJWTSVID(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	caRec, ok := a.authorizeCARead(w, r, caID)
	if !ok {
		return
	}

	var req VerifyJWTSVIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if req.Audience == "" {
		writeError(w, http.StatusBadRequest, "audience is required (a JWT-SVID must be addressed to its validator)")
		return
	}

	// The CA's JWKS trust bundle: its X.509 authorities re-published as jwt-svid
	// verification keys, exactly as the minting response and the public bundle
	// endpoint emit them. Reading the stored chain needs no signing key.
	mgr := ca.NewManager(a.db, a.keyProvider)
	authorities, err := mgr.TrustBundleAuthorities(caRec.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "building the trust bundle: %v", err)
		return
	}
	bundle, err := spiffe.BuildBundle(authorities, a.spiffePolicy.RefreshHint(), 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding the trust bundle: %v", err)
		return
	}

	// The effective trust-domain allowlist: the request's, else the deployment's
	// configured one (the CLI's -trust-domain / spiffe.trust_domains default).
	trustDomains := req.TrustDomains
	if len(trustDomains) == 0 {
		trustDomains = a.spiffePolicy.AllowedTrustDomains()
	}

	res, err := spiffe.ValidateJWTSVID(req.Token, bundle, spiffe.JWTValidationOptions{
		Audience:     req.Audience,
		TrustDomains: trustDomains,
	})
	if err != nil {
		// A rejected token is a verdict, not a server or request fault: 409, the
		// same status POST /api/ers/verify uses for "this evidence does not hold".
		writeJSON(w, http.StatusConflict, VerifyJWTSVIDResponse{Valid: false, Reason: err.Error()})
		return
	}

	// Fail-closed backstop on top of the allowlist above: the deployment's own
	// SVID policy must also permit the token's trust domain. Without it a
	// deployment whose allowlist lives entirely in per-subject grants (so the
	// global list is empty) would accept every syntactically valid trust domain
	// here, while refusing to issue into any of them — and a request-supplied
	// trust_domains could only ever narrow, never widen.
	if !a.spiffePolicy.Allowed(requesterIdentities(user), res.TrustDomain) {
		writeJSON(w, http.StatusConflict, VerifyJWTSVIDResponse{
			Valid:  false,
			Reason: "JWT-SVID trust domain \"" + res.TrustDomain + "\" is not permitted for this requester",
		})
		return
	}

	resp := VerifyJWTSVIDResponse{
		Valid:       true,
		SpiffeID:    res.SPIFFEID,
		TrustDomain: res.TrustDomain,
		Path:        res.Path,
		Audience:    res.Audience,
		KeyID:       res.KeyID,
		Algorithm:   res.Algorithm,
	}
	if !res.IssuedAt.IsZero() {
		resp.IssuedAt = res.IssuedAt.UTC().Format(time.RFC3339)
	}
	if !res.Expiry.IsZero() {
		resp.ExpiresAt = res.Expiry.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}
