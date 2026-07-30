// Package acme implements an RFC 8555 (ACME) certificate-issuance server on top
// of the HSM-backed CA/issuance layer. Clients (certbot, lego, acme.sh, …)
// register an account with a JWS-signed request, place an order for one or more
// identifiers, satisfy an http-01 or dns-01 challenge per identifier, finalize
// the order with a CSR, and download the issued certificate chain.
//
// Every leaf certificate is signed through the same ca.Manager used by the rest
// of the system, so ACME-issued certificates are HSM-backed and recorded for
// revocation/renewal exactly like certificates issued through the REST API.
package acme

import (
	"encoding/json"
	"net/http"
	"time"
)

// The ACME problem-type URN namespace (RFC 8555 §6.7).
const (
	probMalformed          = "urn:ietf:params:acme:error:malformed"
	probUnauthorized       = "urn:ietf:params:acme:error:unauthorized"
	probAccountDoesntExist = "urn:ietf:params:acme:error:accountDoesNotExist"
	probBadNonce           = "urn:ietf:params:acme:error:badNonce"
	probBadSignature       = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	probBadPublicKey       = "urn:ietf:params:acme:error:badPublicKey"
	probUnsupportedID      = "urn:ietf:params:acme:error:unsupportedIdentifier"
	probRejectedID         = "urn:ietf:params:acme:error:rejectedIdentifier"
	probServerInternal     = "urn:ietf:params:acme:error:serverInternal"
	probRateLimited        = "urn:ietf:params:acme:error:rateLimited"
	probConnection         = "urn:ietf:params:acme:error:connection"
	probTLS                = "urn:ietf:params:acme:error:tls"
	probDNS                = "urn:ietf:params:acme:error:dns"
	probIncorrectResponse  = "urn:ietf:params:acme:error:incorrectResponse"
	probOrderNotReady      = "urn:ietf:params:acme:error:orderNotReady"
	probBadCSR             = "urn:ietf:params:acme:error:badCSR"
	probExternalBinding    = "urn:ietf:params:acme:error:externalAccountRequired"
	probUserActionReq      = "urn:ietf:params:acme:error:userActionRequired"
	probAlreadyRevoked     = "urn:ietf:params:acme:error:alreadyRevoked"
	// probAlreadyReplaced signals that the certificate named in a newOrder
	// "replaces" field has already been replaced by another order (ARI §5).
	probAlreadyReplaced = "urn:ietf:params:acme:error:alreadyReplaced"
	// probBadAttestation signals that a device-attest-01 attestation object was
	// missing, malformed, or failed verification (draft-ietf-acme-device-attest).
	probBadAttestation = "urn:ietf:params:acme:error:badAttestationStatement"
	// probInvalidProfile signals that a newOrder "profile" field named a profile
	// the server does not offer (RFC 9773 — the ACME Profiles extension). The
	// available profiles are advertised in the directory's meta.profiles.
	probInvalidProfile = "urn:ietf:params:acme:error:invalidProfile"
	// probAutoRenewalCanceled signals that the STAR certificate of a canceled
	// RFC 8739 recurrence was requested (§3.5): the star-certificate URL answers
	// 403 with this type once the order has been canceled.
	probAutoRenewalCanceled = "urn:ietf:params:acme:error:autoRenewalCanceled"
	// probInvalidContact / probUnsupportedContact reject a newAccount or
	// account-update "contact" entry (RFC 8555 §7.3): unsupportedContact when the
	// URL uses a scheme the server does not support (anything but "mailto:"), and
	// invalidContact when a supported "mailto:" contact carries an invalid value —
	// a malformed address, more than one address, or header fields ("hfields").
	probInvalidContact     = "urn:ietf:params:acme:error:invalidContact"
	probUnsupportedContact = "urn:ietf:params:acme:error:unsupportedContact"
)

// Problem is an RFC 7807 / RFC 8555 problem document.
type Problem struct {
	Type        string       `json:"type"`
	Detail      string       `json:"detail,omitempty"`
	Status      int          `json:"status,omitempty"`
	Subproblems []Subproblem `json:"subproblems,omitempty"`
}

// Subproblem attaches an identifier-scoped error to a problem document.
type Subproblem struct {
	Type       string          `json:"type"`
	Detail     string          `json:"detail,omitempty"`
	Identifier *wireIdentifier `json:"identifier,omitempty"`
}

// Error implements error so problems can flow through normal Go error handling.
func (p *Problem) Error() string {
	if p.Detail != "" {
		return p.Type + ": " + p.Detail
	}
	return p.Type
}

// newProblem builds a problem document with an HTTP status.
func newProblem(typ string, status int, detail string) *Problem {
	return &Problem{Type: typ, Status: status, Detail: detail}
}

// httpStatus returns the problem's HTTP status, defaulting to 400.
func (p *Problem) httpStatus() int {
	if p.Status != 0 {
		return p.Status
	}
	return http.StatusBadRequest
}

// wireIdentifier is the RFC 8555 identifier JSON object.
type wireIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// wireDirectory is the response for the newNonce-anchoring directory resource.
type wireDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	// NewAuthz advertises the optional pre-authorization resource (RFC 8555
	// §7.4.1). Present only when pre-authorization is enabled, so a server without
	// it stays byte-for-byte compatible with the pre-extension directory.
	NewAuthz   string `json:"newAuthz,omitempty"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	// RenewalInfo advertises the ACME Renewal Information (ARI) resource
	// (draft-ietf-acme-ari §4.1). Clients GET "<renewalInfo>/<certID>" to learn a
	// suggested renewal window for a certificate.
	RenewalInfo string        `json:"renewalInfo,omitempty"`
	Meta        directoryMeta `json:"meta"`
}

type directoryMeta struct {
	TermsOfService          string `json:"termsOfService,omitempty"`
	ExternalAccountRequired bool   `json:"externalAccountRequired,omitempty"`
	// Profiles advertises the client-selectable issuance profiles (RFC 9773, the
	// ACME Profiles extension): a map of ACME-visible profile name to a
	// human-readable description. Omitted when no profiles are configured, keeping
	// the directory byte-for-byte compatible with the pre-extension server.
	Profiles map[string]string `json:"profiles,omitempty"`
	// AutoRenewal advertises RFC 8739 STAR (short-term auto-renewed certificate)
	// support (Task 136): the server-configured lifetime/duration bounds a client's
	// newOrder "auto-renewal" object is validated against. Omitted when STAR is
	// disabled, so the directory stays compatible with the pre-extension server.
	AutoRenewal *metaAutoRenewal `json:"auto-renewal,omitempty"`
}

// metaAutoRenewal is the directory meta.auto-renewal object advertising the
// server's RFC 8739 STAR bounds (§3.1). Durations are in seconds.
type metaAutoRenewal struct {
	// MinLifetime is the smallest per-certificate lifetime the server will accept
	// in a newOrder "auto-renewal.lifetime".
	MinLifetime int64 `json:"min-lifetime"`
	// MaxDuration is the longest total recurrence (end-date − start-date) the
	// server will accept.
	MaxDuration int64 `json:"max-duration"`
	// AllowCertificateGet advertises that the server honors a per-order
	// "allow-certificate-get" request, serving the star-certificate to an
	// unauthenticated GET (RFC 8739 §3.4).
	AllowCertificateGet bool `json:"allow-certificate-get,omitempty"`
}

// wireAccount is the account object returned to clients (RFC 8555 §7.1.2).
type wireAccount struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

// newAccountRequest is the payload of a newAccount POST.
type newAccountRequest struct {
	Contact                []string        `json:"contact"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

// accountUpdateRequest is the payload of a POST to an account URL.
type accountUpdateRequest struct {
	Contact []string `json:"contact,omitempty"`
	Status  string   `json:"status,omitempty"`
}

// newOrderRequest is the payload of a newOrder POST.
type newOrderRequest struct {
	Identifiers []wireIdentifier `json:"identifiers"`
	NotBefore   string           `json:"notBefore,omitempty"`
	NotAfter    string           `json:"notAfter,omitempty"`
	// Replaces, when set, is the ARI CertID (draft-ietf-acme-ari §5) of the
	// certificate this order renews, linking the renewal to its predecessor.
	Replaces string `json:"replaces,omitempty"`
	// Profile, when set, selects one of the server's advertised issuance profiles
	// (RFC 9773, the ACME Profiles extension). It must be one of the ACME-visible
	// names in the directory's meta.profiles; an unknown value is rejected with an
	// invalidProfile problem. Omitted means the server's default profile.
	Profile string `json:"profile,omitempty"`
	// AutoRenewal, when set, requests an RFC 8739 STAR (short-term auto-renewed)
	// order (Task 136): the server issues short-lived certificates and re-issues
	// them ahead of expiry until "end-date". Honored only when the server
	// advertises meta.auto-renewal; ignored otherwise (a normal order results).
	AutoRenewal *autoRenewalRequest `json:"auto-renewal,omitempty"`
}

// autoRenewalRequest is the newOrder "auto-renewal" object a client sends to
// request a STAR recurrence (RFC 8739 §3.1.1). Dates are RFC 3339 strings and
// "lifetime" is in seconds.
type autoRenewalRequest struct {
	// StartDate is the requested earliest validity of the first certificate.
	// Optional; the server defaults it to the order creation time.
	StartDate string `json:"start-date,omitempty"`
	// EndDate is the horizon past which the client wants no further certificates.
	// Required.
	EndDate string `json:"end-date,omitempty"`
	// Lifetime is the requested validity of each short-lived certificate, in
	// seconds. Required; validated against the server's min/max lifetime.
	Lifetime int64 `json:"lifetime,omitempty"`
	// AllowCertificateGet, when true, requests that the star-certificate be
	// retrievable with an unauthenticated GET (RFC 8739 §3.4), not just an
	// authenticated POST-as-GET.
	AllowCertificateGet bool `json:"allow-certificate-get,omitempty"`
}

// orderUpdateRequest is the payload of a POST to an order URL that mutates it.
// The only supported mutation is canceling a STAR recurrence (RFC 8739 §3.5) by
// setting status="canceled"; an empty payload is a POST-as-GET.
type orderUpdateRequest struct {
	Status string `json:"status,omitempty"`
}

// authzUpdateRequest is the payload of a POST to an authorization URL that
// mutates it. RFC 8555 §7.5.2 defines exactly one mutation: the client
// relinquishing the authorization by setting status="deactivated". An empty
// payload is a POST-as-GET fetch.
type authzUpdateRequest struct {
	Status string `json:"status,omitempty"`
}

// newAuthzRequest is the payload of a pre-authorization (newAuthz) POST
// (RFC 8555 §7.4.1): a single identifier object the client wishes to
// pre-authorize independently of an order.
type newAuthzRequest struct {
	Identifier wireIdentifier `json:"identifier"`
}

// wireRenewalInfo is the ACME Renewal Information response body
// (draft-ietf-acme-ari §4.2).
type wireRenewalInfo struct {
	SuggestedWindow suggestedWindow `json:"suggestedWindow"`
	ExplanationURL  string          `json:"explanationURL,omitempty"`
}

// suggestedWindow is the [start, end) interval within which the client should
// pick a renewal time (draft-ietf-acme-ari §4.2).
type suggestedWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// wireOrder is the order object returned to clients (RFC 8555 §7.1.3).
type wireOrder struct {
	Status         string           `json:"status"`
	Expires        string           `json:"expires,omitempty"`
	Identifiers    []wireIdentifier `json:"identifiers"`
	NotBefore      string           `json:"notBefore,omitempty"`
	NotAfter       string           `json:"notAfter,omitempty"`
	Error          *Problem         `json:"error,omitempty"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
	// AutoRenewal echoes the resolved RFC 8739 STAR recurrence (Task 136) for a
	// STAR order, reflecting the parameters actually in effect (which may have been
	// clamped to the server's bounds). Present only on STAR orders.
	AutoRenewal *wireAutoRenewal `json:"auto-renewal,omitempty"`
	// StarCertificate is the stable URL that always returns the current short-lived
	// STAR certificate (RFC 8739 §3.4). It replaces "certificate" on a STAR order.
	StarCertificate string `json:"star-certificate,omitempty"`
}

// wireAutoRenewal is the resolved "auto-renewal" object echoed on a STAR order.
type wireAutoRenewal struct {
	StartDate           string `json:"start-date"`
	EndDate             string `json:"end-date"`
	Lifetime            int64  `json:"lifetime"`
	AllowCertificateGet bool   `json:"allow-certificate-get,omitempty"`
}

// wireAuthorization is the authorization object (RFC 8555 §7.1.4).
type wireAuthorization struct {
	Identifier wireIdentifier  `json:"identifier"`
	Status     string          `json:"status"`
	Expires    string          `json:"expires,omitempty"`
	Challenges []wireChallenge `json:"challenges"`
	Wildcard   bool            `json:"wildcard,omitempty"`
}

// wireChallenge is the challenge object (RFC 8555 §7.1.5 / §8).
type wireChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	// Token is the challenge token. For email-reply-00 (RFC 8823) it is
	// token-part-2; the client concatenates it with token-part-1 (delivered in
	// the challenge email's Subject) to form the full ACME token.
	Token string `json:"token"`
	// From is the sender address the email-reply-00 challenge email will come
	// from (RFC 8823 §5); the client validates the challenge email's origin
	// against it. Present only for email-reply-00 challenges.
	From      string   `json:"from,omitempty"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

// finalizeRequest is the payload of a finalize POST.
type finalizeRequest struct {
	CSR string `json:"csr"` // base64url DER
}

// revokeRequest is the payload of a revoke-cert POST.
type revokeRequest struct {
	Certificate string `json:"certificate"` // base64url DER
	Reason      *int   `json:"reason,omitempty"`
}

// keyChangeInner is the inner JWS payload of a key-change request.
type keyChangeInner struct {
	Account string          `json:"account"`
	OldKey  json.RawMessage `json:"oldKey"`
}

// rfc3339 formats a time for ACME JSON, or "" for the zero value.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// rfc3339p formats a *time.Time, or "" if nil.
func rfc3339p(t *time.Time) string {
	if t == nil {
		return ""
	}
	return rfc3339(*t)
}
