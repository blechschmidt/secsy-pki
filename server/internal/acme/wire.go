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
	probConnection         = "urn:ietf:params:acme:error:connection"
	probDNS                = "urn:ietf:params:acme:error:dns"
	probIncorrectResponse  = "urn:ietf:params:acme:error:incorrectResponse"
	probOrderNotReady      = "urn:ietf:params:acme:error:orderNotReady"
	probBadCSR             = "urn:ietf:params:acme:error:badCSR"
	probExternalBinding    = "urn:ietf:params:acme:error:externalAccountRequired"
	probUserActionReq      = "urn:ietf:params:acme:error:userActionRequired"
	probAlreadyRevoked     = "urn:ietf:params:acme:error:alreadyRevoked"
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
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       directoryMeta `json:"meta"`
}

type directoryMeta struct {
	TermsOfService          string `json:"termsOfService,omitempty"`
	ExternalAccountRequired bool   `json:"externalAccountRequired,omitempty"`
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
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
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
