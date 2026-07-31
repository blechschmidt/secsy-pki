package mswstep

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// MS-XCEP client-authentication enumeration values for a CA URI ([MS-XCEP]
// §3.1.4.1.3.6, ClientAuthentication). A CA URI advertises which mechanism the
// client must use against the companion CES service.
const (
	clientAuthAnonymous = 1
	clientAuthKerberos  = 2
	clientAuthUsername  = 4
	clientAuthCert      = 8
)

// oidGroupTemplate is the MS-XCEP OID group value for a certificate template
// ([MS-XCEP] §3.1.4.1.3.24, OIDGroup). Each advertised template contributes one
// oID entry in this group that a policy references by index.
const oidGroupTemplate = 9

// getPoliciesReqEnvelope parses just enough of the MS-XCEP GetPolicies request to
// echo its WS-Addressing MessageID in the response's RelatesTo. Matching is by
// local element name so any client namespace prefix is accepted.
type getPoliciesReqEnvelope struct {
	XMLName xml.Name
	Header  struct {
		MessageID string `xml:"MessageID"`
		Action    string `xml:"Action"`
	} `xml:"Header"`
	Body struct {
		GetPolicies struct{} `xml:"GetPolicies"`
	} `xml:"Body"`
}

// GetPoliciesResponse and its nested types marshal to the [MS-XCEP] response
// structure. The root carries the enrollmentpolicy default namespace, which every
// child inherits (matching AD CS on the wire).
type getPoliciesResponse struct {
	XMLName  xml.Name         `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy GetPoliciesResponse"`
	Response cepResponse      `xml:"response"`
	CAs      cepCACollection  `xml:"cAs"`
	OIDs     cepOIDCollection `xml:"oIDs"`
}

type cepResponse struct {
	PolicyID           string      `xml:"policyID"`
	PolicyFriendlyName string      `xml:"policyFriendlyName"`
	NextUpdateHours    int         `xml:"nextUpdateHours"`
	PoliciesNotChanged bool        `xml:"policiesNotChanged"`
	Policies           []cepPolicy `xml:"policies>policy"`
}

type cepPolicy struct {
	PolicyOIDReference int           `xml:"policyOIDReference"`
	CAs                []int         `xml:"cAs>cAReference"`
	Attributes         cepAttributes `xml:"attributes"`
}

type cepAttributes struct {
	CommonName           string        `xml:"commonName"`
	PolicySchema         int           `xml:"policySchema"`
	CertificateValidity  cepValidity   `xml:"certificateValidity"`
	Permission           cepPermission `xml:"permission"`
	PrivateKeyAttributes cepPrivateKey `xml:"privateKeyAttributes"`
	Revision             cepRevision   `xml:"revision"`
}

type cepValidity struct {
	ValidityPeriodSeconds int64 `xml:"validityPeriodSeconds"`
	RenewalPeriodSeconds  int64 `xml:"renewalPeriodSeconds"`
}

type cepPermission struct {
	Enroll     bool `xml:"enroll"`
	AutoEnroll bool `xml:"autoEnroll"`
}

type cepPrivateKey struct {
	MinimalKeyLength int `xml:"minimalKeyLength"`
}

type cepRevision struct {
	MajorRevision int `xml:"majorRevision"`
	MinorRevision int `xml:"minorRevision"`
}

type cepCACollection struct {
	CA []cepCA `xml:"cA"`
}

type cepCA struct {
	URIs             []cepCAURI `xml:"uris>cAURI"`
	Certificate      string     `xml:"certificate"`
	EnrollPermission bool       `xml:"enrollPermission"`
	CAReferenceID    int        `xml:"cAReferenceID"`
}

type cepCAURI struct {
	ClientAuthentication int    `xml:"clientAuthentication"`
	URI                  string `xml:"uri"`
	Priority             int    `xml:"priority"`
	RenewalOnly          bool   `xml:"renewalOnly"`
}

type cepOIDCollection struct {
	OID []cepOID `xml:"oID"`
}

type cepOID struct {
	Value          string `xml:"value"`
	Group          int    `xml:"group"`
	OIDReferenceID int    `xml:"oIDReferenceID"`
	DefaultName    string `xml:"defaultName"`
}

// handleGetPolicies services the MS-XCEP GetPolicies request: it authenticates
// the caller, then advertises the certificate-enrollment policy — the templates
// mapped from secsy-pki profiles, the issuing CA (with its certificate and the
// CES enrollment URL), and the template OIDs. Any authenticated principal may
// read the policy; the issuing capability is enforced only at enrollment time.
func (s *Server) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	res, ok := s.authenticate(r)
	if !ok {
		s.unauthorized(w)
		return
	}

	var req getPoliciesReqEnvelope
	if err := readEnvelope(w, r, &req); err != nil {
		metrics.RecordMSXCEPGetPolicies(metrics.MSWSTEPResultError)
		writeFault(w, http.StatusBadRequest, faultSender, err.Error(), "")
		return
	}

	resp, err := s.buildPolicies()
	if err != nil {
		metrics.RecordMSXCEPGetPolicies(metrics.MSWSTEPResultError)
		s.recordEvent(r, res.actor, audit.ActionMSXCEPGetPolicies, s.cfg.CAID, audit.ResultError, err.Error())
		writeFault(w, http.StatusInternalServerError, faultReceiver, "certificate enrollment policy unavailable", req.Header.MessageID)
		return
	}

	metrics.RecordMSXCEPGetPolicies(metrics.MSWSTEPResultSuccess)
	s.recordEvent(r, res.actor, audit.ActionMSXCEPGetPolicies, s.cfg.CAID, audit.ResultSuccess,
		"templates="+strconv.Itoa(len(resp.Response.Policies)))
	writeEnvelope(w, http.StatusOK, newEnvelope(actionGetPoliciesResponse, req.Header.MessageID, resp))
}

// buildPolicies assembles the GetPoliciesResponse from the configured templates
// and the issuing CA. Each template becomes a policy (with a certificate-template
// oID it references) that points at the single advertised CA.
func (s *Server) buildPolicies() (getPoliciesResponse, error) {
	caCert, err := s.caCert()
	if err != nil {
		return getPoliciesResponse{}, err
	}

	resp := getPoliciesResponse{
		Response: cepResponse{
			PolicyID:           s.cfg.PolicyID,
			PolicyFriendlyName: s.cfg.PolicyFriendlyName,
			NextUpdateHours:    s.cfg.NextUpdateHours,
			PoliciesNotChanged: false,
		},
	}

	for _, t := range s.templates {
		validity, renewal := s.templateValidity(t)
		resp.Response.Policies = append(resp.Response.Policies, cepPolicy{
			PolicyOIDReference: t.oidRef,
			CAs:                []int{0}, // the single advertised CA (cAReferenceID 0)
			Attributes: cepAttributes{
				CommonName:           t.name,
				PolicySchema:         t.schemaVersion,
				CertificateValidity:  cepValidity{ValidityPeriodSeconds: validity, RenewalPeriodSeconds: renewal},
				Permission:           cepPermission{Enroll: t.enroll, AutoEnroll: t.autoEnroll},
				PrivateKeyAttributes: cepPrivateKey{MinimalKeyLength: t.minKeyLength},
				Revision:             cepRevision{MajorRevision: t.majorRevision, MinorRevision: 0},
			},
		})
		resp.OIDs.OID = append(resp.OIDs.OID, cepOID{
			Value:          t.oid,
			Group:          oidGroupTemplate,
			OIDReferenceID: t.oidRef,
			DefaultName:    t.name,
		})
	}

	caEntry := cepCA{
		Certificate:      base64.StdEncoding.EncodeToString(caCert.Raw),
		EnrollPermission: true,
		CAReferenceID:    0,
	}
	if s.cfg.CESEndpoint != "" {
		caEntry.URIs = []cepCAURI{{
			ClientAuthentication: s.clientAuthValue(),
			URI:                  s.cfg.CESEndpoint,
			Priority:             1,
			RenewalOnly:          false,
		}}
	}
	resp.CAs.CA = []cepCA{caEntry}
	return resp, nil
}

// templateValidity returns the advertised (validityPeriodSeconds,
// renewalPeriodSeconds) for a template, from its mapped profile's default
// validity. The renewal window is one tenth of the lifetime (at least a day),
// mirroring the overlap AD templates advertise so a client renews before expiry.
func (s *Server) templateValidity(t resolvedTemplate) (validity, renewal int64) {
	validity = int64((365 * 24 * time.Hour).Seconds())
	if prof, err := ca.LookupProfile(t.profile); err == nil && prof.DefaultValidity > 0 {
		validity = int64(prof.DefaultValidity.Seconds())
	}
	renewal = validity / 10
	if minRenewal := int64((24 * time.Hour).Seconds()); renewal < minRenewal {
		renewal = minRenewal
	}
	return validity, renewal
}

// clientAuthValue selects the CA-URI ClientAuthentication value advertised to the
// client, based on which mechanisms this deployment accepts: certificate (mTLS)
// takes precedence, then username/password (API token), else anonymous.
func (s *Server) clientAuthValue() int {
	switch {
	case s.cfg.CertBinder != nil || s.cfg.AllowClientCertIssuedByCA:
		return clientAuthCert
	case s.cfg.Tokens != nil:
		return clientAuthUsername
	default:
		return clientAuthAnonymous
	}
}

// unauthorized writes an HTTP 401 (before any SOAP processing) for a request that
// presented no acceptable credential. CES/CEP authentication is transport-level,
// so this mirrors how a Windows client sees an auth failure.
func (s *Server) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Token realm="mswstep"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}
