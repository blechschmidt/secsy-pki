package mswstep

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Microsoft certificate-template extension OIDs carried in an enrollment CSR. A
// Windows client stamps the requested template into the PKCS#10 so the server can
// map it back to a policy/profile:
//   - V2 (1.3.6.1.4.1.311.21.7): a SEQUENCE whose first element is the template OID.
//   - V1 (1.3.6.1.4.1.311.20.2): the template common name as a BMPString.
var (
	oidTemplateV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}
	oidTemplateV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
)

// contextItemTemplate is the AdditionalContext ContextItem name a client may use
// to select a template in the RST itself (an alternative to the CSR extension).
const contextItemTemplate = "CertificateTemplate"

// rstReqEnvelope parses an MS-WSTEP RequestSecurityToken (Issue) request. Element
// matching is by local name so any client namespace prefix is accepted.
type rstReqEnvelope struct {
	XMLName xml.Name
	Header  struct {
		MessageID string `xml:"MessageID"`
		Action    string `xml:"Action"`
	} `xml:"Header"`
	Body struct {
		RST rstRequest `xml:"RequestSecurityToken"`
	} `xml:"Body"`
}

type rstRequest struct {
	TokenType   string           `xml:"TokenType"`
	RequestType string           `xml:"RequestType"`
	Token       reqBinaryToken   `xml:"BinarySecurityToken"`
	Context     []rstContextItem `xml:"AdditionalContext>ContextItem"`
}

type reqBinaryToken struct {
	ValueType    string `xml:"ValueType,attr"`
	EncodingType string `xml:"EncodingType,attr"`
	Value        string `xml:",chardata"`
}

type rstContextItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value"`
}

// RequestSecurityTokenResponseCollection and its nested types marshal to the
// [MS-WSTEP] RSTRC. The WS-Trust elements carry the ws-trust default namespace
// (inherited by their children); the Microsoft disposition/request-id and the WSS
// binary-security-token declare their own namespaces per subtree.
type rstrCollection struct {
	XMLName  xml.Name     `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponseCollection"`
	Response rstrResponse `xml:"RequestSecurityTokenResponse"`
}

type rstrResponse struct {
	TokenType string `xml:"TokenType"`
	// DispositionMessage and RequestID carry their own namespaced XMLName, so they
	// need no field tag here.
	DispositionMessage     dispositionMessage
	RequestedSecurityToken requestedSecurityToken `xml:"RequestedSecurityToken"`
	RequestID              requestID
}

type dispositionMessage struct {
	XMLName xml.Name `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollment DispositionMessage"`
	Lang    string   `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value   string   `xml:",chardata"`
}

type requestedSecurityToken struct {
	Token respBinaryToken
}

type respBinaryToken struct {
	XMLName      xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd BinarySecurityToken"`
	ValueType    string   `xml:"ValueType,attr"`
	EncodingType string   `xml:"EncodingType,attr"`
	Value        string   `xml:",chardata"`
}

type requestID struct {
	XMLName xml.Name `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollment RequestID"`
	Value   string   `xml:",chardata"`
}

// handleRequestSecurityToken services the MS-WSTEP RequestSecurityToken (Issue)
// request: it authenticates and authorizes the caller, extracts the PKCS#10 from
// the BinarySecurityToken, resolves the requested template to a profile, issues
// the certificate through the shared HSM-backed ca.Manager, and returns it as a
// certs-only PKCS#7 in a RequestSecurityTokenResponse.
func (s *Server) handleRequestSecurityToken(w http.ResponseWriter, r *http.Request) {
	res, ok := s.authenticate(r)
	if !ok {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultDenied)
		s.unauthorized(w)
		return
	}
	if !s.authorizeIssue(res) {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultDenied)
		s.recordEvent(r, res.actor, audit.ActionMSWSTEPEnroll, "", audit.ResultDenied,
			"caller lacks the cert:issue capability on the issuing CA's tenant")
		http.Error(w, "not authorized to enroll on this CA", http.StatusForbidden)
		return
	}

	var req rstReqEnvelope
	if err := readEnvelope(w, r, &req); err != nil {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultError)
		writeFault(w, http.StatusBadRequest, faultSender, err.Error(), "")
		return
	}
	msgID := req.Header.MessageID

	if rt := strings.TrimSpace(req.Body.RST.RequestType); rt != "" && rt != requestTypeIssue {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultError)
		writeFault(w, http.StatusBadRequest, faultSender, "unsupported RequestType (only Issue is supported)", msgID)
		return
	}

	csr, err := s.parseCSR(req.Body.RST.Token.Value)
	if err != nil {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultError)
		writeFault(w, http.StatusBadRequest, faultSender, "invalid PKCS#10 request: "+err.Error(), msgID)
		return
	}

	// Resolve the requested template (RST context first, then the CSR's Microsoft
	// template extensions) to an issuance profile.
	selector := templateSelector(req.Body.RST.Context, csr)
	tmpl := s.resolveTemplate(selector)
	profile := tmpl.profile

	result, err := s.issue(r.Context(), csr, profile, res.actor)
	if err != nil {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultError)
		s.recordEvent(r, res.actor, audit.ActionMSWSTEPEnroll, csr.Subject.CommonName, audit.ResultError, err.Error())
		s.writeIssuanceFault(w, err, msgID)
		log.Printf("mswstep: issuance failed: %v", err)
		return
	}

	rstrc, err := s.buildRSTRC(result.Certificate, result.Serial.String())
	if err != nil {
		metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultError)
		writeFault(w, http.StatusInternalServerError, faultReceiver, "encoding issued certificate", msgID)
		log.Printf("mswstep: encoding response: %v", err)
		return
	}

	metrics.RecordMSWSTEPRequest(metrics.MSWSTEPResultSuccess)
	s.recordEvent(r, res.actor, audit.ActionMSWSTEPEnroll, result.Certificate.Subject.CommonName, audit.ResultSuccess,
		"serial="+result.Serial.String()+" profile="+profile+" template="+tmpl.name)
	writeEnvelope(w, http.StatusOK, newEnvelope(actionRSTRC, msgID, rstrc))
}

// parseCSR base64-decodes the BinarySecurityToken value and parses/validates the
// PKCS#10.
func (s *Server) parseCSR(value string) (*x509.CertificateRequest, error) {
	der, err := decodeBase64(value)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	return csr, nil
}

// buildRSTRC assembles the RequestSecurityTokenResponseCollection with the issued
// certificate (and its CA chain) as a base64 certs-only PKCS#7.
func (s *Server) buildRSTRC(leaf *x509.Certificate, reqID string) (rstrCollection, error) {
	chain, err := s.caChain()
	if err != nil {
		return rstrCollection{}, err
	}
	certs := append([]*x509.Certificate{leaf}, chain...)
	p7, err := cms.DegenerateCertsOnly(certs)
	if err != nil {
		return rstrCollection{}, err
	}
	b64 := base64.StdEncoding.EncodeToString(p7)
	return rstrCollection{
		Response: rstrResponse{
			TokenType:          valueTypePKCS7,
			DispositionMessage: dispositionMessage{Lang: "en-US", Value: "Issued"},
			RequestedSecurityToken: requestedSecurityToken{
				Token: respBinaryToken{ValueType: valueTypePKCS7, EncodingType: encodingBase64, Value: b64},
			},
			RequestID: requestID{Value: reqID},
		},
	}, nil
}

// writeIssuanceFault maps an issuance failure to a SOAP fault with the enrollment
// protocol's HTTP semantics: a suspended tenant is 403, tenant quota exhaustion is
// 429 with a Retry-After, anything else is an opaque 500.
func (s *Server) writeIssuanceFault(w http.ResponseWriter, err error, msgID string) {
	var susp *models.TenantSuspendedError
	if errors.As(err, &susp) {
		writeFault(w, http.StatusForbidden, faultSender, "tenant is suspended; enrollment is disabled", msgID)
		return
	}
	var quota *models.QuotaExceededError
	if errors.As(err, &quota) {
		if quota.RetryAfter > 0 {
			secs := int(math.Ceil(quota.RetryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		writeFault(w, http.StatusTooManyRequests, faultReceiver, "tenant issuance quota exceeded", msgID)
		return
	}
	writeFault(w, http.StatusInternalServerError, faultReceiver, "issuance failed", msgID)
}

// --- template selection ----------------------------------------------------

// templateSelector determines the requested template identifier, preferring an
// explicit RST AdditionalContext ContextItem, then the CSR's Microsoft V2
// (template OID) extension, then the V1 (template name) extension. It returns ""
// when the request names no template (the caller falls back to the default).
func templateSelector(context []rstContextItem, csr *x509.CertificateRequest) string {
	for _, item := range context {
		if strings.EqualFold(item.Name, contextItemTemplate) {
			if v := strings.TrimSpace(item.Value); v != "" {
				return v
			}
		}
	}
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidTemplateV2):
			if oid := templateOIDFromV2(ext.Value); oid != "" {
				return oid
			}
		case ext.Id.Equal(oidTemplateV1):
			if name := templateNameFromV1(ext.Value); name != "" {
				return name
			}
		}
	}
	return ""
}

// templateOIDFromV2 extracts the template OID from a V2 certificate-template
// extension value (a SEQUENCE whose first element is the OID).
func templateOIDFromV2(der []byte) string {
	var v struct {
		TemplateID   asn1.ObjectIdentifier
		MajorVersion int `asn1:"optional"`
		MinorVersion int `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return ""
	}
	return v.TemplateID.String()
}

// templateNameFromV1 extracts the template common name from a V1 template-name
// extension value. Windows encodes it as a BMPString; UTF8/IA5/Printable strings
// are also decoded for robustness against non-Windows clients.
func templateNameFromV1(der []byte) string {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return ""
	}
	const tagBMPString = 30
	if raw.Tag == tagBMPString {
		return decodeBMPString(raw.Bytes)
	}
	return strings.TrimSpace(string(raw.Bytes))
}

// decodeBMPString decodes a BMPString (UTF-16 big-endian) payload to a Go string.
func decodeBMPString(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return strings.TrimSpace(string(utf16.Decode(u16)))
}

// decodeBase64 decodes a base64 string, tolerating embedded whitespace/newlines
// (some SOAP clients wrap the token) and both padded and unpadded encodings.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
