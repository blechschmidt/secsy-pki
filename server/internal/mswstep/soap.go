package mswstep

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
)

// SOAP, WS-Addressing, WS-Trust, WS-Security and Microsoft-enrollment namespace
// URIs and the message-action / value-type constants used by MS-XCEP and
// MS-WSTEP. They are quoted verbatim from the OASIS and Microsoft Open
// Specifications so a genuine Windows autoenrollment client interoperates.
const (
	nsSOAP12       = "http://www.w3.org/2003/05/soap-envelope"
	nsWSA          = "http://www.w3.org/2005/08/addressing"
	nsWSSE         = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	nsWSTrust      = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	nsEnroll       = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
	nsEnrollPolicy = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"

	// WS-Addressing Action header values ([MS-WSTEP] §3.1.4.1 / [MS-XCEP] §3.1.4.1).
	actionRST                 = nsEnroll + "/RST/wstep"
	actionRSTRC               = nsEnroll + "/RSTRC/wstep"
	actionGetPolicies         = nsEnrollPolicy + "/IPolicy/GetPolicies"
	actionGetPoliciesResponse = nsEnrollPolicy + "/IPolicy/GetPoliciesResponse"
	actionSOAPFault           = nsWSA + "/soap/fault"

	// WS-Trust request type for issuance and the token/value/encoding types used
	// on the wire. A PKCS#10 request carries the Microsoft-defined value type; the
	// issued certificate is returned as a certs-only PKCS#7 (WSS X.509 profile).
	requestTypeIssue = nsWSTrust + "/Issue"
	valueTypePKCS10  = nsEnroll + "#PKCS10"
	valueTypePKCS7   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7"
	encodingBase64   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#base64binary"

	// contentTypeSOAP is the SOAP 1.2 media type Windows uses for both services.
	contentTypeSOAP = "application/soap+xml; charset=utf-8"
)

// maxSOAPBytes bounds a SOAP request body to guard against memory exhaustion.
// A PKCS#10 plus SOAP framing is small; this is a generous safety cap.
const maxSOAPBytes = 512 * 1024

// readEnvelope reads and unmarshals a SOAP request body into v, which must be a
// pointer to a struct describing the envelope. It caps the body size and returns
// a descriptive error on malformed XML.
func readEnvelope(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSOAPBytes))
	if err != nil {
		return fmt.Errorf("reading request body: %w", err)
	}
	if err := xml.Unmarshal(body, v); err != nil {
		return fmt.Errorf("invalid SOAP envelope: %w", err)
	}
	return nil
}

// --- response envelope -----------------------------------------------------
//
// The response types below marshal to the exact SOAP 1.2 + WS-Addressing shape a
// Windows client expects. The envelope and header carry the "s" (SOAP) and "a"
// (WS-Addressing) prefixes because the mustUnderstand attribute is SOAP-
// namespaced; the body content declares its own default namespaces per subtree
// (WS-Trust / WSS / Microsoft-enrollment), matching how AD CS emits them.

// outEnvelope is a SOAP 1.2 response envelope with a WS-Addressing header.
type outEnvelope struct {
	XMLName xml.Name  `xml:"s:Envelope"`
	S       string    `xml:"xmlns:s,attr"`
	A       string    `xml:"xmlns:a,attr"`
	Header  outHeader `xml:"s:Header"`
	Body    outBody   `xml:"s:Body"`
}

type outHeader struct {
	Action    outAction `xml:"a:Action"`
	RelatesTo string    `xml:"a:RelatesTo,omitempty"`
}

type outAction struct {
	MustUnderstand string `xml:"s:mustUnderstand,attr"`
	Value          string `xml:",chardata"`
}

// outBody carries the operation-specific content (an RSTRC, a GetPoliciesResponse,
// or a Fault). The concrete value's own XMLName supplies the element name and
// namespace.
type outBody struct {
	Content any
}

// newEnvelope assembles a response envelope with the given WS-Addressing action,
// RelatesTo (the request MessageID, echoed per WS-Addressing), and body content.
func newEnvelope(action, relatesTo string, content any) outEnvelope {
	return outEnvelope{
		S: nsSOAP12,
		A: nsWSA,
		Header: outHeader{
			Action:    outAction{MustUnderstand: "1", Value: action},
			RelatesTo: relatesTo,
		},
		Body: outBody{Content: content},
	}
}

// writeEnvelope marshals env and writes it as a SOAP 1.2 response with the given
// HTTP status. A marshaling failure degrades to a plain 500 (it indicates a
// server bug, not a client error).
func writeEnvelope(w http.ResponseWriter, status int, env outEnvelope) {
	out, err := xml.Marshal(env)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeSOAP)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// --- SOAP fault ------------------------------------------------------------

// soapFault is a SOAP 1.2 Fault body (used for malformed requests and issuance
// failures). Authentication failures are handled at the HTTP layer with a 401
// before any SOAP processing, matching the transport-authenticated CES model.
type soapFault struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`
	Code    faultCode   `xml:"Code"`
	Reason  faultReason `xml:"Reason"`
}

type faultCode struct {
	Value string `xml:"Value"`
}

type faultReason struct {
	Text faultText `xml:"Text"`
}

type faultText struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// Fault code values (SOAP 1.2 §5.4.6). Sender indicates the client's message was
// malformed or unauthorized; Receiver indicates a server-side processing error.
const (
	faultSender   = "s:Sender"
	faultReceiver = "s:Receiver"
)

// writeFault writes a SOAP 1.2 Fault with the given HTTP status. The RelatesTo
// echoes the request MessageID so a client can correlate the fault.
func writeFault(w http.ResponseWriter, status int, code, reason, relatesTo string) {
	fault := soapFault{
		Code:   faultCode{Value: code},
		Reason: faultReason{Text: faultText{Lang: "en-US", Value: reason}},
	}
	env := newEnvelope(actionSOAPFault, relatesTo, fault)
	writeEnvelope(w, status, env)
}
