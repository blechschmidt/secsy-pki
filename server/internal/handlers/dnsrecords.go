package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/dnsrecords"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// DNSRecordsTLSA generates DANE TLSA records (RFC 6698) for a TLS service that
// presents a certificate issued by CA {id}.
//
//	GET /api/ca/{id}/dns-records/tlsa?host=<h>&port=<p>&protocol=<tcp|udp>&serial=<leaf>
//
// Without ?serial it returns records for the issuing CA only (usages PKIX-CA and
// DANE-TA). With ?serial — a leaf issued by this CA — it additionally returns the
// leaf's DANE-EE records. Read-gated plus tenant membership, like the inventory.
func (a *API) DNSRecordsTLSA(w http.ResponseWriter, r *http.Request) {
	caModel, ok := a.authorizeCARead(w, r, r.PathValue("id"))
	if !ok {
		return
	}

	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	if host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	port := 443
	if v := strings.TrimSpace(q.Get("port")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			writeError(w, http.StatusBadRequest, "invalid port %q", v)
			return
		}
		port = p
	}
	protocol := q.Get("protocol") // TLSAOwnerName defaults empty to "tcp"

	if strings.TrimSpace(caModel.Certificate) == "" {
		writeError(w, http.StatusUnprocessableEntity, "CA has no certificate on record")
		return
	}
	caCert, err := pki.ParseCertificatePEM([]byte(caModel.Certificate))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "parsing CA certificate: %v", err)
		return
	}

	owner := dnsrecords.TLSAOwnerName(host, port, protocol)

	var tlsa []dnsrecords.TLSARecord
	if serial := strings.TrimSpace(q.Get("serial")); serial != "" {
		leafModel, err := a.db.GetIssuedCertificate(caModel.ID, serial)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "looking up certificate: %v", err)
			return
		}
		if leafModel == nil {
			writeError(w, http.StatusNotFound, "no certificate with serial %s issued by this CA", serial)
			return
		}
		leafCert, err := pki.ParseCertificatePEM([]byte(leafModel.Certificate))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "parsing certificate: %v", err)
			return
		}
		leafRecs, err := dnsrecords.LeafTLSARecords(owner, leafCert)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "generating leaf TLSA records: %v", err)
			return
		}
		tlsa = append(tlsa, leafRecs...)
	}

	issuerRecs, err := dnsrecords.IssuerTLSARecords(owner, caCert)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generating issuer TLSA records: %v", err)
		return
	}
	tlsa = append(tlsa, issuerRecs...)

	writeJSON(w, http.StatusOK, dnsrecords.NewBundle(tlsa, nil))
}

// dnsSSHFPRequest is the body of the SSHFP generation endpoint. Exactly one of
// serial (a stored host certificate under the SSH CA) or public_key (a raw SSH
// public key or certificate in authorized_keys format) must be supplied.
type dnsSSHFPRequest struct {
	Host      string `json:"host"`
	Serial    string `json:"serial,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

// DNSRecordsSSHFP generates SSHFP records (RFC 4255) for an SSH host key.
//
//	POST /api/ssh/cas/{id}/dns-records/sshfp   {host, serial?, public_key?}
//
// With serial it pins a host certificate this SSH CA issued (looked up by serial);
// with public_key it pins a supplied host key. Read-gated plus tenant membership.
func (a *API) DNSRecordsSSHFP(w http.ResponseWriter, r *http.Request) {
	caModel, ok := a.authorizeCARead(w, r, r.PathValue("id"))
	if !ok {
		return
	}

	var req dnsSSHFPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	serial := strings.TrimSpace(req.Serial)
	pubKey := strings.TrimSpace(req.PublicKey)
	if (serial == "") == (pubKey == "") {
		writeError(w, http.StatusBadRequest, "exactly one of serial or public_key is required")
		return
	}

	host := strings.TrimSpace(req.Host)
	var authorizedKey []byte
	if serial != "" {
		certModel, err := a.db.GetSSHCertificate(caModel.ID, serial)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "looking up SSH certificate: %v", err)
			return
		}
		if certModel == nil {
			writeError(w, http.StatusNotFound, "no SSH certificate with serial %s under this CA", serial)
			return
		}
		if certModel.CertType != "host" {
			writeError(w, http.StatusUnprocessableEntity, "SSH certificate %s is a %s certificate; SSHFP records apply to host keys", serial, certModel.CertType)
			return
		}
		authorizedKey = []byte(certModel.Certificate)
		if host == "" && len(certModel.Principals) > 0 {
			host = certModel.Principals[0]
		}
	} else {
		authorizedKey = []byte(pubKey)
	}

	if host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}

	key, err := dnsrecords.ParseSSHPublicKey(authorizedKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	sshfp, err := dnsrecords.SSHFPRecords(host, key)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}

	writeJSON(w, http.StatusOK, dnsrecords.NewBundle(nil, sshfp))
}
