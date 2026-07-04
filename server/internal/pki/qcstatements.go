package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"
	"strings"
)

// Object identifiers for the ETSI EN 319 412-5 QCStatements extension and the
// ETSI TS 119 495 PSD2 QcStatement carried inside it. These identify EU
// qualified-certificate semantics under Regulation (EU) No 910/2014 (eIDAS): an
// issuer stamps them so relying parties can recognize a certificate as issued
// under a qualified trust service.
var (
	// OIDQCStatements is the RFC 3739 / RFC 5280 id-pe-qcStatements extension
	// ({ id-pe 3 } = 1.3.6.1.5.5.7.1.3). Its value is a SEQUENCE OF QCStatement.
	// ETSI EN 319 412-5 §4 requires the extension be non-critical.
	OIDQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

	// The id-etsi-qcs arc ({ itu-t(0) identified-organization(4) etsi(0)
	// id-qc-statements(1862) 1 } = 0.4.0.1862.1) roots the ETSI QC statements.

	// OIDEtsiQcsQcCompliance is esi4-qcStatement-1 (0.4.0.1862.1.1): the
	// certificate is an EU qualified certificate. It carries no statementInfo.
	OIDEtsiQcsQcCompliance = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	// OIDEtsiQcsQcRetentionPeriod is esi4-qcStatement-3 (0.4.0.1862.1.3): the
	// number of years the issuer retains material information about the
	// certificate. Its statementInfo is an INTEGER (QcEuRetentionPeriod).
	OIDEtsiQcsQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	// OIDEtsiQcsQcSSCD is esi4-qcStatement-4 (0.4.0.1862.1.4): the private key
	// resides in a qualified signature/seal creation device (QSCD/SSCD). It
	// carries no statementInfo.
	OIDEtsiQcsQcSSCD = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	// OIDEtsiQcsQcPDS is esi4-qcStatement-5 (0.4.0.1862.1.5): the locations of
	// the PKI Disclosure Statement(s). Its statementInfo is a PdsLocations.
	OIDEtsiQcsQcPDS = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	// OIDEtsiQcsQcType is esi4-qcStatement-6 (0.4.0.1862.1.6): the type(s) of
	// qualified certificate. Its statementInfo is a SEQUENCE OF OBJECT IDENTIFIER.
	OIDEtsiQcsQcType = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}

	// The three QcType values (ETSI EN 319 412-5 §4.2.3), under id-etsi-qcs-QcType.

	// OIDEtsiQctEsign is id-etsi-qct-esign (0.4.0.1862.1.6.1): a qualified
	// certificate for electronic signatures (a natural person).
	OIDEtsiQctEsign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
	// OIDEtsiQctEseal is id-etsi-qct-eseal (0.4.0.1862.1.6.2): a qualified
	// certificate for electronic seals (a legal person).
	OIDEtsiQctEseal = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	// OIDEtsiQctWeb is id-etsi-qct-web (0.4.0.1862.1.6.3): a qualified
	// certificate for website authentication (a QWAC).
	OIDEtsiQctWeb = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}

	// OIDEtsiPSD2QcStatement is the ETSI TS 119 495 PSD2 QcStatement
	// (etsi-psd2-qcStatement, { itu-t(0) identified-organization(4) etsi(0)
	// psd2(19495) qcstatement(2) } = 0.4.0.19495.2). Its statementInfo is a
	// PSD2QcType (roles of the payment service provider plus its competent
	// authority's name and identifier).
	OIDEtsiPSD2QcStatement = asn1.ObjectIdentifier{0, 4, 0, 19495, 2}

	// The four PSP role OIDs (ETSI TS 119 495 §5.1), under
	// etsi-psd2-roles ({ ... psd2(19495) id-roles(1) } = 0.4.0.19495.1).

	// OIDPSD2RolePSPAS is PSP_AS (0.4.0.19495.1.1): account servicing.
	OIDPSD2RolePSPAS = asn1.ObjectIdentifier{0, 4, 0, 19495, 1, 1}
	// OIDPSD2RolePSPPI is PSP_PI (0.4.0.19495.1.2): payment initiation.
	OIDPSD2RolePSPPI = asn1.ObjectIdentifier{0, 4, 0, 19495, 1, 2}
	// OIDPSD2RolePSPAI is PSP_AI (0.4.0.19495.1.3): account information.
	OIDPSD2RolePSPAI = asn1.ObjectIdentifier{0, 4, 0, 19495, 1, 3}
	// OIDPSD2RolePSPIC is PSP_IC (0.4.0.19495.1.4): issuing of card-based payment
	// instruments.
	OIDPSD2RolePSPIC = asn1.ObjectIdentifier{0, 4, 0, 19495, 1, 4}
)

// qcTypeByName maps the profile/CLI-facing QcType selector to its OID.
var qcTypeByName = map[string]asn1.ObjectIdentifier{
	"esign": OIDEtsiQctEsign,
	"eseal": OIDEtsiQctEseal,
	"web":   OIDEtsiQctWeb,
}

// QCTypeOID resolves a QcType selector ("esign", "eseal", "web",
// case-insensitive) to its object identifier.
func QCTypeOID(name string) (asn1.ObjectIdentifier, bool) {
	oid, ok := qcTypeByName[strings.ToLower(strings.TrimSpace(name))]
	return oid, ok
}

// psd2RoleByName maps the standard PSP role name to its OID. ETSI TS 119 495
// Annex A fixes both the OID and the accompanying roleOfPspName string.
var psd2RoleByName = map[string]asn1.ObjectIdentifier{
	"PSP_AS": OIDPSD2RolePSPAS,
	"PSP_PI": OIDPSD2RolePSPPI,
	"PSP_AI": OIDPSD2RolePSPAI,
	"PSP_IC": OIDPSD2RolePSPIC,
}

// PSD2RoleOID resolves a PSP role name ("PSP_AS", "PSP_PI", "PSP_AI", "PSP_IC",
// case-insensitive) to its object identifier.
func PSD2RoleOID(name string) (asn1.ObjectIdentifier, bool) {
	oid, ok := psd2RoleByName[strings.ToUpper(strings.TrimSpace(name))]
	return oid, ok
}

// QCPDSLocation is one PKI Disclosure Statement location: a URL and the ISO
// 639-1 (two-letter) language code of the document it points to.
type QCPDSLocation struct {
	URL      string
	Language string
}

// QCPSD2Role is one PSP role: its OID and the accompanying human-readable
// roleOfPspName (per ETSI TS 119 495, the fixed strings "PSP_AS", "PSP_PI",
// "PSP_AI", "PSP_IC").
type QCPSD2Role struct {
	OID  asn1.ObjectIdentifier
	Name string
}

// QCPSD2 is the ETSI TS 119 495 PSD2 QcStatement content: the roles of the
// payment service provider plus the name and identifier of the National
// Competent Authority (NCA) that authorized it.
type QCPSD2 struct {
	Roles   []QCPSD2Role
	NCAName string
	NCAID   string
}

// QCStatements is the decoded/whole content of an id-pe-qcStatements extension
// as this CA emits it. A zero value emits nothing; Extension only encodes the
// statements whose fields are set, in a fixed order.
type QCStatements struct {
	// Compliance emits id-etsi-qcs-QcCompliance (the certificate is an EU
	// qualified certificate).
	Compliance bool
	// Types are the id-etsi-qcs-QcType values (esign/eseal/web OIDs). Empty
	// omits the QcType statement.
	Types []asn1.ObjectIdentifier
	// SSCD emits id-etsi-qcs-QcSSCD (private key in a QSCD/SSCD).
	SSCD bool
	// RetentionYears, when > 0, emits id-etsi-qcs-QcRetentionPeriod.
	RetentionYears int
	// PDS, when non-empty, emits id-etsi-qcs-QcPDS with these locations.
	PDS []QCPDSLocation
	// PSD2, when non-nil, emits the ETSI TS 119 495 PSD2 QcStatement.
	PSD2 *QCPSD2
	// Unrecognized records the ids of any QCStatements a decode did not
	// understand. It is populated only by ParseQCStatements and is ignored by
	// Extension (a re-encode emits only the recognized fields above).
	Unrecognized []asn1.ObjectIdentifier
}

// IsZero reports whether the value would emit no statements at all.
func (q QCStatements) IsZero() bool {
	return !q.Compliance && len(q.Types) == 0 && !q.SSCD &&
		q.RetentionYears <= 0 && len(q.PDS) == 0 && q.PSD2 == nil
}

// pdsLocation is the DER shape of a PdsLocation:
//
//	PdsLocation ::= SEQUENCE { url IA5String, language PrintableString (SIZE(2)) }
type pdsLocation struct {
	URL      string `asn1:"ia5"`
	Language string `asn1:"printable"`
}

// psd2Role is the DER shape of a RoleOfPSP:
//
//	RoleOfPSP ::= SEQUENCE { roleOfPspOid OBJECT IDENTIFIER, roleOfPspName UTF8String }
type psd2Role struct {
	OID  asn1.ObjectIdentifier
	Name string `asn1:"utf8"`
}

// psd2QcType is the DER shape of a PSD2QcType:
//
//	PSD2QcType ::= SEQUENCE { rolesOfPSP SEQUENCE OF RoleOfPSP,
//	                         nCAName UTF8String, nCAId UTF8String }
type psd2QcType struct {
	Roles   []psd2Role
	NCAName string `asn1:"utf8"`
	NCAID   string `asn1:"utf8"`
}

// encodeStatement DER-encodes a single QCStatement:
//
//	QCStatement ::= SEQUENCE { statementId OBJECT IDENTIFIER,
//	                          statementInfo ANY DEFINED BY statementId OPTIONAL }
//
// A nil info encodes a statement with no statementInfo (QcCompliance, QcSSCD).
func encodeStatement(id asn1.ObjectIdentifier, info []byte) ([]byte, error) {
	idDER, err := asn1.Marshal(id)
	if err != nil {
		return nil, fmt.Errorf("encoding QCStatement id %v: %w", id, err)
	}
	content := make([]byte, 0, len(idDER)+len(info))
	content = append(content, idDER...)
	content = append(content, info...)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// Extension builds the complete id-pe-qcStatements extension (OID
// 1.3.6.1.5.5.7.1.3), a non-critical SEQUENCE OF QCStatement. The statements are
// emitted in a fixed, documented order — QcCompliance, QcType, QcSSCD,
// QcRetentionPeriod, QcPDS, PSD2 — so the encoding is reproducible; order is not
// semantically significant (SEQUENCE OF, not SET OF). It returns an error if no
// statement would be emitted, since an empty QCStatements is degenerate.
//
// crypto/x509 cannot encode this extension, so — like the smartcard/UPN
// otherName SAN — it is hand-rolled and supplied via ExtraExtensions. The caller
// appends it before any Certificate-Transparency poison/SCT-list extension so
// that trailing CT extension stays last (keeping the precertificate and final
// certificate TBSCertificates aligned).
func (q QCStatements) Extension() (pkix.Extension, error) {
	if q.IsZero() {
		return pkix.Extension{}, fmt.Errorf("qcStatements: no statements to encode")
	}

	var statements []byte
	appendStatement := func(id asn1.ObjectIdentifier, info []byte) error {
		der, err := encodeStatement(id, info)
		if err != nil {
			return err
		}
		statements = append(statements, der...)
		return nil
	}

	if q.Compliance {
		if err := appendStatement(OIDEtsiQcsQcCompliance, nil); err != nil {
			return pkix.Extension{}, err
		}
	}
	if len(q.Types) > 0 {
		info, err := asn1.Marshal(q.Types) // SEQUENCE OF OBJECT IDENTIFIER
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("encoding QcType: %w", err)
		}
		if err := appendStatement(OIDEtsiQcsQcType, info); err != nil {
			return pkix.Extension{}, err
		}
	}
	if q.SSCD {
		if err := appendStatement(OIDEtsiQcsQcSSCD, nil); err != nil {
			return pkix.Extension{}, err
		}
	}
	if q.RetentionYears > 0 {
		info, err := asn1.Marshal(q.RetentionYears) // INTEGER
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("encoding QcRetentionPeriod: %w", err)
		}
		if err := appendStatement(OIDEtsiQcsQcRetentionPeriod, info); err != nil {
			return pkix.Extension{}, err
		}
	}
	if len(q.PDS) > 0 {
		locs := make([]pdsLocation, len(q.PDS))
		for i, l := range q.PDS {
			locs[i] = pdsLocation(l)
		}
		info, err := asn1.Marshal(locs) // SEQUENCE OF PdsLocation
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("encoding QcPDS: %w", err)
		}
		if err := appendStatement(OIDEtsiQcsQcPDS, info); err != nil {
			return pkix.Extension{}, err
		}
	}
	if q.PSD2 != nil {
		roles := make([]psd2Role, len(q.PSD2.Roles))
		for i, r := range q.PSD2.Roles {
			roles[i] = psd2Role(r)
		}
		info, err := asn1.Marshal(psd2QcType{Roles: roles, NCAName: q.PSD2.NCAName, NCAID: q.PSD2.NCAID})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("encoding PSD2 QcStatement: %w", err)
		}
		if err := appendStatement(OIDEtsiPSD2QcStatement, info); err != nil {
			return pkix.Extension{}, err
		}
	}

	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      statements,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding qcStatements: %w", err)
	}
	// ETSI EN 319 412-5 §4: the extension shall NOT be marked critical, so that a
	// relying party that does not understand it still accepts the certificate.
	return pkix.Extension{Id: OIDQCStatements, Critical: false, Value: value}, nil
}

// ParseQCStatements decodes an id-pe-qcStatements extension value back into a
// QCStatements. It fully validates the outer structure (a SEQUENCE OF QCStatement,
// each a SEQUENCE starting with an OBJECT IDENTIFIER) and decodes the statements
// this package emits; a statement with an unrecognized id is tolerated and its
// id recorded in Unrecognized so a caller can distinguish "no such statement"
// from "unparseable". A structurally malformed value yields an error, which is
// how the pre-issuance lint gate recognizes-but-rejects a corrupt extension.
func ParseQCStatements(value []byte) (QCStatements, error) {
	var out QCStatements
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(value, &seq)
	if err != nil {
		return out, fmt.Errorf("decoding qcStatements: %w", err)
	}
	if len(rest) != 0 {
		return out, fmt.Errorf("qcStatements has %d trailing byte(s)", len(rest))
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return out, fmt.Errorf("qcStatements is not a SEQUENCE")
	}

	body := seq.Bytes
	for len(body) > 0 {
		var stmt asn1.RawValue
		body, err = asn1.Unmarshal(body, &stmt)
		if err != nil {
			return out, fmt.Errorf("decoding QCStatement: %w", err)
		}
		if stmt.Class != asn1.ClassUniversal || stmt.Tag != asn1.TagSequence || !stmt.IsCompound {
			return out, fmt.Errorf("QCStatement is not a SEQUENCE")
		}
		var id asn1.ObjectIdentifier
		info, err := asn1.Unmarshal(stmt.Bytes, &id)
		if err != nil {
			return out, fmt.Errorf("decoding QCStatement id: %w", err)
		}
		if err := out.decodeStatement(id, info); err != nil {
			return out, err
		}
	}
	return out, nil
}

// decodeStatement folds one decoded QCStatement (its id and the raw DER of its
// optional statementInfo) into the receiver, recording an unrecognized id rather
// than failing so a forward-compatible statement does not break parsing.
func (q *QCStatements) decodeStatement(id asn1.ObjectIdentifier, info []byte) error {
	switch {
	case id.Equal(OIDEtsiQcsQcCompliance):
		q.Compliance = true
	case id.Equal(OIDEtsiQcsQcSSCD):
		q.SSCD = true
	case id.Equal(OIDEtsiQcsQcType):
		var types []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(info, &types); err != nil {
			return fmt.Errorf("decoding QcType statementInfo: %w", err)
		}
		q.Types = append(q.Types, types...)
	case id.Equal(OIDEtsiQcsQcRetentionPeriod):
		var years int
		if _, err := asn1.Unmarshal(info, &years); err != nil {
			return fmt.Errorf("decoding QcRetentionPeriod statementInfo: %w", err)
		}
		q.RetentionYears = years
	case id.Equal(OIDEtsiQcsQcPDS):
		var locs []pdsLocation
		if _, err := asn1.Unmarshal(info, &locs); err != nil {
			return fmt.Errorf("decoding QcPDS statementInfo: %w", err)
		}
		for _, l := range locs {
			q.PDS = append(q.PDS, QCPDSLocation(l))
		}
	case id.Equal(OIDEtsiPSD2QcStatement):
		var psd2 psd2QcType
		if _, err := asn1.Unmarshal(info, &psd2); err != nil {
			return fmt.Errorf("decoding PSD2 statementInfo: %w", err)
		}
		roles := make([]QCPSD2Role, len(psd2.Roles))
		for i, r := range psd2.Roles {
			roles[i] = QCPSD2Role(r)
		}
		q.PSD2 = &QCPSD2{Roles: roles, NCAName: psd2.NCAName, NCAID: psd2.NCAID}
	default:
		q.Unrecognized = append(q.Unrecognized, id)
	}
	return nil
}

// QCStatementsFromCertificate returns the decoded id-pe-qcStatements content a
// parsed certificate carries, reporting present=false when the extension is
// absent. A present-but-malformed extension yields an error.
func QCStatementsFromCertificate(cert *x509.Certificate) (qc QCStatements, present bool, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDQCStatements) {
			continue
		}
		qc, err = ParseQCStatements(ext.Value)
		return qc, true, err
	}
	return QCStatements{}, false, nil
}

// QCTypeNames renders a set of QcType OIDs as their friendly selectors
// (esign/eseal/web), falling back to the dotted OID for any unrecognized value.
// Sorted for stable output.
func QCTypeNames(types []asn1.ObjectIdentifier) []string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		switch {
		case t.Equal(OIDEtsiQctEsign):
			names = append(names, "esign")
		case t.Equal(OIDEtsiQctEseal):
			names = append(names, "eseal")
		case t.Equal(OIDEtsiQctWeb):
			names = append(names, "web")
		default:
			names = append(names, t.String())
		}
	}
	sort.Strings(names)
	return names
}
