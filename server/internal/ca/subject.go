package ca

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/caext"
)

// Object identifiers for the distinguished-name attributes PKIXName can emit
// beyond the ones pkix.Name models as its own fields.
var (
	oidDomainComponent       = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID                = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidOrganizationIdentifer = asn1.ObjectIdentifier{2, 5, 4, 97}
)

// oidEmailAddress, the PKCS#9 emailAddress attribute, is declared next to the
// S/MIME gate that validates addresses (smime.go) and reused here.

// subjectAttributeOIDs resolves the short attribute names accepted in a
// CASubject.ExtraNames entry. Anything absent here can still be written as a
// dotted OID, so the list is a convenience rather than a limit.
//
// The keys are matched case-insensitively. The RFC 4514 attribute names (CN, O,
// OU, …) and the X.520 / EV / eIDAS attribute names enterprise DNs actually use
// are both present.
var subjectAttributeOIDs = map[string]asn1.ObjectIdentifier{
	"cn":                     {2, 5, 4, 3},
	"commonname":             {2, 5, 4, 3},
	"surname":                {2, 5, 4, 4},
	"sn":                     {2, 5, 4, 4},
	"serialnumber":           {2, 5, 4, 5},
	"c":                      {2, 5, 4, 6},
	"country":                {2, 5, 4, 6},
	"l":                      {2, 5, 4, 7},
	"locality":               {2, 5, 4, 7},
	"st":                     {2, 5, 4, 8},
	"province":               {2, 5, 4, 8},
	"street":                 {2, 5, 4, 9},
	"o":                      {2, 5, 4, 10},
	"organization":           {2, 5, 4, 10},
	"ou":                     {2, 5, 4, 11},
	"organizationalunit":     {2, 5, 4, 11},
	"title":                  {2, 5, 4, 12},
	"description":            {2, 5, 4, 13},
	"businesscategory":       {2, 5, 4, 15},
	"postalcode":             {2, 5, 4, 17},
	"givenname":              {2, 5, 4, 42},
	"gn":                     {2, 5, 4, 42},
	"initials":               {2, 5, 4, 43},
	"pseudonym":              {2, 5, 4, 65},
	"organizationidentifier": oidOrganizationIdentifer,
	"dc":                     oidDomainComponent,
	"domaincomponent":        oidDomainComponent,
	"e":                      oidEmailAddress,
	"email":                  oidEmailAddress,
	"emailaddress":           oidEmailAddress,
	"uid":                    oidUserID,
	"userid":                 oidUserID,
	// CA/Browser Forum EV jurisdiction-of-incorporation attributes.
	"jurisdictionc":  {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3},
	"jurisdictionst": {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2},
	"jurisdictionl":  {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1},
}

// ia5Value wraps a string so pkix emits it as an IA5String, the encoding the
// PKCS#9 emailAddress and domainComponent attributes are defined with. Handing
// pkix a bare Go string would produce a PrintableString or UTF8String instead,
// which some strict validators and DN-matching relying parties reject.
func ia5Value(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(s)}
}

// parseSubjectAttributeType resolves a CASubject.ExtraNames type: a short
// attribute name from subjectAttributeOIDs, or a dotted OID.
func parseSubjectAttributeType(s string) (asn1.ObjectIdentifier, error) {
	name := strings.TrimSpace(s)
	if name == "" {
		return nil, fmt.Errorf("a distinguished-name attribute type is required")
	}
	if oid, ok := subjectAttributeOIDs[strings.ToLower(name)]; ok {
		return oid, nil
	}
	oid, err := caext.ParseOID(name)
	if err != nil {
		return nil, fmt.Errorf("unknown distinguished-name attribute %q (give a short name or a dotted OID)", s)
	}
	return oid, nil
}
