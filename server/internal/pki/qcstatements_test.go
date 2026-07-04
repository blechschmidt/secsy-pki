package pki

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// TestQCStatements_KnownAnswer pins the exact DER of individual statements,
// hand-computed from ETSI EN 319 412-5, so a regression in the ASN.1 encoding is
// caught immediately (not just a round-trip that could hide a symmetric bug).
func TestQCStatements_KnownAnswer(t *testing.T) {
	cases := []struct {
		name string
		in   QCStatements
		want string // hex of the extension value (outer SEQUENCE OF QCStatement)
	}{
		{
			// QCStatements { QCStatement { id-etsi-qcs-QcCompliance } }
			//   OID 0.4.0.1862.1.1 = 06 06 04 00 8e 46 01 01
			//   QCStatement        = 30 08 <oid>
			//   QCStatements       = 30 0a <stmt>
			name: "compliance-only",
			in:   QCStatements{Compliance: true},
			want: "30 0a 30 08 06 06 04 00 8e 46 01 01",
		},
		{
			// QCStatements { QCStatement { id-etsi-qcs-QcType, SEQUENCE { id-etsi-qct-esign } } }
			//   QcType OID 0.4.0.1862.1.6   = 06 06 04 00 8e 46 01 06
			//   esign  OID 0.4.0.1862.1.6.1 = 06 07 04 00 8e 46 01 06 01
			//   info SEQUENCE OF OID        = 30 09 <esign-oid>
			//   QCStatement                 = 30 13 <qctype-oid> <info>
			//   QCStatements                = 30 15 <stmt>
			name: "qctype-esign-only",
			in:   QCStatements{Types: []asn1.ObjectIdentifier{OIDEtsiQctEsign}},
			want: "30 15 30 13 06 06 04 00 8e 46 01 06 30 09 06 07 04 00 8e 46 01 06 01",
		},
		{
			// QCStatement { id-etsi-qcs-QcSSCD } — OID 0.4.0.1862.1.4.
			name: "sscd-only",
			in:   QCStatements{SSCD: true},
			want: "30 0a 30 08 06 06 04 00 8e 46 01 04",
		},
		{
			// QCStatement { id-etsi-qcs-QcRetentionPeriod, INTEGER 10 }
			//   OID 0.4.0.1862.1.3 = 06 06 04 00 8e 46 01 03; INTEGER 10 = 02 01 0a
			name: "retention-only",
			in:   QCStatements{RetentionYears: 10},
			want: "30 0d 30 0b 06 06 04 00 8e 46 01 03 02 01 0a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(strings.ReplaceAll(tc.want, " ", ""))
			if err != nil {
				t.Fatalf("bad want hex: %v", err)
			}
			ext, err := tc.in.Extension()
			if err != nil {
				t.Fatalf("Extension() error: %v", err)
			}
			if !ext.Id.Equal(OIDQCStatements) {
				t.Errorf("extension OID = %v, want %v", ext.Id, OIDQCStatements)
			}
			if ext.Critical {
				t.Error("qcStatements extension must be non-critical (ETSI EN 319 412-5 §4)")
			}
			if !bytes.Equal(ext.Value, want) {
				t.Errorf("DER mismatch:\n got %s\nwant %s", hex.EncodeToString(ext.Value), hex.EncodeToString(want))
			}
		})
	}
}

// TestQCStatements_PDSKnownAnswer pins the QcPDS encoding, whose PdsLocation uses
// IA5String + PrintableString — the field-tag path most prone to silent drift.
func TestQCStatements_PDSKnownAnswer(t *testing.T) {
	// QCStatement { id-etsi-qcs-QcPDS(0.4.0.1862.1.5), PdsLocations }
	//   PdsLocation { url="https://x/pds", language="en" }
	//     IA5String "https://x/pds" (13 bytes) = 16 0d <ascii>
	//     PrintableString "en" (2 bytes)       = 13 02 65 6e
	//     PdsLocation SEQUENCE                  = 30 13 <ia5> <printable>
	//   PdsLocations SEQUENCE OF                = 30 15 <loc>
	//   QcPDS OID 0.4.0.1862.1.5 (8B) + PdsLocations (23B) = 31B content
	//   QCStatement SEQUENCE                    = 30 1f <oid> <info>
	//   QCStatements SEQUENCE OF                = 30 21 <stmt>
	in := QCStatements{PDS: []QCPDSLocation{{URL: "https://x/pds", Language: "en"}}}
	ext, err := in.Extension()
	if err != nil {
		t.Fatalf("Extension() error: %v", err)
	}
	url := hex.EncodeToString([]byte("https://x/pds"))
	want := strings.ReplaceAll(
		"30 21 30 1f 06 06 04 00 8e 46 01 05 "+ // QCStatements, QCStatement, QcPDS OID
			"30 15 30 13 16 0d "+url+" 13 02 65 6e", // PdsLocations{ PdsLocation{ IA5, Printable } }
		" ", "")
	if got := hex.EncodeToString(ext.Value); got != want {
		t.Errorf("QcPDS DER mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestQCStatements_RoundTrip encodes the full feature set (including PSD2) and
// decodes it back, asserting the decoded content matches the input exactly.
func TestQCStatements_RoundTrip(t *testing.T) {
	psAS, _ := PSD2RoleOID("PSP_AS")
	psPI, _ := PSD2RoleOID("psp_pi") // case-insensitive
	in := QCStatements{
		Compliance:     true,
		Types:          []asn1.ObjectIdentifier{OIDEtsiQctWeb},
		SSCD:           true,
		RetentionYears: 15,
		PDS: []QCPDSLocation{
			{URL: "https://ca.example/pds/en.pdf", Language: "en"},
			{URL: "https://ca.example/pds/de.pdf", Language: "de"},
		},
		PSD2: &QCPSD2{
			Roles: []QCPSD2Role{
				{OID: psAS, Name: "PSP_AS"},
				{OID: psPI, Name: "PSP_PI"},
			},
			NCAName: "Financial Conduct Authority",
			NCAID:   "GB-FCA",
		},
	}
	ext, err := in.Extension()
	if err != nil {
		t.Fatalf("Extension() error: %v", err)
	}
	got, err := ParseQCStatements(ext.Value)
	if err != nil {
		t.Fatalf("ParseQCStatements() error: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
	if !psAS.Equal(OIDPSD2RolePSPAS) || !psPI.Equal(OIDPSD2RolePSPPI) {
		t.Errorf("PSD2 role OIDs unexpected: AS=%v PI=%v", psAS, psPI)
	}
}

func TestQCStatements_IsZeroAndEmptyError(t *testing.T) {
	if !(QCStatements{}).IsZero() {
		t.Error("empty QCStatements should be zero")
	}
	if _, err := (QCStatements{}).Extension(); err == nil {
		t.Error("Extension() on empty QCStatements should error")
	}
	if (QCStatements{Compliance: true}).IsZero() {
		t.Error("QCStatements with a statement should not be zero")
	}
}

func TestParseQCStatements_Malformed(t *testing.T) {
	valid, err := (QCStatements{Compliance: true}).Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	cases := map[string][]byte{
		"not a sequence":    {0x02, 0x01, 0x01},                          // INTEGER
		"trailing bytes":    append(append([]byte{}, valid.Value...), 0), // valid + junk
		"statement not seq": {0x30, 0x03, 0x02, 0x01, 0x01},              // SEQUENCE { INTEGER }
		"truncated":         {0x30, 0x05, 0x30, 0x03, 0x06, 0x01},        // length claims more than present
		"empty input":       {},
		"statement no oid":  {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01}, // SEQUENCE { SEQUENCE { INTEGER } }
	}
	for name, in := range cases {
		if _, err := ParseQCStatements(in); err == nil {
			t.Errorf("%s: ParseQCStatements did not error", name)
		}
	}
}

func TestParseQCStatements_UnrecognizedTolerated(t *testing.T) {
	// A QCStatement with an unknown id (id-etsi-qcs-QcLimitValue, 0.4.0.1862.1.2,
	// which this package does not emit) must not break decoding of the rest.
	unknown := asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 2}
	stmt, err := encodeStatement(unknown, nil)
	if err != nil {
		t.Fatalf("encodeStatement: %v", err)
	}
	comp, _ := encodeStatement(OIDEtsiQcsQcCompliance, nil)
	value, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte{}, comp...), stmt...),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseQCStatements(value)
	if err != nil {
		t.Fatalf("ParseQCStatements error: %v", err)
	}
	if !got.Compliance {
		t.Error("recognized QcCompliance lost when an unknown statement is present")
	}
	if len(got.Unrecognized) != 1 || !got.Unrecognized[0].Equal(unknown) {
		t.Errorf("Unrecognized = %v, want [%v]", got.Unrecognized, unknown)
	}
}

func TestQCTypeAndRoleOIDLookup(t *testing.T) {
	for name, want := range map[string]asn1.ObjectIdentifier{
		"esign": OIDEtsiQctEsign, "ESEAL": OIDEtsiQctEseal, " web ": OIDEtsiQctWeb,
	} {
		got, ok := QCTypeOID(name)
		if !ok || !got.Equal(want) {
			t.Errorf("QCTypeOID(%q) = (%v,%v), want %v", name, got, ok, want)
		}
	}
	if _, ok := QCTypeOID("bogus"); ok {
		t.Error("QCTypeOID(bogus) should not resolve")
	}
	for name, want := range map[string]asn1.ObjectIdentifier{
		"PSP_AS": OIDPSD2RolePSPAS, "psp_pi": OIDPSD2RolePSPPI,
		"PSP_AI": OIDPSD2RolePSPAI, "PSP_IC": OIDPSD2RolePSPIC,
	} {
		got, ok := PSD2RoleOID(name)
		if !ok || !got.Equal(want) {
			t.Errorf("PSD2RoleOID(%q) = (%v,%v), want %v", name, got, ok, want)
		}
	}
	if _, ok := PSD2RoleOID("PSP_XX"); ok {
		t.Error("PSD2RoleOID(PSP_XX) should not resolve")
	}
}
