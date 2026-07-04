package pki

import (
	"bytes"
	"encoding/asn1"
	"reflect"
	"testing"
)

// mustStapleDER is the exact DER encoding of the RFC 7633 Must-Staple TLS
// Feature extension value: SEQUENCE { INTEGER 5 } (status_request).
var mustStapleDER = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

func TestMustStapleExtensionExactDER(t *testing.T) {
	ext := MustStapleExtension()

	if !ext.Id.Equal(OIDTLSFeature) {
		t.Errorf("OID = %v, want %v (id-pe-tlsfeature)", ext.Id, OIDTLSFeature)
	}
	if want := (asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}); !ext.Id.Equal(want) {
		t.Errorf("OID = %v, want 1.3.6.1.5.5.7.1.24", ext.Id)
	}
	if ext.Critical {
		t.Error("Must-Staple extension must be non-critical (RFC 7633 §6)")
	}
	if !bytes.Equal(ext.Value, mustStapleDER) {
		t.Errorf("value = % x, want % x (SEQUENCE OF INTEGER { 5 })", ext.Value, mustStapleDER)
	}
}

func TestTLSFeatureExtensionMultiValue(t *testing.T) {
	// status_request(5) + status_request_v2(17) → SEQUENCE { INTEGER 5, INTEGER 17 }.
	ext, err := TLSFeatureExtension(TLSFeatureStatusRequest, 17)
	if err != nil {
		t.Fatalf("TLSFeatureExtension: %v", err)
	}
	want := []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x11}
	if !bytes.Equal(ext.Value, want) {
		t.Errorf("value = % x, want % x", ext.Value, want)
	}
	feats, err := ParseTLSFeature(ext.Value)
	if err != nil {
		t.Fatalf("ParseTLSFeature: %v", err)
	}
	if !reflect.DeepEqual(feats, []int{5, 17}) {
		t.Errorf("features = %v, want [5 17]", feats)
	}
}

func TestTLSFeatureExtensionEmptyRejected(t *testing.T) {
	if _, err := TLSFeatureExtension(); err == nil {
		t.Error("expected an error for an empty feature list")
	}
}

func TestParseTLSFeatureRoundTrip(t *testing.T) {
	feats, err := ParseTLSFeature(mustStapleDER)
	if err != nil {
		t.Fatalf("ParseTLSFeature: %v", err)
	}
	if !reflect.DeepEqual(feats, []int{TLSFeatureStatusRequest}) {
		t.Errorf("features = %v, want [5]", feats)
	}
	if !TLSFeatureListed(feats, TLSFeatureStatusRequest) {
		t.Error("TLSFeatureListed(status_request) = false, want true")
	}
	if TLSFeatureListed(feats, 17) {
		t.Error("TLSFeatureListed(17) = true, want false")
	}
}

func TestParseTLSFeatureMalformed(t *testing.T) {
	cases := map[string][]byte{
		"not a sequence":   {0x02, 0x01, 0x05},       // bare INTEGER
		"truncated":        {0x30, 0x03, 0x02, 0x01}, // missing final byte
		"trailing bytes":   {0x30, 0x03, 0x02, 0x01, 0x05, 0xFF},
		"wrong inner type": {0x30, 0x03, 0x0C, 0x01, 0x05}, // UTF8String, not INTEGER
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTLSFeature(value); err == nil {
				t.Errorf("ParseTLSFeature(% x) = nil error, want a decode error", value)
			}
		})
	}
}
