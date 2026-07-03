package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// testECDSACert builds a self-signed ECDSA P-256 certificate + key.
func testECDSACert(t *testing.T, cn string, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func TestDetachedSignedDataRoundTrip(t *testing.T) {
	content := []byte("release artifact bytes")

	rsaCert, rsaKey := testRSACert(t, "rsa-signer", 10)
	ecCert, ecKey := testECDSACert(t, "ec-signer", 11)

	cases := []struct {
		name   string
		cert   *x509.Certificate
		signer crypto.Signer
	}{
		{"rsa", rsaCert, rsaKey},
		{"ecdsa", ecCert, ecKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := BuildSignedData(SignedDataOpts{
				Content:    content,
				Detached:   true,
				SignerCert: tc.cert,
				Signer:     tc.signer,
			})
			if err != nil {
				t.Fatalf("BuildSignedData: %v", err)
			}

			p, err := ParseSignedData(der)
			if err != nil {
				t.Fatalf("ParseSignedData: %v", err)
			}
			if len(p.Content) != 0 {
				t.Fatalf("detached message embeds eContent (%d bytes)", len(p.Content))
			}
			if err := p.VerifyDetached(content); err != nil {
				t.Fatalf("VerifyDetached: %v", err)
			}
			if p.SignerCertificate() == nil || p.SignerCertificate().SerialNumber.Cmp(tc.cert.SerialNumber) != 0 {
				t.Error("signer certificate not resolved")
			}

			// Digest-based verification of the same message.
			sum := sha256.Sum256(content)
			p2, _ := ParseSignedData(der)
			if err := p2.VerifyDetachedDigest(sum[:]); err != nil {
				t.Fatalf("VerifyDetachedDigest: %v", err)
			}

			// Tampered content and truncated digest must fail.
			p3, _ := ParseSignedData(der)
			if err := p3.VerifyDetached(append([]byte("x"), content...)); err == nil {
				t.Fatal("VerifyDetached accepted tampered content")
			}
			p4, _ := ParseSignedData(der)
			if err := p4.VerifyDetachedDigest(sum[:16]); err == nil {
				t.Fatal("VerifyDetachedDigest accepted a digest of the wrong length")
			}
		})
	}
}

func TestDetachedSignedDataByDigest(t *testing.T) {
	cert, key := testECDSACert(t, "digest-signer", 20)
	content := []byte("huge artifact that is only available as a digest")
	sum := sha256.Sum256(content)

	// Sign by digest: no content passes through the builder.
	der, err := BuildSignedData(SignedDataOpts{
		ContentDigest: sum[:],
		Detached:      true,
		Digest:        crypto.SHA256,
		SignerCert:    cert,
		Signer:        key,
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	// Yet the signature verifies against the full content.
	p, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := p.VerifyDetached(content); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}

	// ContentDigest without Detached is rejected, as is a wrong-length digest.
	if _, err := BuildSignedData(SignedDataOpts{ContentDigest: sum[:], SignerCert: cert, Signer: key}); err == nil {
		t.Fatal("BuildSignedData accepted ContentDigest without Detached")
	}
	if _, err := BuildSignedData(SignedDataOpts{ContentDigest: sum[:12], Detached: true, SignerCert: cert, Signer: key}); err == nil {
		t.Fatal("BuildSignedData accepted a truncated ContentDigest")
	}
}

func TestVerifyDetachedRejectsAttachedMessage(t *testing.T) {
	cert, key := testRSACert(t, "attached", 30)
	content := []byte("embedded payload")
	der, err := BuildSignedData(SignedDataOpts{Content: content, SignerCert: cert, Signer: key})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	p, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := p.VerifyDetached([]byte("attacker-chosen")); err == nil {
		t.Fatal("VerifyDetached ran on an attached message")
	}
	if err := p.VerifyDetachedDigest(bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("VerifyDetachedDigest ran on an attached message")
	}
}

// TestContentTypeAttributeMismatch hand-assembles a SignedData whose signed
// content-type attribute names a different type than the eContentType — the
// cross-context substitution RFC 5652 §5.6 exists to stop — and confirms
// verification fails closed.
func TestContentTypeAttributeMismatch(t *testing.T) {
	cert, key := testRSACert(t, "ct-mismatch", 50)
	content := []byte("payload")
	otherType := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} // id-ct-TSTInfo

	// Build a valid message whose signed content-type attribute is otherType…
	der, err := BuildSignedData(SignedDataOpts{
		Content:     content,
		ContentType: otherType,
		SignerCert:  cert,
		Signer:      key,
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	// …then rewrite the transmitted eContentType to plain data without touching
	// the signed attributes (the attacker-controlled, unsigned part).
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	sd.ContentInfo.ContentType = oidData
	tampered, err := wrapContentInfo(oidSignedData, sd)
	if err != nil {
		t.Fatal(err)
	}

	p, err := ParseSignedData(tampered)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := p.Verify(); err == nil {
		t.Fatal("Verify accepted a content-type attribute that contradicts the eContentType")
	}
}

func TestUnauthenticatedAttributes(t *testing.T) {
	cert, key := testRSACert(t, "unauth", 40)
	content := []byte("artifact")
	tokenOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	var seenSig []byte
	der, err := BuildSignedData(SignedDataOpts{
		Content:    content,
		Detached:   true,
		SignerCert: cert,
		Signer:     key,
		UnauthAttrsFunc: func(sig []byte) ([]Attribute, error) {
			seenSig = append([]byte(nil), sig...)
			// Stand-in for a timestamp token: any DER value works at this layer.
			return []Attribute{{Type: tokenOID, Value: sig}}, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	p, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := p.VerifyDetached(content); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if !bytes.Equal(p.Signature(), seenSig) {
		t.Error("Signature() does not return the signature the unauth-attrs callback saw")
	}
	raw, ok := p.UnauthenticatedAttribute(tokenOID)
	if !ok {
		t.Fatal("unauthenticated attribute not found")
	}
	var got []byte
	if _, err := asn1.Unmarshal(raw.FullBytes, &got); err != nil {
		t.Fatalf("unmarshal attribute value: %v", err)
	}
	if !bytes.Equal(got, seenSig) {
		t.Error("unauthenticated attribute value round-trip mismatch")
	}
}
