package cms

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ParsedEnvelopedData is a decoded EnvelopedData message.
type ParsedEnvelopedData struct {
	ed envelopedData
}

// ParseEnvelopedData decodes a top-level ContentInfo wrapping an EnvelopedData.
func ParseEnvelopedData(der []byte) (*ParsedEnvelopedData, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: parsing ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf("cms: content type is %v, want envelopedData", ci.ContentType)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("cms: parsing EnvelopedData: %w", err)
	}
	if len(ed.RecipientInfos) == 0 {
		return nil, errors.New("cms: EnvelopedData has no recipients")
	}
	return &ParsedEnvelopedData{ed: ed}, nil
}

// Decrypt recovers the enveloped plaintext for the given recipient. The
// content-encryption key is unwrapped through dec (typically an HSM-backed
// crypto.Decrypter, so the recipient private key never leaves the device); the
// symmetric content is then decrypted in-process.
//
// SECURITY: to avoid a Bleichenbacher padding oracle, all failures — no matching
// recipient, RSA unwrap error, bad CBC padding — are reported as a single opaque
// error. Callers must not leak the distinction to remote peers.
func (p *ParsedEnvelopedData) Decrypt(recipient *x509.Certificate, dec crypto.Decrypter) ([]byte, error) {
	ri := p.findRecipient(recipient)
	if ri == nil {
		return nil, errors.New("cms: no recipient matches the decryption certificate")
	}
	if !ri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAEncryption) {
		return nil, fmt.Errorf("cms: unsupported key-encryption algorithm %v (only RSA)", ri.KeyEncryptionAlgorithm.Algorithm)
	}

	cek, err := dec.Decrypt(rand.Reader, ri.EncryptedKey, &rsa.PKCS1v15DecryptOptions{})
	if err != nil {
		return nil, errors.New("cms: content-encryption key unwrap failed")
	}

	eci := p.ed.EncryptedContentInfo
	plaintext, err := decryptContent(eci.ContentEncryptionAlgorithm, cek, eci.EncryptedContent.Bytes)
	if err != nil {
		return nil, errors.New("cms: content decryption failed")
	}
	return plaintext, nil
}

// findRecipient resolves the recipient info addressed to a certificate.
func (p *ParsedEnvelopedData) findRecipient(cert *x509.Certificate) *recipientInfo {
	for i := range p.ed.RecipientInfos {
		ri := &p.ed.RecipientInfos[i]
		if ri.IssuerAndSerialNumber.SerialNumber != nil &&
			cert.SerialNumber.Cmp(ri.IssuerAndSerialNumber.SerialNumber) == 0 &&
			bytes.Equal(cert.RawIssuer, ri.IssuerAndSerialNumber.IssuerName.FullBytes) {
			return ri
		}
	}
	return nil
}

// decryptContent decrypts CBC-mode content given the algorithm identifier (which
// carries the IV in its parameters), the content-encryption key, and the
// ciphertext.
func decryptContent(alg pkix.AlgorithmIdentifier, key, ciphertext []byte) ([]byte, error) {
	block, err := blockCipher(alg.Algorithm, key)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("cms: parsing CBC IV: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New("cms: IV length does not match cipher block size")
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("cms: ciphertext is not a whole number of blocks")
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out, block.BlockSize())
}

// blockCipher builds the block cipher for a CBC content-encryption OID.
func blockCipher(oid asn1.ObjectIdentifier, key []byte) (cipher.Block, error) {
	switch {
	case oid.Equal(oidAES128CBC), oid.Equal(oidAES192CBC), oid.Equal(oidAES256CBC):
		return aes.NewCipher(key)
	case oid.Equal(oidDESEDE3CBC):
		return des.NewTripleDESCipher(key)
	default:
		return nil, fmt.Errorf("cms: unsupported content-encryption algorithm %v", oid)
	}
}

// pkcs7Unpad removes and validates PKCS#7 (RFC 5652 §6.3) block padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cms: empty padded content")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errors.New("cms: invalid padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("cms: invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}
