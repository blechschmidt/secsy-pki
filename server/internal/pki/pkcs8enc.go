package pki

// Decryption of passphrase-protected private key containers (Task 194).
//
// Two legacy-facing decoders live here, both needed to read the key files a
// migrating CA actually ships with:
//
//   - DecryptPKCS8 opens an RFC 5958 "ENCRYPTED PRIVATE KEY" (PBES2 with
//     PBKDF2), which is what `openssl pkcs8 -topk8` and `openssl genpkey
//     -aes256` produce and therefore the dominant format today.
//   - decryptPEMBlock opens the older in-place PEM encryption (Proc-Type /
//     DEK-Info), which pre-3.0 `openssl genrsa -aes256` produced and which
//     still guards plenty of long-lived root keys.
//
// Both are read-only: nothing here ever *writes* an encrypted container. The
// PKI's own keys live in a provider and are never exported, so producing these
// formats would be a step backwards; consuming them is how key material stops
// living in a file.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
)

// Object identifiers from RFC 8018 (PKCS #5 v2.1) and NIST.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3   = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// encryptedPrivateKeyInfo is RFC 5958 §3.
type encryptedPrivateKeyInfo struct {
	Algo          pkix.AlgorithmIdentifier
	EncryptedData []byte
}

// pbes2Params is RFC 8018 appendix A.4.
type pbes2Params struct {
	KDF              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

// pbkdf2Params is RFC 8018 appendix A.2. Salt is modelled as the OCTET STRING
// "specified" alternative; the "otherSource" alternative is not used by any
// producer in the wild and is rejected by the unmarshal.
type pbkdf2Params struct {
	Salt      []byte
	Iter      int
	KeyLength int                      `asn1:"optional"`
	PRF       pkix.AlgorithmIdentifier `asn1:"optional"`
}

// DecryptPKCS8 decrypts an RFC 5958 EncryptedPrivateKeyInfo (the DER inside an
// "ENCRYPTED PRIVATE KEY" PEM block) and returns the plaintext PKCS#8 DER.
//
// Only PBES2/PBKDF2 is supported, with AES-128/192/256-CBC or 3DES-CBC and an
// HMAC-SHA-1/224/256/384/512 PRF — the full set OpenSSL emits. The obsolete
// PBES1 schemes are rejected by name so an operator holding one knows to
// convert it rather than seeing an opaque ASN.1 error.
func DecryptPKCS8(der []byte, passphrase []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("pki: parsing EncryptedPrivateKeyInfo: %w", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("pki: trailing data after EncryptedPrivateKeyInfo")
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("pki: unsupported private key encryption scheme %v; only PBES2 (PKCS#5 v2) is supported — convert with: openssl pkcs8 -topk8 -in key.pem -out key-pkcs8.pem", epki.Algo.Algorithm)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pki: parsing PBES2 parameters: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("pki: unsupported PBES2 key-derivation function %v; only PBKDF2 is supported", params.KDF.Algorithm)
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("pki: parsing PBKDF2 parameters: %w", err)
	}
	if kdf.Iter <= 0 {
		return nil, fmt.Errorf("pki: PBKDF2 iteration count %d is invalid", kdf.Iter)
	}

	prf, err := pbkdf2PRF(kdf.PRF)
	if err != nil {
		return nil, err
	}
	block, iv, keyLen, err := pbes2Cipher(params.EncryptionScheme)
	if err != nil {
		return nil, err
	}
	// An explicit keyLength must agree with the cipher; a mismatch would derive
	// the wrong key and surface as a padding error three steps later.
	if kdf.KeyLength != 0 && kdf.KeyLength != keyLen {
		return nil, fmt.Errorf("pki: PBKDF2 key length %d does not match the %d-byte cipher key", kdf.KeyLength, keyLen)
	}

	key := pbkdf2Key(prf, passphrase, kdf.Salt, kdf.Iter, keyLen)
	blk, err := block(key)
	if err != nil {
		return nil, fmt.Errorf("pki: initializing decryption cipher: %w", err)
	}
	if len(iv) != blk.BlockSize() {
		return nil, fmt.Errorf("pki: encryption IV is %d bytes, expected %d", len(iv), blk.BlockSize())
	}
	if len(epki.EncryptedData) == 0 || len(epki.EncryptedData)%blk.BlockSize() != 0 {
		return nil, fmt.Errorf("pki: encrypted key length %d is not a multiple of the %d-byte block size", len(epki.EncryptedData), blk.BlockSize())
	}
	plaintext := make([]byte, len(epki.EncryptedData))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plaintext, epki.EncryptedData)

	plaintext, err = stripPKCS7Padding(plaintext, blk.BlockSize())
	if err != nil {
		// Padding that does not validate means the derived key was wrong, which
		// in practice always means the passphrase was wrong.
		return nil, ErrWrongPassphrase
	}
	// Confirm the plaintext really is a PKCS#8 key: a wrong passphrase can, with
	// probability ~1/256, produce plausible padding over random bytes.
	if _, err := x509.ParsePKCS8PrivateKey(plaintext); err != nil {
		return nil, ErrWrongPassphrase
	}
	return plaintext, nil
}

// pbkdf2PRF maps a PBKDF2 prf AlgorithmIdentifier to a hash constructor. An
// absent prf means hmacWithSHA1, per the RFC 8018 DEFAULT.
func pbkdf2PRF(prf pkix.AlgorithmIdentifier) (func() hash.Hash, error) {
	switch {
	case prf.Algorithm == nil, prf.Algorithm.Equal(oidHMACWithSHA1):
		return sha1.New, nil //nolint:gosec // G505: SHA-1 here is the RFC 8018 default PRF of an existing container we must read, not a new security choice.
	case prf.Algorithm.Equal(oidHMACWithSHA224):
		return sha256.New224, nil
	case prf.Algorithm.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case prf.Algorithm.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case prf.Algorithm.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("pki: unsupported PBKDF2 PRF %v", prf.Algorithm)
	}
}

// pbes2Cipher maps a PBES2 encryptionScheme to a block-cipher constructor, its
// IV, and the key length it needs.
func pbes2Cipher(scheme pkix.AlgorithmIdentifier) (newBlock func([]byte) (cipher.Block, error), iv []byte, keyLen int, err error) {
	if _, uerr := asn1.Unmarshal(scheme.Parameters.FullBytes, &iv); uerr != nil {
		return nil, nil, 0, fmt.Errorf("pki: parsing encryption IV: %w", uerr)
	}
	switch {
	case scheme.Algorithm.Equal(oidAES128CBC):
		return aes.NewCipher, iv, 16, nil
	case scheme.Algorithm.Equal(oidAES192CBC):
		return aes.NewCipher, iv, 24, nil
	case scheme.Algorithm.Equal(oidAES256CBC):
		return aes.NewCipher, iv, 32, nil
	case scheme.Algorithm.Equal(oidDESEDE3):
		return des.NewTripleDESCipher, iv, 24, nil //nolint:gosec // G405: 3DES is the legacy default of `openssl pkcs8 -topk8`; reading such a container is the whole point of this decoder.
	default:
		return nil, nil, 0, fmt.Errorf("pki: unsupported PBES2 encryption scheme %v (supported: AES-128/192/256-CBC, DES-EDE3-CBC)", scheme.Algorithm)
	}
}

// pbkdf2Key implements PBKDF2 (RFC 8018 §5.2). It is written out here rather
// than pulled from a dependency so that the decoder behaves identically in
// FIPS and non-FIPS builds: the FIPS-validated PBKDF2 refuses the short salts
// and low iteration counts that older OpenSSL containers legitimately carry,
// which would make an operator's own root key unreadable in a FIPS deployment.
func pbkdf2Key(h func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	buf := make([]byte, 4)
	u := make([]byte, hashLen)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		t := prf.Sum(nil)
		copy(u, t)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// stripPKCS7Padding removes and validates RFC 5652 block padding in constant
// time with respect to the padding bytes' values.
func stripPKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid padding length")
	}
	var diff byte
	for _, b := range data[len(data)-pad:] {
		diff |= b ^ byte(pad)
	}
	if diff != 0 {
		return nil, errors.New("invalid padding bytes")
	}
	return data[:len(data)-pad], nil
}

// isEncryptedPEMBlock reports whether a PEM block carries the legacy in-place
// OpenSSL encryption headers (Proc-Type: 4,ENCRYPTED + DEK-Info).
func isEncryptedPEMBlock(block *pem.Block) bool {
	return x509.IsEncryptedPEMBlock(block) //nolint:staticcheck // SA1019: RFC 1423 PEM encryption is deprecated and insecure, but pre-OpenSSL-3.0 CA key files are encrypted this way and must still be readable to be migrated off.
}

// decryptPEMBlock opens a legacy DEK-Info-encrypted PEM block.
func decryptPEMBlock(block *pem.Block, passphrase []byte) ([]byte, error) {
	der, err := x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck // SA1019: see isEncryptedPEMBlock — read-only support for migrating legacy key files.
	if err != nil {
		if errors.Is(err, x509.IncorrectPasswordError) {
			return nil, ErrWrongPassphrase
		}
		return nil, fmt.Errorf("pki: decrypting legacy PEM private key: %w", err)
	}
	return der, nil
}
