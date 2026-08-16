package yubihsm

import "fmt"

// YubiHSM algorithm identifiers.
//
// The device reports the algorithm of every stored object, and the list of
// algorithms it supports, as these one-byte ids. The names are the ones Yubico's
// tooling uses, so an operator reading `secsy-ca hsm-attest list` sees the same
// strings as in the YubiHSM documentation.
//
// The table is dense and contiguous from 1, which the hardware confirms: a
// YubiHSM 2 on firmware 2.4.0 reports exactly ids 1 through 55, in this order.
var algorithmNames = [...]string{
	1:  "rsa-pkcs1-sha1",
	2:  "rsa-pkcs1-sha256",
	3:  "rsa-pkcs1-sha384",
	4:  "rsa-pkcs1-sha512",
	5:  "rsa-pss-sha1",
	6:  "rsa-pss-sha256",
	7:  "rsa-pss-sha384",
	8:  "rsa-pss-sha512",
	9:  "rsa2048",
	10: "rsa3072",
	11: "rsa4096",
	12: "ecp256",
	13: "ecp384",
	14: "ecp521",
	15: "eck256",
	16: "ecbp256",
	17: "ecbp384",
	18: "ecbp512",
	19: "hmac-sha1",
	20: "hmac-sha256",
	21: "hmac-sha384",
	22: "hmac-sha512",
	23: "ecdsa-sha1",
	24: "ecdh",
	25: "rsa-oaep-sha1",
	26: "rsa-oaep-sha256",
	27: "rsa-oaep-sha384",
	28: "rsa-oaep-sha512",
	29: "aes128-ccm-wrap",
	30: "opaque-data",
	31: "opaque-x509-certificate",
	32: "mgf1-sha1",
	33: "mgf1-sha256",
	34: "mgf1-sha384",
	35: "mgf1-sha512",
	36: "template-ssh",
	37: "aes128-yubico-otp",
	38: "aes128-yubico-authentication",
	39: "aes192-yubico-otp",
	40: "aes256-yubico-otp",
	41: "aes192-ccm-wrap",
	42: "aes256-ccm-wrap",
	43: "ecdsa-sha256",
	44: "ecdsa-sha384",
	45: "ecdsa-sha512",
	46: "ed25519",
	47: "ecp224",
	48: "rsa-pkcs1-decrypt",
	49: "ecp256-yubico-authentication",
	50: "aes128",
	51: "aes192",
	52: "aes256",
	53: "aes-ecb",
	54: "aes-cbc",
	55: "aes-kwp",
}

// Algorithm identifiers this codebase refers to by name.
const (
	AlgorithmECP256  byte = 12
	AlgorithmEd25519 byte = 46
)

// AlgorithmName renders an algorithm identifier. An id this build does not know
// is reported as its number rather than as an empty string, so a key on newer
// firmware is still identifiable in an inventory listing.
func AlgorithmName(id byte) string {
	if int(id) < len(algorithmNames) && algorithmNames[id] != "" {
		return algorithmNames[id]
	}
	return fmt.Sprintf("algorithm-%d", id)
}
