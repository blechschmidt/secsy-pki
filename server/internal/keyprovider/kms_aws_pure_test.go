package keyprovider

// Unit tests for the AWS KMS translation layer: the key-spec and
// signing-algorithm mappers, the alias/URI naming, and the not-found predicate.
// All pure functions — no AWS credentials, no network.
//
// The mappers are tested as *pairs* wherever a pair exists. A key type that
// converts one way but not back is the classic drift bug: one direction learns a
// new key size, the other keeps returning an error (or worse, the wrong type),
// and a key created as one thing is then used as another.

import (
	"crypto"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// awsKeyTypes is the set of canonical key types the AWS backend claims to
// support. kmsSupportsKeyType is the authority on that set, so it is asserted
// against it below rather than being a second, drifting list.
var awsKeyTypes = []string{
	KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521,
	KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096,
}

// TestAWSKeySpecRoundTrip: every supported key type must survive
// keyType -> KeySpec -> keyType unchanged. This is the property that catches a
// mapping pair drifting apart.
func TestAWSKeySpecRoundTrip(t *testing.T) {
	for _, keyType := range awsKeyTypes {
		t.Run(keyType, func(t *testing.T) {
			if err := kmsSupportsKeyType(keyType); err != nil {
				t.Fatalf("%q is in the AWS list but the provider rejects it: %v", keyType, err)
			}
			spec, err := awsKeySpec(keyType)
			if err != nil {
				t.Fatalf("awsKeySpec(%q): %v", keyType, err)
			}
			if spec == "" {
				t.Fatal("awsKeySpec returned an empty spec with no error")
			}
			back, err := awsKeyTypeFromSpec(spec)
			if err != nil {
				t.Fatalf("awsKeyTypeFromSpec(%q): %v", spec, err)
			}
			if back != keyType {
				t.Errorf("round trip: %q -> %q -> %q", keyType, spec, back)
			}
		})
	}
}

// TestAWSKeySpecRejectsUnsupportedKeyTypes: a key type AWS KMS cannot hold as a
// sign/verify key must fail before CreateKey. An empty KeySpec sent to the API
// would create a *symmetric* key (SYMMETRIC_DEFAULT is the API default), which is
// silently useless for signing.
func TestAWSKeySpecRejectsUnsupportedKeyTypes(t *testing.T) {
	for _, keyType := range []string{
		"", " ", "RSA_2048", KeyTypeEd25519,
		KeyTypeMLDSA44, KeyTypeMLDSA65, KeyTypeMLDSA87,
		"rsa-1024", "rsa", "ecdsa", "ecdsa-sha2-nistp256 ",
	} {
		t.Run("keyType="+keyType, func(t *testing.T) {
			spec, err := awsKeySpec(keyType)
			if err == nil {
				t.Fatalf("awsKeySpec(%q) = %q, want an error", keyType, spec)
			}
			if spec != "" {
				t.Errorf("returned spec %q alongside the error", spec)
			}
		})
	}
}

// TestAWSKeyTypeFromSpecCoversEveryAPISpec walks every KeySpec the installed SDK
// knows and requires each to be either rejected or mapped to a key type that
// round-trips and that the provider actually supports. It is the reverse drift
// guard: a spec that maps to a type the rest of the code rejects (or to a
// different spec) is caught here rather than at signing time.
func TestAWSKeyTypeFromSpecCoversEveryAPISpec(t *testing.T) {
	var mapped int
	for _, spec := range (kmstypes.KeySpec("")).Values() {
		t.Run(string(spec), func(t *testing.T) {
			keyType, err := awsKeyTypeFromSpec(spec)
			if err != nil {
				if keyType != "" {
					t.Errorf("returned key type %q alongside the error", keyType)
				}
				return
			}
			mapped++
			if err := kmsSupportsKeyType(keyType); err != nil {
				t.Errorf("spec %q maps to %q, which the KMS provider rejects: %v", spec, keyType, err)
			}
			back, err := awsKeySpec(keyType)
			if err != nil {
				t.Fatalf("awsKeySpec(%q) after mapping from %q: %v", keyType, spec, err)
			}
			if back != spec {
				t.Errorf("round trip: %q -> %q -> %q", spec, keyType, back)
			}
		})
	}
	if mapped != len(awsKeyTypes) {
		t.Errorf("awsKeyTypeFromSpec accepted %d specs, want %d (one per supported key type)", mapped, len(awsKeyTypes))
	}
}

// TestAWSKeyTypeFromSpecRejectsNonSigningSpecs names the specs that must never be
// mistaken for an asymmetric signing key: a symmetric or HMAC key reported as
// "rsa-2048" would be handed to the x509 signing path, and an unexpected curve
// (secp256k1, SM2) is not something this PKI issues from.
func TestAWSKeyTypeFromSpecRejectsNonSigningSpecs(t *testing.T) {
	for _, spec := range []kmstypes.KeySpec{
		kmstypes.KeySpecSymmetricDefault,
		kmstypes.KeySpecHmac224, kmstypes.KeySpecHmac256,
		kmstypes.KeySpecHmac384, kmstypes.KeySpecHmac512,
		kmstypes.KeySpecSm2,
		kmstypes.KeySpecEccSecgP256k1,
		kmstypes.KeySpec(""),
		kmstypes.KeySpec("RSA_8192"),
	} {
		t.Run(string(spec), func(t *testing.T) {
			keyType, err := awsKeyTypeFromSpec(spec)
			if err == nil {
				t.Fatalf("awsKeyTypeFromSpec(%q) = %q, want an error", spec, keyType)
			}
			if keyType != "" {
				t.Errorf("returned %q alongside the error", keyType)
			}
		})
	}
}

// TestAWSSigningAlgorithm pins every (key family, digest, PSS) combination onto
// its KMS signing algorithm, and checks the padding scheme matches the request:
// answering RSASSA_PKCS1_V1_5 for a PSS request produces a signature that does
// not match the algorithm identifier in the certificate it signs.
func TestAWSSigningAlgorithm(t *testing.T) {
	valid := map[kmstypes.SigningAlgorithmSpec]bool{}
	for _, a := range (kmstypes.SigningAlgorithmSpec("")).Values() {
		valid[a] = true
	}

	for _, keyType := range []string{KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096} {
		for _, tc := range []struct {
			hash crypto.Hash
			pss  bool
			want kmstypes.SigningAlgorithmSpec
		}{
			{crypto.SHA256, false, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
			{crypto.SHA384, false, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384},
			{crypto.SHA512, false, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
			{crypto.SHA256, true, kmstypes.SigningAlgorithmSpecRsassaPssSha256},
			{crypto.SHA384, true, kmstypes.SigningAlgorithmSpecRsassaPssSha384},
			{crypto.SHA512, true, kmstypes.SigningAlgorithmSpecRsassaPssSha512},
		} {
			t.Run(fmt.Sprintf("%s/%v/pss=%v", keyType, tc.hash, tc.pss), func(t *testing.T) {
				got, err := awsSigningAlgorithm(keyType, tc.hash, tc.pss)
				if err != nil {
					t.Fatalf("awsSigningAlgorithm: %v", err)
				}
				if got != tc.want {
					t.Fatalf("algorithm = %q, want %q", got, tc.want)
				}
				if !valid[got] {
					t.Errorf("algorithm %q is not a value the installed KMS API accepts", got)
				}
				if tc.pss != strings.Contains(string(got), "PSS") {
					t.Errorf("pss=%v produced %q: the padding scheme does not match the request", tc.pss, got)
				}
				// The digest in the algorithm name must be the digest requested, or
				// KMS hashes a digest of the wrong length and rejects (or worse).
				if !strings.HasSuffix(string(got), digestSuffix(tc.hash)) {
					t.Errorf("algorithm %q does not name the requested digest %v", got, tc.hash)
				}
			})
		}
	}
	for _, keyType := range []string{KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521} {
		for _, tc := range []struct {
			hash crypto.Hash
			want kmstypes.SigningAlgorithmSpec
		}{
			{crypto.SHA256, kmstypes.SigningAlgorithmSpecEcdsaSha256},
			{crypto.SHA384, kmstypes.SigningAlgorithmSpecEcdsaSha384},
			{crypto.SHA512, kmstypes.SigningAlgorithmSpecEcdsaSha512},
		} {
			t.Run(fmt.Sprintf("%s/%v", keyType, tc.hash), func(t *testing.T) {
				got, err := awsSigningAlgorithm(keyType, tc.hash, false)
				if err != nil {
					t.Fatalf("awsSigningAlgorithm: %v", err)
				}
				if got != tc.want {
					t.Errorf("algorithm = %q, want %q", got, tc.want)
				}
				if !valid[got] {
					t.Errorf("algorithm %q is not a value the installed KMS API accepts", got)
				}
				// An ECDSA key must not be routed to an RSA-PSS algorithm just because
				// the caller passed *rsa.PSSOptions.
				pssGot, err := awsSigningAlgorithm(keyType, tc.hash, true)
				if err != nil {
					t.Fatalf("awsSigningAlgorithm(pss=true): %v", err)
				}
				if pssGot != tc.want {
					t.Errorf("pss=true on an ECDSA key changed the algorithm to %q", pssGot)
				}
			})
		}
	}
}

// digestSuffix is the digest fragment KMS algorithm names end with.
func digestSuffix(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "SHA_256"
	case crypto.SHA384:
		return "SHA_384"
	case crypto.SHA512:
		return "SHA_512"
	default:
		return "?"
	}
}

// TestAWSSigningAlgorithmRejectsUnsupportedHash: a digest KMS has no algorithm
// for must fail locally rather than send an empty SigningAlgorithm.
func TestAWSSigningAlgorithmRejectsUnsupportedHash(t *testing.T) {
	for _, keyType := range []string{KeyTypeRSA2048, KeyTypeECDSAP256} {
		for _, hash := range []crypto.Hash{crypto.Hash(0), crypto.SHA1, crypto.SHA224, crypto.MD5, crypto.SHA3_256} {
			for _, pss := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%v/pss=%v", keyType, hash, pss), func(t *testing.T) {
					got, err := awsSigningAlgorithm(keyType, hash, pss)
					if err == nil {
						t.Fatalf("awsSigningAlgorithm(%q, %v) = %q, want an error", keyType, hash, got)
					}
					if got != "" {
						t.Errorf("returned %q alongside the error", got)
					}
				})
			}
		}
	}
}

// TestAWSAliasName holds aliasName to the KMS alias charset. '/' has to survive
// (the documented key_prefix form is "secsy/"), everything outside
// [A-Za-z0-9/_-] has to become '_', and the result must always carry the
// "alias/" prefix — an alias that does not is not an alias, and DescribeKey then
// looks up a key id instead.
func TestAWSAliasName(t *testing.T) {
	allowed := regexp.MustCompile(`^alias/[A-Za-z0-9/_-]*$`)
	for _, tc := range []struct {
		prefix, label, want string
	}{
		{"", "ca-root", "alias/ca-root"},
		{"secsy/", "ca-root", "alias/secsy/ca-root"},
		{"secsy/", "ca root", "alias/secsy/ca_root"},
		{"", "tenant.1:key", "alias/tenant_1_key"},
		{"", "under_score-ok/nested", "alias/under_score-ok/nested"},
		{"", "trailing\n", "alias/trailing_"},
		{"secsy/", "", "alias/secsy/"},
		// One underscore per *rune*: byte-wise sanitization would emit two for a
		// two-byte rune and change the alias length.
		{"", "café", "alias/caf_"},
		{"", "日本", "alias/__"},
	} {
		t.Run(tc.prefix+"|"+tc.label, func(t *testing.T) {
			b := &awsKMSBackend{prefix: tc.prefix}
			got := b.aliasName(tc.label)
			if got != tc.want {
				t.Errorf("aliasName(%q) with prefix %q = %q, want %q", tc.label, tc.prefix, got, tc.want)
			}
			if !allowed.MatchString(got) {
				t.Errorf("aliasName(%q) = %q contains characters AWS rejects in an alias", tc.label, got)
			}
		})
	}

	// ListKeys strips "alias/" + prefix to recover the label, so a sanitized label
	// must survive that round trip for the keys the backend itself created.
	b := &awsKMSBackend{prefix: "secsy/"}
	alias := b.aliasName("ca-root")
	if got := strings.TrimPrefix(alias, "alias/"+b.prefix); got != "ca-root" {
		t.Errorf("label recovered from %q = %q, want %q", alias, got, "ca-root")
	}
}

func TestAWSKMSURI(t *testing.T) {
	for _, keyID := range []string{
		"1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"",
	} {
		if got, want := awsKMSURI(keyID), "kms:aws:"+keyID; got != want {
			t.Errorf("awsKMSURI(%q) = %q, want %q", keyID, got, want)
		}
	}
}

// TestIsAWSNotFound: ResolveKey turns a not-found into ErrKeyNotFound and
// CreateKey treats it as "the alias is free", so any *other* failure — a denied
// permission, a key pending deletion, a throttle — must not read as not-found. A
// misclassified error there tells the caller the CA key does not exist.
func TestIsAWSNotFound(t *testing.T) {
	notFound := &kmstypes.NotFoundException{Message: awsString("Alias arn:aws:kms:...:alias/secsy/ca is not found")}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"NotFoundException", notFound, true},
		{"NotFoundException wrapped by the caller", fmt.Errorf("checking AWS KMS key %q: %w", "ca", notFound), true},
		{"doubly wrapped", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", notFound)), true},
		{"AccessDenied", &kmstypes.KMSInvalidStateException{Message: awsString("key is pending deletion")}, false},
		{"DisabledException", &kmstypes.DisabledException{Message: awsString("key is disabled")}, false},
		{"InvalidArn", &kmstypes.InvalidArnException{Message: awsString("bad arn")}, false},
		{"plain error mentioning not found", errors.New("dial tcp: host not found"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAWSNotFound(tc.err); got != tc.want {
				t.Errorf("isAWSNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func awsString(s string) *string { return &s }
