package ers

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// clockSkew tolerates modest drift between the TSA and the verifier when judging
// whether a token's genTime lies in the future.
const clockSkew = 5 * time.Minute

// VerifyOptions parameterizes Verify.
type VerifyOptions struct {
	// Objects are the protected data objects to prove coverage for. They must be
	// the exact bytes the record was generated over. When empty, only the
	// structural integrity (timestamps, chain linkage, ordering) is checked.
	Objects []DataObject
	// Roots, when non-empty, are the trust anchors the TSA certificate of every
	// token must chain to at its genTime. When empty the certificate-path step is
	// skipped (token integrity is still fully checked), matching how
	// `openssl ts -verify` separates token integrity from trust.
	Roots []*x509.Certificate
	// Now is the verification instant (defaults to time.Now); tokens may not be
	// dated in its future.
	Now time.Time
}

// ObjectResult is the per-object coverage outcome.
type ObjectResult struct {
	ID      string `json:"id"`
	Covered bool   `json:"covered"`
	Reason  string `json:"reason,omitempty"`
}

// ChainResult is the per-ArchiveTimeStampChain outcome.
type ChainResult struct {
	Index      int       `json:"index"`
	Hash       string    `json:"hash"`
	Timestamps int       `json:"timestamps"`
	Valid      bool      `json:"valid"`
	Reason     string    `json:"reason,omitempty"`
	FirstGen   time.Time `json:"first_gen_time"`
	LastGen    time.Time `json:"last_gen_time"`
}

// VerifyResult is the outcome of Verify.
type VerifyResult struct {
	Valid         bool           `json:"valid"`
	Reason        string         `json:"reason,omitempty"`
	Chains        []ChainResult  `json:"chains"`
	Objects       []ObjectResult `json:"objects,omitempty"`
	FirstGenTime  time.Time      `json:"first_gen_time"`
	LatestGenTime time.Time      `json:"latest_gen_time"`
}

// Verify checks an EvidenceRecord end to end (RFC 4998 §4.3 and §5.3):
//
//   - Every embedded RFC 3161 token verifies: CMS signature by the TSA
//     certificate it carries, time-stamping EKU, a genTime not in the future,
//     and — when Roots are supplied — a certificate path to a trust anchor.
//   - Each ArchiveTimeStamp's reduced hash tree recomputes to its token's
//     message imprint under the chain's hash algorithm.
//   - Within a chain, each ArchiveTimeStamp after the first covers the previous
//     token (time-stamp renewal linkage).
//   - Each protected object is provable in the first ArchiveTimeStamp of the
//     first chain, and — across every hash-tree renewal — in the first
//     ArchiveTimeStamp of each later chain (which re-binds the objects and all
//     prior chains under the new algorithm).
//   - genTimes are strictly non-decreasing across the whole sequence.
func Verify(er *EvidenceRecord, opts VerifyOptions) (*VerifyResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	seq := er.wire.ArchiveTimeStampSequence
	if len(seq) == 0 {
		return &VerifyResult{Valid: false, Reason: "evidence record contains no archive timestamp"}, nil
	}

	res := &VerifyResult{Valid: true}
	// Per-object coverage accumulates across chains: an object stays covered only
	// if every chain (initial + each hash-tree renewal) re-proves it.
	objCovered := make([]bool, len(opts.Objects))
	objReason := make([]string, len(opts.Objects))
	for i := range objCovered {
		objCovered[i] = true
	}

	var lastGenOverall time.Time
	for ci, chain := range seq {
		cr := ChainResult{Index: ci, Timestamps: len(chain), Valid: true}
		hash, err := chainHashAlg(chain)
		if err != nil {
			cr.Valid, cr.Reason = false, err.Error()
			res.Valid, res.Reason = false, fmt.Sprintf("chain %d: %v", ci, err)
			res.Chains = append(res.Chains, cr)
			continue
		}
		cr.Hash = HashName(hash)

		// The "entry leaves" the first ArchiveTimeStamp of this chain must cover.
		entryLeaves, err := er.entryLeaves(ci, hash, opts.Objects)
		if err != nil {
			cr.Valid, cr.Reason = false, err.Error()
			res.Valid, res.Reason = false, fmt.Sprintf("chain %d: %v", ci, err)
			res.Chains = append(res.Chains, cr)
			continue
		}

		var prevToken []byte
		var lastGenChain time.Time
		for j, ats := range chain {
			imprintHash, imprintVal, genTime, verr := verifyToken(ats.TimeStamp.FullBytes, opts.Roots, now)
			if verr != nil {
				cr.Valid, cr.Reason = false, fmt.Sprintf("timestamp %d: %v", j, verr)
				break
			}
			if imprintHash != hash {
				cr.Valid, cr.Reason = false, fmt.Sprintf("timestamp %d: imprint hash %v differs from chain hash %v", j, imprintHash, hash)
				break
			}

			// Determine which leaf(s) this ArchiveTimeStamp must reduce from.
			var members [][]byte
			if j == 0 {
				members = entryLeaves
			} else {
				// Time-stamp renewal: the sole member is H(previous token).
				members = [][]byte{leafHash(hash, prevToken)}
			}
			if err := checkReduction(hash, ats.ReducedHashtree, members, imprintVal); err != nil {
				cr.Valid, cr.Reason = false, fmt.Sprintf("timestamp %d: %v", j, err)
				break
			}

			if !genTime.IsZero() {
				if cr.FirstGen.IsZero() {
					cr.FirstGen = genTime
				}
				cr.LastGen = genTime
				if res.FirstGenTime.IsZero() || genTime.Before(res.FirstGenTime) {
					res.FirstGenTime = genTime
				}
				if genTime.After(res.LatestGenTime) {
					res.LatestGenTime = genTime
				}
				// genTimes must not run backwards across the whole sequence.
				if genTime.Add(clockSkew).Before(lastGenOverall) {
					cr.Valid, cr.Reason = false, fmt.Sprintf("timestamp %d: genTime %s precedes an earlier timestamp", j, genTime.UTC().Format(time.RFC3339))
					break
				}
				lastGenChain = genTime
				lastGenOverall = genTime
			}
			prevToken = ats.TimeStamp.FullBytes
		}
		_ = lastGenChain

		// Fold this chain's coverage into the per-object accumulators. A chain that
		// fails structurally revokes coverage for every object.
		for i := range opts.Objects {
			if !cr.Valid {
				objCovered[i] = false
				if objReason[i] == "" {
					objReason[i] = fmt.Sprintf("chain %d invalid", ci)
				}
				continue
			}
			leaf := entryLeaves[i]
			if !containsHash(firstList(chain), leaf) {
				objCovered[i] = false
				if objReason[i] == "" {
					objReason[i] = fmt.Sprintf("not present in chain %d", ci)
				}
			}
		}

		if !cr.Valid && res.Valid {
			res.Valid, res.Reason = false, fmt.Sprintf("chain %d: %s", ci, cr.Reason)
		}
		res.Chains = append(res.Chains, cr)
	}

	for i, o := range opts.Objects {
		res.Objects = append(res.Objects, ObjectResult{ID: o.ID, Covered: objCovered[i], Reason: objReason[i]})
		if !objCovered[i] {
			if res.Valid {
				res.Valid, res.Reason = false, fmt.Sprintf("object %q not covered: %s", o.ID, objReason[i])
			}
		}
	}
	return res, nil
}

// entryLeaves computes the leaf hashes the first ArchiveTimeStamp of chain ci
// must cover under hash: for the initial chain, H(object); for a hash-tree
// renewal chain, H_new(H_new(object) || H_new(atsc)) where atsc is the DER
// concatenation of all prior chains (RFC 4998 §5.2).
func (er *EvidenceRecord) entryLeaves(ci int, hash crypto.Hash, objects []DataObject) ([][]byte, error) {
	leaves := make([][]byte, len(objects))
	if ci == 0 {
		for i, o := range objects {
			leaves[i] = leafHash(hash, o.Bytes)
		}
		return leaves, nil
	}
	prevSeqBytes, err := previousSequenceBytes(er.wire.ArchiveTimeStampSequence[:ci])
	if err != nil {
		return nil, err
	}
	ha := leafHash(hash, prevSeqBytes)
	for i, o := range objects {
		hi := leafHash(hash, o.Bytes)
		leaves[i] = leafHash(hash, append(append([]byte{}, hi...), ha...))
	}
	return leaves, nil
}

// checkReduction verifies that every member appears in the reduced hash tree's
// first list and that the reduction recomputes to the token's message imprint.
func checkReduction(hash crypto.Hash, reduced []partialHashtree, members [][]byte, imprint []byte) error {
	if len(reduced) == 0 {
		// No reduced hash tree: the token must cover a single member directly.
		if len(members) != 1 {
			return fmt.Errorf("archive timestamp omits the reduced hash tree but covers %d objects", len(members))
		}
		if !bytes.Equal(members[0], imprint) {
			return fmt.Errorf("timestamp imprint does not match the single protected object")
		}
		return nil
	}
	for _, m := range members {
		if !containsHash(reduced[0], m) {
			return fmt.Errorf("protected object is absent from the reduced hash tree")
		}
	}
	root, err := recomputeRoot(hash, members[0], reduced)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, imprint) {
		return fmt.Errorf("recomputed hash-tree root does not match the timestamp imprint")
	}
	return nil
}

// firstList returns the first ArchiveTimeStamp's first reduced-hash-tree list,
// or nil when the chain/tree is empty. It is where a chain's entry leaves live.
func firstList(chain archiveTimeStampChain) [][]byte {
	if len(chain) == 0 || len(chain[0].ReducedHashtree) == 0 {
		return nil
	}
	return chain[0].ReducedHashtree[0]
}

// verifyToken validates one embedded RFC 3161 token: CMS signature by its
// embedded TSA certificate, time-stamping EKU, a genTime plausibility bound,
// and (when roots are supplied) a certificate path at genTime. It returns the
// message-imprint hash and value and the genTime.
func verifyToken(token []byte, roots []*x509.Certificate, now time.Time) (crypto.Hash, []byte, time.Time, error) {
	if len(token) == 0 {
		return 0, nil, time.Time{}, ErrNoTimestamp
	}
	parsed, err := cms.ParseSignedData(token)
	if err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("parsing timestamp token: %w", err)
	}
	if err := parsed.Verify(); err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("timestamp token signature: %w", err)
	}
	cert := parsed.SignerCertificate()
	if cert == nil {
		return 0, nil, time.Time{}, fmt.Errorf("timestamp token does not embed the TSA certificate")
	}

	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		return 0, nil, time.Time{}, err
	}
	if !info.Hash.Available() {
		return 0, nil, time.Time{}, fmt.Errorf("token imprint hash %v is not available", info.Hash)
	}
	genTime := info.GenTime.UTC()
	if genTime.After(now.Add(clockSkew)) {
		return 0, nil, time.Time{}, fmt.Errorf("token genTime %s is in the future", genTime.Format(time.RFC3339))
	}

	hasTS := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTS = true
		}
	}
	if !hasTS {
		return 0, nil, time.Time{}, fmt.Errorf("token signer lacks the id-kp-timeStamping extended key usage")
	}

	if len(roots) > 0 {
		rootPool := x509.NewCertPool()
		for _, r := range roots {
			rootPool.AddCert(r)
		}
		interPool := x509.NewCertPool()
		for _, c := range parsed.Certificates {
			if !bytes.Equal(c.Raw, cert.Raw) {
				interPool.AddCert(c)
			}
		}
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: interPool,
			CurrentTime:   genTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}); err != nil {
			return 0, nil, time.Time{}, fmt.Errorf("TSA certificate chain: %w", err)
		}
	}
	return info.Hash, info.HashedMessage, genTime, nil
}
