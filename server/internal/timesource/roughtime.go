package timesource

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Roughtime is a UDP time protocol in which the server signs its response with
// an Ed25519 key, so the returned time is unforgeable by an on-path attacker and
// verifiable offline against the server's published long-term public key. This
// implements the classic Google/Cloudflare wire format (64-byte nonce, SHA-512
// Merkle tree, MIDP/RADI in microseconds), which the public Roughtime servers
// deploy. The signature chain is: the server's long-term key signs a delegated
// key (DELE) with a validity window, and the delegated key signs the response
// (SREP); the client's nonce is proven to be in the response via a Merkle path.
//
// The full verification path (message parse, Merkle, both Ed25519 signatures,
// delegation-window check) is exercised end to end in roughtime_test.go against
// a locally-constructed, correctly-signed response — so the verifier is tested
// even though a live server is not reachable from unit tests.

// Roughtime signature contexts and tags (classic format).
const (
	roughtimeCertContext     = "RoughTime v1 delegation signature--\x00"
	roughtimeResponseContext = "RoughTime v1 response signature\x00"
	roughtimeNonceLen        = 64
	roughtimeMinRequestLen   = 1024
	roughtimeHashLen         = sha512.Size // 64
)

// Roughtime tag identifiers (4 ASCII bytes, compared as little-endian uint32).
var (
	tagSIG  = rtTag("SIG\x00")
	tagNONC = rtTag("NONC")
	tagDELE = rtTag("DELE")
	tagPATH = rtTag("PATH")
	tagRADI = rtTag("RADI")
	tagPUBK = rtTag("PUBK")
	tagMIDP = rtTag("MIDP")
	tagSREP = rtTag("SREP")
	tagMINT = rtTag("MINT")
	tagROOT = rtTag("ROOT")
	tagCERT = rtTag("CERT")
	tagMAXT = rtTag("MAXT")
	tagINDX = rtTag("INDX")
	tagPAD  = rtTag("PAD\xff")
)

func rtTag(s string) uint32 { return binary.LittleEndian.Uint32([]byte(s)) }

// decodeEd25519PublicKey decodes a 32-byte Ed25519 public key from base64
// (standard or URL, padded or raw) or hex. Because a 64-character hex string is
// also valid base64 (decoding to 48 bytes), it collects every valid decoding and
// prefers the one of the correct length rather than the first that parses.
func decodeEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty public key")
	}
	var candidates [][]byte
	if b, err := hex.DecodeString(s); err == nil {
		candidates = append(candidates, b)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			candidates = append(candidates, b)
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("public key is not valid base64 or hex")
	}
	for _, b := range candidates {
		if len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(candidates[0]))
}

// RoughtimeServer configures one Roughtime server.
type RoughtimeServer struct {
	Name      string        // label for metrics/audit; defaults to Address
	Address   string        // UDP endpoint (host:port)
	PublicKey string        // server long-term Ed25519 public key (base64 or hex)
	Timeout   time.Duration // per-query timeout; defaults to 5s
}

// roughtimeProvider queries one Roughtime server.
type roughtimeProvider struct {
	name      string
	address   string
	publicKey ed25519.PublicKey
	timeout   time.Duration
}

// NewRoughtimeProvider builds a Roughtime Provider for one server.
func NewRoughtimeProvider(s RoughtimeServer) (Provider, error) {
	key, err := decodeEd25519PublicKey(s.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("roughtime: %w", err)
	}
	if _, _, err := net.SplitHostPort(s.Address); err != nil {
		return nil, fmt.Errorf("roughtime: address %q must be host:port: %w", s.Address, err)
	}
	name := s.Name
	if name == "" {
		name = s.Address
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &roughtimeProvider{name: name, address: s.Address, publicKey: key, timeout: timeout}, nil
}

func (p *roughtimeProvider) Name() string { return p.name }

// Now sends one Roughtime request and verifies the signed response.
func (p *roughtimeProvider) Now(ctx context.Context) (Reading, error) {
	nonce := make([]byte, roughtimeNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return Reading{}, err
	}
	request := buildRoughtimeRequest(nonce)

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", p.address)
	if err != nil {
		return Reading{}, fmt.Errorf("roughtime: dialing server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(p.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	t1 := time.Now()
	if _, err := conn.Write(request); err != nil {
		return Reading{}, fmt.Errorf("roughtime: sending request: %w", err)
	}
	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	t4 := time.Now()
	if err != nil {
		return Reading{}, fmt.Errorf("roughtime: reading response: %w", err)
	}

	midp, radius, err := verifyRoughtimeResponse(resp[:n], nonce, p.publicKey)
	if err != nil {
		return Reading{}, fmt.Errorf("roughtime: %w", err)
	}

	rtt := t4.Sub(t1)
	if rtt < 0 {
		rtt = 0
	}
	midpoint := t1.Add(rtt / 2)
	return Reading{Time: midp, Offset: midpoint.Sub(midp), RTT: rtt, Uncertainty: radius}, nil
}

// buildRoughtimeRequest builds a request carrying the nonce, padded to the
// minimum request size to prevent the server from being an amplification vector.
func buildRoughtimeRequest(nonce []byte) []byte {
	msg := encodeRoughtimeMessage(map[uint32][]byte{tagNONC: nonce})
	if len(msg) < roughtimeMinRequestLen {
		pad := make([]byte, roughtimeMinRequestLen-len(msg))
		msg = encodeRoughtimeMessage(map[uint32][]byte{tagNONC: nonce, tagPAD: pad})
	}
	return msg
}

// verifyRoughtimeResponse validates the full signed response and returns the
// midpoint time and radius. It fails closed on any signature, Merkle, or
// delegation-window failure — the guarantee that the time is authentic.
func verifyRoughtimeResponse(resp, nonce []byte, longTermKey ed25519.PublicKey) (time.Time, time.Duration, error) {
	top, err := decodeRoughtimeMessage(resp)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parsing response: %w", err)
	}
	certBytes, ok := top[tagCERT]
	if !ok {
		return time.Time{}, 0, errors.New("response missing CERT")
	}
	srepBytes, ok := top[tagSREP]
	if !ok {
		return time.Time{}, 0, errors.New("response missing SREP")
	}
	sig, ok := top[tagSIG]
	if !ok || len(sig) != ed25519.SignatureSize {
		return time.Time{}, 0, errors.New("response missing or malformed SIG")
	}
	indxBytes, ok := top[tagINDX]
	if !ok || len(indxBytes) != 4 {
		return time.Time{}, 0, errors.New("response missing or malformed INDX")
	}
	path := top[tagPATH] // may be empty (single-leaf tree)

	// 1. Long-term key certifies the delegated key (over the DELE bytes).
	cert, err := decodeRoughtimeMessage(certBytes)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parsing CERT: %w", err)
	}
	deleBytes, ok := cert[tagDELE]
	if !ok {
		return time.Time{}, 0, errors.New("CERT missing DELE")
	}
	certSig, ok := cert[tagSIG]
	if !ok || len(certSig) != ed25519.SignatureSize {
		return time.Time{}, 0, errors.New("CERT missing or malformed SIG")
	}
	if !ed25519.Verify(longTermKey, append([]byte(roughtimeCertContext), deleBytes...), certSig) {
		return time.Time{}, 0, errors.New("delegation signature does not verify against the server's long-term key")
	}

	// 2. Delegated key signs the response (over the SREP bytes).
	dele, err := decodeRoughtimeMessage(deleBytes)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parsing DELE: %w", err)
	}
	pubk, ok := dele[tagPUBK]
	if !ok || len(pubk) != ed25519.PublicKeySize {
		return time.Time{}, 0, errors.New("DELE missing or malformed PUBK")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubk), append([]byte(roughtimeResponseContext), srepBytes...), sig) {
		return time.Time{}, 0, errors.New("response signature does not verify against the delegated key")
	}

	// 3. The nonce is committed to by ROOT via the Merkle PATH at INDX.
	srep, err := decodeRoughtimeMessage(srepBytes)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parsing SREP: %w", err)
	}
	root, ok := srep[tagROOT]
	if !ok || len(root) != roughtimeHashLen {
		return time.Time{}, 0, errors.New("SREP missing or malformed ROOT")
	}
	index := binary.LittleEndian.Uint32(indxBytes)
	if err := verifyMerklePath(nonce, path, index, root); err != nil {
		return time.Time{}, 0, err
	}

	// 4. Midpoint must fall inside the delegation's validity window.
	midpRaw, ok := srep[tagMIDP]
	if !ok || len(midpRaw) != 8 {
		return time.Time{}, 0, errors.New("SREP missing or malformed MIDP")
	}
	midpMicros := binary.LittleEndian.Uint64(midpRaw)
	if minRaw, ok := dele[tagMINT]; ok && len(minRaw) == 8 {
		if midpMicros < binary.LittleEndian.Uint64(minRaw) {
			return time.Time{}, 0, errors.New("midpoint precedes the delegation validity window")
		}
	}
	if maxRaw, ok := dele[tagMAXT]; ok && len(maxRaw) == 8 {
		if midpMicros > binary.LittleEndian.Uint64(maxRaw) {
			return time.Time{}, 0, errors.New("midpoint follows the delegation validity window")
		}
	}

	var radius time.Duration
	if radiRaw, ok := srep[tagRADI]; ok && len(radiRaw) == 4 {
		radius = time.Duration(binary.LittleEndian.Uint32(radiRaw)) * time.Microsecond
	}
	return microsToTime(midpMicros), radius, nil
}

// verifyMerklePath recomputes the Merkle root from the nonce and PATH and checks
// it equals the signed ROOT.
func verifyMerklePath(nonce, path []byte, index uint32, root []byte) error {
	if len(path)%roughtimeHashLen != 0 {
		return errors.New("roughtime: Merkle PATH length is not a multiple of the hash size")
	}
	h := hashLeaf(nonce)
	for off := 0; off < len(path); off += roughtimeHashLen {
		sibling := path[off : off+roughtimeHashLen]
		if index&1 == 0 {
			h = hashNode(h, sibling)
		} else {
			h = hashNode(sibling, h)
		}
		index >>= 1
	}
	if !constantTimeEqual(h, root) {
		return errors.New("nonce is not committed to by the response ROOT (Merkle verification failed)")
	}
	return nil
}

// hashLeaf hashes a tree leaf: SHA-512(0x00 || nonce).
func hashLeaf(nonce []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0x00})
	h.Write(nonce)
	return h.Sum(nil)
}

// hashNode hashes an internal node: SHA-512(0x01 || left || right).
func hashNode(left, right []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// microsToTime converts microseconds-since-Unix-epoch to a time.Time.
func microsToTime(micros uint64) time.Time {
	sec := int64(micros / 1_000_000)
	nsec := int64(micros%1_000_000) * 1000
	return time.Unix(sec, nsec).UTC()
}

// encodeRoughtimeMessage encodes a tag->value map into the Roughtime wire
// format: a tag count, ascending tag list, value offsets, and the values. Tags
// are emitted in ascending little-endian-uint32 order, as the format requires.
func encodeRoughtimeMessage(fields map[uint32][]byte) []byte {
	tags := make([]uint32, 0, len(fields))
	for t := range fields {
		tags = append(tags, t)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })

	n := len(tags)
	out := make([]byte, 0, 4)
	out = binary.LittleEndian.AppendUint32(out, uint32(n))

	// Offsets to the start of each value after the first (must be multiples of 4).
	offset := 0
	for i := 0; i < n; i++ {
		if i > 0 {
			out = binary.LittleEndian.AppendUint32(out, uint32(offset))
		}
		offset += len(fields[tags[i]])
	}
	for _, t := range tags {
		out = binary.LittleEndian.AppendUint32(out, t)
	}
	for _, t := range tags {
		out = append(out, fields[t]...)
	}
	return out
}

// decodeRoughtimeMessage parses the Roughtime wire format into a tag->value map.
func decodeRoughtimeMessage(b []byte) (map[uint32][]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("message too short")
	}
	n := int(binary.LittleEndian.Uint32(b[0:4]))
	if n == 0 {
		return map[uint32][]byte{}, nil
	}
	// Layout: numTags(4) + (n-1) offsets(4) + n tags(4) + values.
	headerLen := 4 + (n-1)*4 + n*4
	if headerLen < 0 || headerLen > len(b) {
		return nil, errors.New("message header exceeds message length")
	}
	offsets := make([]int, n+1)
	offsets[0] = 0
	pos := 4
	for i := 1; i < n; i++ {
		offsets[i] = int(binary.LittleEndian.Uint32(b[pos : pos+4]))
		pos += 4
	}
	valuesStart := headerLen
	offsets[n] = len(b) - valuesStart
	tags := make([]uint32, n)
	for i := 0; i < n; i++ {
		tags[i] = binary.LittleEndian.Uint32(b[pos : pos+4])
		pos += 4
	}

	fields := make(map[uint32][]byte, n)
	for i := 0; i < n; i++ {
		start := offsets[i]
		end := offsets[i+1]
		if start < 0 || end < start || valuesStart+end > len(b) {
			return nil, errors.New("malformed value offset")
		}
		fields[tags[i]] = b[valuesStart+start : valuesStart+end]
	}
	return fields, nil
}
