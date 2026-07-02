package attestation

import (
	"errors"
	"fmt"
	"math"
)

// This file implements a deliberately minimal, allocation-conservative CBOR
// (RFC 8949) reader — just enough to decode the WebAuthn attestation objects
// used by ACME device-attest-01 (draft-ietf-acme-device-attest) and the COSE
// keys embedded in their authenticator data. It supports only the subset of
// CBOR those structures use: unsigned/negative integers, byte strings, text
// strings, definite-length arrays, and definite-length maps.
//
// A full CBOR library is intentionally avoided: the input here is a small,
// attacker-influenced blob on the enrollment path, so a tight, auditable parser
// with hard bounds is preferable to a general-purpose decoder, and it keeps the
// dependency/supply-chain surface unchanged (see the supply-chain-security
// hardening in Task 48).

// maxCBORNesting bounds recursion so a hostile blob of deeply nested
// arrays/maps cannot exhaust the stack.
const maxCBORNesting = 16

// maxCBORItems bounds the element count of any single array or map so a
// truncated blob claiming a huge count cannot drive unbounded allocation.
const maxCBORItems = 1 << 16

// cborReader is a cursor over a CBOR byte slice.
type cborReader struct {
	buf   []byte
	pos   int
	depth int
}

// decodeCBOR parses a single top-level CBOR data item and requires the whole
// input to be consumed. The returned value is one of: uint64, int64, []byte,
// string, []interface{}, or map[interface{}]interface{}.
func decodeCBOR(buf []byte) (interface{}, error) {
	r := &cborReader{buf: buf}
	v, err := r.readValue()
	if err != nil {
		return nil, err
	}
	if r.pos != len(buf) {
		return nil, fmt.Errorf("cbor: %d trailing byte(s) after top-level item", len(buf)-r.pos)
	}
	return v, nil
}

func (r *cborReader) readValue() (interface{}, error) {
	if r.depth > maxCBORNesting {
		return nil, errors.New("cbor: nesting too deep")
	}
	if r.pos >= len(r.buf) {
		return nil, errors.New("cbor: unexpected end of input")
	}
	b := r.buf[r.pos]
	r.pos++
	major := b >> 5
	minor := b & 0x1f

	switch major {
	case 0: // unsigned integer
		n, err := r.readUint(minor)
		if err != nil {
			return nil, err
		}
		return n, nil
	case 1: // negative integer: value is -1 - n
		n, err := r.readUint(minor)
		if err != nil {
			return nil, err
		}
		if n > math.MaxInt64 {
			return nil, errors.New("cbor: negative integer out of range")
		}
		return int64(-1) - int64(n), nil
	case 2: // byte string
		n, err := r.readLen(minor)
		if err != nil {
			return nil, err
		}
		return r.readBytes(n)
	case 3: // text string
		n, err := r.readLen(minor)
		if err != nil {
			return nil, err
		}
		raw, err := r.readBytes(n)
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	case 4: // array
		n, err := r.readLen(minor)
		if err != nil {
			return nil, err
		}
		r.depth++
		defer func() { r.depth-- }()
		out := make([]interface{}, 0, n)
		for i := 0; i < n; i++ {
			v, err := r.readValue()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map
		n, err := r.readLen(minor)
		if err != nil {
			return nil, err
		}
		r.depth++
		defer func() { r.depth-- }()
		out := make(map[interface{}]interface{}, n)
		for i := 0; i < n; i++ {
			k, err := r.readValue()
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case uint64, int64, string:
				// hashable key types we accept
			default:
				return nil, errors.New("cbor: unsupported map key type")
			}
			v, err := r.readValue()
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cbor: unsupported major type %d", major)
	}
}

// readUint decodes the argument of an integer/length header from its minor
// value, reading 1/2/4/8 trailing bytes as needed.
func (r *cborReader) readUint(minor byte) (uint64, error) {
	switch {
	case minor < 24:
		return uint64(minor), nil
	case minor == 24:
		v, err := r.readBytes(1)
		if err != nil {
			return 0, err
		}
		return uint64(v[0]), nil
	case minor == 25:
		v, err := r.readBytes(2)
		if err != nil {
			return 0, err
		}
		return uint64(v[0])<<8 | uint64(v[1]), nil
	case minor == 26:
		v, err := r.readBytes(4)
		if err != nil {
			return 0, err
		}
		return uint64(v[0])<<24 | uint64(v[1])<<16 | uint64(v[2])<<8 | uint64(v[3]), nil
	case minor == 27:
		v, err := r.readBytes(8)
		if err != nil {
			return 0, err
		}
		var n uint64
		for _, x := range v {
			n = n<<8 | uint64(x)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("cbor: reserved/indefinite length encoding (minor %d) not supported", minor)
	}
}

// readLen decodes a length argument and range-checks it against the remaining
// input and the item cap.
func (r *cborReader) readLen(minor byte) (int, error) {
	n, err := r.readUint(minor)
	if err != nil {
		return 0, err
	}
	// Loose upper bound: no item count or byte length can exceed the total input
	// size. Byte/text-string reads are additionally exact-checked in readBytes,
	// and array/map loops fail naturally on truncation.
	if n > maxCBORItems || n > uint64(len(r.buf)) {
		return 0, errors.New("cbor: length exceeds bounds")
	}
	return int(n), nil
}

func (r *cborReader) readBytes(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, errors.New("cbor: truncated input")
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

// ---- typed accessors ------------------------------------------------------

// cborMapGet fetches a value from a decoded CBOR map by an integer or string
// key, returning (value, true) when present.
func cborMapGet(m map[interface{}]interface{}, key interface{}) (interface{}, bool) {
	switch k := key.(type) {
	case int:
		if k < 0 {
			v, ok := m[int64(k)]
			return v, ok
		}
		v, ok := m[uint64(k)]
		return v, ok
	default:
		v, ok := m[key]
		return v, ok
	}
}

// cborBytes returns v as a byte slice when it decoded as a CBOR byte string.
func cborBytes(v interface{}) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

// cborInt coerces a decoded CBOR integer (uint64 or int64) to int64.
func cborInt(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}
