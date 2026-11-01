package celpolicy

// Durations across the JSON boundary.
//
// A rule compares a duration the way CEL spells one — `signing.ssh.validity <=
// duration("12h")` — so the fact carrying it has to be a time.Duration: that is
// the only Go type cel-go's native provider renders as a CEL duration, and a
// named wrapper would arrive in an expression as a bare integer of nanoseconds.
//
// time.Duration's own JSON encoding, however, *is* that integer. Which means a
// hand-written fact set — the console's dry-run box, a `-facts` file, a curl
// body — would have to say `"validity": 28800000000000` for eight hours, and
// `"validity": "8h"` would be a decode error rather than the obvious thing.
// That is a bad trade for the one audience that writes these by hand.
//
// So the fact structs that carry a duration decode it flexibly (a duration
// string, or a number of nanoseconds) and encode it as the string. The CEL side
// is untouched: the field is still a time.Duration, and an expression still
// compares it with duration().

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// jsonDuration is a time.Duration that accepts either spelling in JSON and
// always writes the readable one.
type jsonDuration time.Duration

// UnmarshalJSON accepts `"8h"`, `"30m"`, `0` or `28800000000000`. An empty
// string and a JSON null both read as zero, so an operator can leave the field
// in their fact set without it meaning something.
func (d *jsonDuration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	if len(s) >= 2 && s[0] == '"' {
		var text string
		if err := json.Unmarshal(b, &text); err != nil {
			return err
		}
		if text == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(text)
		if err != nil {
			return fmt.Errorf("%q is not a duration: write it as 90m, 8h or 30s (or as a whole number of nanoseconds)", text)
		}
		*d = jsonDuration(parsed)
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("%s is not a duration: write it as a string (8h) or a whole number of nanoseconds", s)
	}
	*d = jsonDuration(n)
	return nil
}

// MarshalJSON writes the readable form ("8h0m0s"), so the facts a dry-run
// echoes back can be pasted into the next one.
func (d jsonDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON decodes a certificate request, accepting `validity` in either
// spelling. The shadow type drops the methods (so this does not recurse) and the
// outer field shadows the embedded one for encoding/json, which prefers the
// shallower of two same-named fields.
func (r *CertRequest) UnmarshalJSON(b []byte) error {
	type shadow CertRequest
	aux := struct {
		*shadow
		Validity *jsonDuration `json:"validity,omitempty"`
	}{shadow: (*shadow)(r)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Validity != nil {
		r.Validity = time.Duration(*aux.Validity)
	}
	return nil
}

// MarshalJSON encodes a certificate request with its validity as a duration
// string.
func (r CertRequest) MarshalJSON() ([]byte, error) {
	type shadow CertRequest
	return json.Marshal(struct {
		shadow
		Validity jsonDuration `json:"validity,omitempty"`
	}{shadow: shadow(r), Validity: jsonDuration(r.Validity)})
}

// UnmarshalJSON decodes the OpenSSH-certificate facts, accepting `validity` in
// either spelling.
func (s *SSHCertInfo) UnmarshalJSON(b []byte) error {
	type shadow SSHCertInfo
	aux := struct {
		*shadow
		Validity *jsonDuration `json:"validity,omitempty"`
	}{shadow: (*shadow)(s)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Validity != nil {
		s.Validity = time.Duration(*aux.Validity)
	}
	return nil
}

// MarshalJSON encodes the OpenSSH-certificate facts with a readable validity.
func (s SSHCertInfo) MarshalJSON() ([]byte, error) {
	type shadow SSHCertInfo
	return json.Marshal(struct {
		shadow
		Validity jsonDuration `json:"validity,omitempty"`
	}{shadow: shadow(s), Validity: jsonDuration(s.Validity)})
}

// UnmarshalJSON decodes the JWT-SVID facts, accepting `ttl` in either spelling.
func (j *JWTSVIDInfo) UnmarshalJSON(b []byte) error {
	type shadow JWTSVIDInfo
	aux := struct {
		*shadow
		TTL *jsonDuration `json:"ttl,omitempty"`
	}{shadow: (*shadow)(j)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.TTL != nil {
		j.TTL = time.Duration(*aux.TTL)
	}
	return nil
}

// MarshalJSON encodes the JWT-SVID facts with a readable TTL.
func (j JWTSVIDInfo) MarshalJSON() ([]byte, error) {
	type shadow JWTSVIDInfo
	return json.Marshal(struct {
		shadow
		TTL jsonDuration `json:"ttl,omitempty"`
	}{shadow: shadow(j), TTL: jsonDuration(j.TTL)})
}
