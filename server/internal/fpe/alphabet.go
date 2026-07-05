package fpe

import (
	"fmt"
	"sort"
	"strings"
)

// Alphabet maps between human data (a string of symbols) and the FF1 numeral
// slices the cipher operates on. The radix is the number of distinct symbols;
// symbol i encodes to numeral i and back. Symbols are Unicode runes, so a custom
// alphabet may use any distinct characters.
type Alphabet struct {
	name    string
	symbols []rune
	index   map[rune]uint16
}

// Radix returns the alphabet size (the FF1 radix).
func (a *Alphabet) Radix() int { return len(a.symbols) }

// Name returns the alphabet's name (a registered name, or "chars:<symbols>" for
// an inline custom set).
func (a *Alphabet) Name() string { return a.name }

// Contains reports whether r is a symbol of the alphabet.
func (a *Alphabet) Contains(r rune) bool { _, ok := a.index[r]; return ok }

// IndexOf returns the numeral for symbol r and whether r is in the alphabet.
func (a *Alphabet) IndexOf(r rune) (uint16, bool) { v, ok := a.index[r]; return v, ok }

// SymbolAt returns the symbol for numeral v. v must be in [0, radix).
func (a *Alphabet) SymbolAt(v uint16) rune { return a.symbols[v] }

// ToNumerals converts a symbol string to an FF1 numeral slice, failing on any
// character outside the alphabet.
func (a *Alphabet) ToNumerals(s string) ([]uint16, error) {
	runes := []rune(s)
	out := make([]uint16, len(runes))
	for i, r := range runes {
		v, ok := a.index[r]
		if !ok {
			return nil, fmt.Errorf("fpe: character %q is not in alphabet %q", string(r), a.name)
		}
		out[i] = v
	}
	return out, nil
}

// FromNumerals converts an FF1 numeral slice back to its symbol string. Numerals
// must be in [0, radix); an out-of-range numeral is a programming error and
// panics, since it can only arise from a corrupt cipher output.
func (a *Alphabet) FromNumerals(x []uint16) string {
	var b strings.Builder
	for _, v := range x {
		if int(v) >= len(a.symbols) {
			panic(fmt.Sprintf("fpe: numeral %d out of range for alphabet %q", v, a.name))
		}
		b.WriteRune(a.symbols[v])
	}
	return b.String()
}

// newAlphabet builds an Alphabet from an ordered symbol string, rejecting an
// out-of-range size or a duplicate symbol (duplicates would make the codec
// ambiguous and thus non-invertible).
func newAlphabet(name, symbols string) (*Alphabet, error) {
	runes := []rune(symbols)
	if len(runes) < MinRadix || len(runes) > MaxRadix {
		return nil, fmt.Errorf("fpe: alphabet %q has %d symbols, out of range [%d,%d]", name, len(runes), MinRadix, MaxRadix)
	}
	index := make(map[rune]uint16, len(runes))
	for i, r := range runes {
		if _, dup := index[r]; dup {
			return nil, fmt.Errorf("fpe: alphabet %q has duplicate symbol %q", name, string(r))
		}
		index[r] = uint16(i)
	}
	return &Alphabet{name: name, symbols: runes, index: index}, nil
}

// Registered alphabet symbol sets. The ordering defines the numeral mapping and
// must never change once data is tokenized under a name, so these are frozen.
var namedAlphabets = map[string]string{
	"digits":             "0123456789",
	"hex-lower":          "0123456789abcdef",
	"hex-upper":          "0123456789ABCDEF",
	"letters-lower":      "abcdefghijklmnopqrstuvwxyz",
	"letters-upper":      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alphanumeric-lower": "0123456789abcdefghijklmnopqrstuvwxyz",                           // radix 36
	"alphanumeric-upper": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",                           // radix 36
	"alphanumeric":       "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", // radix 62
	"base32":             "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",                               // RFC 4648
	"base32-hex":         "0123456789ABCDEFGHIJKLMNOPQRSTUV",                               // RFC 4648 §7
}

// charsPrefix introduces an inline custom alphabet: "chars:<symbols>" defines
// the radix and mapping directly from the literal symbol string.
const charsPrefix = "chars:"

// NamedAlphabets returns the sorted list of registered alphabet names, for CLI
// help and config validation messages.
func NamedAlphabets() []string {
	names := make([]string, 0, len(namedAlphabets))
	for n := range namedAlphabets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ResolveAlphabet resolves an alphabet specification to an Alphabet. spec is
// either a registered name (see NamedAlphabets) or an inline "chars:<symbols>"
// literal defining a custom symbol set.
func ResolveAlphabet(spec string) (*Alphabet, error) {
	if spec == "" {
		return nil, fmt.Errorf("fpe: empty alphabet specification")
	}
	if strings.HasPrefix(spec, charsPrefix) {
		symbols := strings.TrimPrefix(spec, charsPrefix)
		return newAlphabet(spec, symbols)
	}
	symbols, ok := namedAlphabets[spec]
	if !ok {
		return nil, fmt.Errorf("fpe: unknown alphabet %q (known: %s, or an inline %q<symbols>)", spec, strings.Join(NamedAlphabets(), ", "), charsPrefix)
	}
	return newAlphabet(spec, symbols)
}
