//go:build ignore

// gen-pkcs11-names.go regenerates server/internal/pki/pkcs11names_gen.go: the
// Cryptoki constant -> name tables the raw PKCS#11 inspector (Task 218) renders
// with.
//
// The names are not retyped here. They are read out of the PKCS#11 binding this
// project already links (github.com/miekg/pkcs11), which transcribes them from
// the OASIS headers: the generator scrapes every CKA_/CKO_/CKK_/CKC_/CKH_/CKM_
// identifier out of the binding's zconst.go, then emits and RUNS a throwaway Go
// program that prints each one's value. Going through the compiler rather than
// parsing the right-hand sides is what makes aliases
// (CKA_ECDSA_PARAMS == CKA_EC_PARAMS), composed values
// (CKA_WRAP_TEMPLATE == CKF_ARRAY_ATTRIBUTE|0x211) and plain typos impossible to
// get wrong. CKR_ return values come from the binding's own strerror map, which
// is unexported, so those are read as text.
//
// Where two names share a value the one NOT marked "// Deprecated" in zconst.go
// wins, so an attribute renders as CKA_EC_PARAMS rather than its 1990s spelling.
//
// Usage (from the repository root):
//
//	go run scripts/gen-pkcs11-names.go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// prefixes are the constant families to tabulate, in output order.
var prefixes = []struct {
	prefix string // Cryptoki identifier prefix
	mapVar string // Go map variable to emit
	what   string // doc-comment subject
}{
	{"CKA_", "ckaNames", "attribute types (CK_ATTRIBUTE_TYPE)"},
	{"CKO_", "ckoNames", "object classes (CK_OBJECT_CLASS)"},
	{"CKK_", "ckkNames", "key types (CK_KEY_TYPE)"},
	{"CKC_", "ckcNames", "certificate types (CK_CERTIFICATE_TYPE)"},
	{"CKH_", "ckhNames", "hardware feature types (CK_HW_FEATURE_TYPE)"},
	{"CKM_", "ckmNames", "mechanism types (CK_MECHANISM_TYPE)"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-pkcs11-names:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := moduleDir()
	if err != nil {
		return err
	}
	zconst, err := os.ReadFile(filepath.Join(dir, "zconst.go"))
	if err != nil {
		return err
	}
	errsrc, err := os.ReadFile(filepath.Join(dir, "error.go"))
	if err != nil {
		return err
	}

	// Scrape the declared identifiers of each family, noting which are
	// deprecated so an alias pair resolves to the current spelling.
	names := map[string][]string{}
	deprecated := map[string]bool{}
	decl := regexp.MustCompile(`^\s*(CK[AOKCHM]_[A-Z0-9_]+)\s*=`)
	for _, line := range strings.Split(string(zconst), "\n") {
		m := decl.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id := m[1]
		for _, p := range prefixes {
			if strings.HasPrefix(id, p.prefix) {
				names[p.prefix] = append(names[p.prefix], id)
				if strings.Contains(line, "Deprecated") {
					deprecated[id] = true
				}
				break
			}
		}
	}
	for _, p := range prefixes {
		if len(names[p.prefix]) == 0 {
			return fmt.Errorf("no %s constants found in %s/zconst.go", p.prefix, dir)
		}
	}

	values, err := constantValues(names)
	if err != nil {
		return err
	}

	// CKR_ names live in the binding's unexported strerror map.
	ckr, err := returnValues(errsrc)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	fmt.Fprint(&b, header)
	for _, p := range prefixes {
		emit(&b, p.mapVar, p.what, p.prefix, names[p.prefix], values, deprecated)
	}
	emitCKR(&b, ckr)

	out := filepath.Join("server", "internal", "pki", "pkcs11names_gen.go")
	if err := os.WriteFile(out, b.Bytes(), 0o644); err != nil {
		return err
	}
	gofmt := exec.Command("gofmt", "-w", out)
	gofmt.Stderr = os.Stderr
	if err := gofmt.Run(); err != nil {
		return fmt.Errorf("gofmt %s: %w", out, err)
	}
	fmt.Printf("wrote %s\n", out)
	return nil
}

// moduleDir locates the source of the PKCS#11 binding the server module builds
// against, so the tables describe the constants actually compiled in.
func moduleDir() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/miekg/pkcs11")
	cmd.Dir = "server"
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locating github.com/miekg/pkcs11: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("github.com/miekg/pkcs11 has no module directory")
	}
	return dir, nil
}

// constantValues compiles and runs a throwaway program that prints every
// collected identifier's value, so the Go compiler — not a regexp — evaluates
// the right-hand sides.
func constantValues(names map[string][]string) (map[string]uint64, error) {
	var prog bytes.Buffer
	prog.WriteString("package main\n\nimport (\n\t\"fmt\"\n\n\t\"github.com/miekg/pkcs11\"\n)\n\nfunc main() {\n")
	for _, p := range prefixes {
		for _, id := range names[p.prefix] {
			fmt.Fprintf(&prog, "\tfmt.Printf(\"%s\\t%%d\\n\", uint64(pkcs11.%s))\n", id, id)
		}
	}
	prog.WriteString("}\n")

	// The probe lives inside the server module so it resolves the same binding
	// version the server builds against, in a directory removed again before
	// this function returns.
	pkg := filepath.Join("server", "pkcs11names-probe")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		return nil, err
	}
	defer os.RemoveAll(pkg)
	if err := os.WriteFile(filepath.Join(pkg, "main.go"), prog.Bytes(), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.Command("go", "run", "./pkcs11names-probe")
	cmd.Dir = "server"
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("evaluating constants: %w", err)
	}

	values := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("value of %s: %w", parts[0], err)
		}
		values[parts[0]] = v
	}
	return values, sc.Err()
}

// returnValues reads the CKR_ table out of the binding's strerror map.
func returnValues(errsrc []byte) (map[uint64]string, error) {
	row := regexp.MustCompile(`^\s*(0x[0-9A-Fa-f]+):\s*"(CKR_[A-Z0-9_]+)"`)
	out := map[uint64]string{}
	for _, line := range strings.Split(string(errsrc), "\n") {
		m := row.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(m[1], "0x"), 16, 64)
		if err != nil {
			return nil, err
		}
		out[v] = m[2]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CKR_ names found in error.go")
	}
	return out, nil
}

// emit writes one value -> name map, resolving alias collisions in favour of the
// non-deprecated spelling.
func emit(b *bytes.Buffer, mapVar, what, prefix string, ids []string, values map[string]uint64, deprecated map[string]bool) {
	chosen := map[uint64]string{}
	for _, id := range ids {
		v, ok := values[id]
		if !ok {
			continue
		}
		prev, seen := chosen[v]
		if !seen || (deprecated[prev] && !deprecated[id]) {
			chosen[v] = id
		}
	}
	keys := make([]uint64, 0, len(chosen))
	for v := range chosen {
		keys = append(keys, v)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	fmt.Fprintf(b, "\n// %s maps Cryptoki %s to their %s names.\nvar %s = map[uint]string{\n", mapVar, what, strings.TrimSuffix(prefix, "_"), mapVar)
	for _, v := range keys {
		fmt.Fprintf(b, "\t0x%08X: %q,\n", v, chosen[v])
	}
	fmt.Fprint(b, "}\n")
}

func emitCKR(b *bytes.Buffer, ckr map[uint64]string) {
	keys := make([]uint64, 0, len(ckr))
	for v := range ckr {
		keys = append(keys, v)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	fmt.Fprint(b, "\n// ckrNames maps Cryptoki return values (CK_RV) to their CKR names, so a\n"+
		"// refused attribute read reports WHY in the spec's own vocabulary.\nvar ckrNames = map[uint]string{\n")
	for _, v := range keys {
		fmt.Fprintf(b, "\t0x%08X: %q,\n", v, ckr[v])
	}
	fmt.Fprint(b, "}\n")
}

const header = `// Code generated by scripts/gen-pkcs11-names.go. DO NOT EDIT.
//
// Cryptoki constant -> name tables for the raw PKCS#11 inspector: attribute
// types, object classes, key types, certificate types, hardware feature types,
// mechanisms and return values. Regenerate with:
//
//	go run scripts/gen-pkcs11-names.go
//
// The values come from github.com/miekg/pkcs11 (the binding this project links),
// evaluated by the Go compiler rather than transcribed, so they cannot drift
// from the constants the rest of the package uses.

package pki
`
