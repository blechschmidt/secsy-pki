package pki

// Resolution of the RFC 7512 "module-name" query attribute to a loadable
// PKCS#11 library path.
//
// RFC 7512 §2.3 lets a URI name its module either absolutely (module-path) or
// symbolically (module-name, "the name of the module, without any prefix or
// file extension"). Only module-path can be dlopen'd directly; module-name has
// to be looked up the way p11-kit looks it up, which is what this file does.
//
// It matters for portability of a config: "module-name=yubihsm_pkcs11" is the
// same string on Debian, RHEL and in the container image, where the absolute
// path is /usr/lib/x86_64-linux-gnu/pkcs11/, /usr/lib64/pkcs11/ and
// /usr/local/lib/pkcs11/ respectively. A deployment that writes the path has to
// know which base image it landed on; one that writes the name does not.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ModuleDirsEnv names an environment variable holding a colon-separated list of
// directories to search for a module-name, taking precedence over the built-in
// list. It exists so a deployment with an unusual layout (or a test with a
// fixture module) can resolve names without patching the binary.
const ModuleDirsEnv = "SECSY_PKCS11_MODULE_DIRS"

// p11KitModuleConfigDirs are the directories p11-kit reads module *descriptions*
// from. Each file there is a small key: value config whose "module:" line points
// at the library; the file's base name (minus ".module") is the module name.
// Checking these first means a name resolves to whatever the host's p11-kit
// would load, rather than to a same-named library that happens to be on the
// search path.
var p11KitModuleConfigDirs = []string{
	"/etc/pkcs11/modules",
	"/usr/share/p11-kit/modules",
	"/usr/local/share/p11-kit/modules",
}

// defaultModuleDirs are the conventional PKCS#11 library directories, covering
// Debian/Ubuntu multiarch, RHEL/SUSE lib64, and /usr/local installs (which is
// where a module built from source — as the -yubihsm image does — lands).
func defaultModuleDirs() []string {
	dirs := []string{
		"/usr/lib/" + gnuTriplet() + "/pkcs11",
		"/usr/lib64/pkcs11",
		"/usr/lib/pkcs11",
		"/usr/local/lib/" + gnuTriplet() + "/pkcs11",
		"/usr/local/lib64/pkcs11",
		"/usr/local/lib/pkcs11",
		// Some distributions ship the module directly in the library directory
		// rather than a pkcs11/ subdirectory.
		"/usr/lib/" + gnuTriplet(),
		"/usr/lib64",
		"/usr/local/lib",
	}
	out := dirs[:0:0]
	seen := map[string]bool{}
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// gnuTriplet returns the GNU multiarch triplet for this platform, used to form
// the Debian/Ubuntu module directory. It covers the architectures this project
// builds for; an unknown architecture simply yields a directory that does not
// exist and is skipped.
func gnuTriplet() string {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		return "x86_64-linux-gnu"
	case "arm64":
		return "aarch64-linux-gnu"
	case "arm":
		return "arm-linux-gnueabihf"
	case "386":
		return "i386-linux-gnu"
	case "riscv64":
		return "riscv64-linux-gnu"
	case "ppc64le":
		return "powerpc64le-linux-gnu"
	case "s390x":
		return "s390x-linux-gnu"
	default:
		return arch + "-linux-gnu"
	}
}

// moduleSearchDirs returns the directories to search, honoring ModuleDirsEnv.
func moduleSearchDirs() []string {
	if v := strings.TrimSpace(os.Getenv(ModuleDirsEnv)); v != "" {
		var dirs []string
		for _, d := range strings.Split(v, string(os.PathListSeparator)) {
			if d = strings.TrimSpace(d); d != "" {
				dirs = append(dirs, d)
			}
		}
		if len(dirs) > 0 {
			return dirs
		}
	}
	return defaultModuleDirs()
}

// ResolveModuleName maps an RFC 7512 module-name onto an absolute library path.
//
// It first consults the p11-kit module descriptions (so the name means what
// p11-kit says it means on this host), then searches the conventional module
// directories for "<name>.so". A name that already looks like a path (contains a
// separator or a shared-object extension) is accepted as-is if it exists, since
// operators reliably write one where the other is meant.
//
// It returns an error naming the directories searched when nothing matches —
// a resolution failure at config time is far easier to act on than a dlopen
// failure at first signature.
func ResolveModuleName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", fmt.Errorf("pkcs11 uri: module-name is empty")
	}
	// A path written into module-name: accept it when it resolves.
	if strings.ContainsRune(n, os.PathSeparator) || strings.HasSuffix(n, ".so") || strings.Contains(n, ".so.") {
		if st, err := os.Stat(n); err == nil && !st.IsDir() {
			return n, nil
		}
	}
	if path, ok := lookupP11KitModule(n); ok {
		return path, nil
	}
	dirs := moduleSearchDirs()
	base := n
	if !strings.HasSuffix(base, ".so") {
		base += ".so"
	}
	for _, d := range dirs {
		cand := filepath.Join(d, base)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
	}
	return "", fmt.Errorf("pkcs11 uri: module-name %q not found (searched %s; set module-path= or %s)",
		name, strings.Join(dirs, ", "), ModuleDirsEnv)
}

// lookupP11KitModule reads the p11-kit module description for name, returning
// the library path its "module:" line points at. The path may itself be
// relative, in which case it is resolved against the search directories exactly
// as p11-kit does.
func lookupP11KitModule(name string) (string, bool) {
	for _, dir := range p11KitModuleConfigDirs {
		data, err := os.ReadFile(filepath.Join(dir, name+".module"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, val, ok := strings.Cut(line, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "module") {
				continue
			}
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}
			if filepath.IsAbs(val) {
				if st, serr := os.Stat(val); serr == nil && !st.IsDir() {
					return val, true
				}
				continue
			}
			for _, d := range moduleSearchDirs() {
				cand := filepath.Join(d, val)
				if st, serr := os.Stat(cand); serr == nil && !st.IsDir() {
					return cand, true
				}
			}
		}
	}
	return "", false
}

// ResolveModulePath returns the module library path this URI names: module-path
// verbatim when present, otherwise module-name resolved through
// ResolveModuleName. It returns ("", nil) when the URI names no module at all,
// which is the common case — the module usually comes from pkcs11.module_path.
func (u *PKCS11URI) ResolveModulePath() (string, error) {
	if u == nil {
		return "", nil
	}
	if u.ModulePath != "" {
		return u.ModulePath, nil
	}
	if u.ModuleName == "" {
		return "", nil
	}
	return ResolveModuleName(u.ModuleName)
}
