package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExampleConfigsLoad guards the shipped use-case example configs under
// examples/. Every examples/<use-case>/config.yaml must (a) contain no unknown
// keys under a strict decode and (b) pass full structural validation via Load.
// This keeps the copy-and-adapt examples honest as the config schema evolves: a
// renamed or removed field, or a validation tightened elsewhere, fails here
// instead of silently shipping a broken example an operator would copy.
func TestExampleConfigsLoad(t *testing.T) {
	root := filepath.Join("..", "..", "..", "examples")
	matches, err := filepath.Glob(filepath.Join(root, "*", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatalf("no example configs found under %s (has examples/ moved?)", root)
	}
	for _, path := range matches {
		path := path
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if unknown, err := UnknownKeys(data); err != nil {
				t.Fatalf("UnknownKeys(%s): %v", path, err)
			} else if len(unknown) > 0 {
				t.Fatalf("%s references config keys that do not exist:\n  %v", path, unknown)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("Load(%s): %v", path, err)
			}
		})
	}
}
