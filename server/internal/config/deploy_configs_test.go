package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeployConfigsLoad guards the configs shipped with the deployment stacks
// under deploy/, the same way TestExampleConfigsLoad guards examples/.
//
// These are mounted read-only into a container by a compose file that is
// documented as working, so a key renamed here and not there produces a stack
// that fails at `docker compose up` on somebody else's hardware. The two
// failures this catches are a key that no longer exists (strict decode) and a
// combination that no longer validates (Load).
//
// The credentials these files deliberately omit come from the environment in
// the stacks themselves, so the test supplies them: a config that refuses to
// load without a superuser password is the behaviour being relied on, not a
// problem to work around.
func TestDeployConfigsLoad(t *testing.T) {
	t.Setenv("SECSY_ROOT_PASSWORD", "deploy-config-test")
	t.Setenv("SECSY_USER_PIN", "0001deploy-config-test")
	clearYubiHSMEnv(t)

	root := filepath.Join("..", "..", "..", "deploy")
	matches, err := filepath.Glob(filepath.Join(root, "*", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatalf("no deployment configs found under %s (has deploy/ moved?)", root)
	}
	for _, path := range matches {
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
