package secret

// KEK rotation status reporting: the operator-facing view of a family's
// lineage joined with how many stored secrets still sit on each version, plus
// the periodic gauge refresh the expiry monitor drives so
// secsy_secret_on_old_kek and secsy_secret_kek_active_version stay current
// between explicit rotation operations.

import (
	"fmt"
	"sort"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// KEKStatusStore is the read-only persistence the status report and gauge
// refresh need. *database.DB satisfies it.
type KEKStatusStore interface {
	ListKEKFamilies() ([]string, error)
	ListKEKVersions(family string) ([]models.KEKVersion, error)
	CountStoredSecretsByKEKLabel(family string) (map[string]int64, error)
}

// KEKVersionStatus is one lineage entry of a KEKStatus report: the recorded
// version joined with the number of stored secrets still wrapped under it.
type KEKVersionStatus struct {
	models.KEKVersion
	// Secrets is how many stored secrets are currently wrapped under this
	// version's label.
	Secrets int64 `json:"secrets"`
}

// KEKStatus is the rotation posture of one KEK family.
type KEKStatus struct {
	Family        string `json:"family"`
	ActiveVersion int    `json:"active_version"`
	ActiveLabel   string `json:"active_label"`
	// NeverRotated is true when the family has no recorded lineage: its base
	// key is implicitly version 1, active.
	NeverRotated bool               `json:"never_rotated,omitempty"`
	Versions     []KEKVersionStatus `json:"versions"`
	// StoredSecrets is the family's total number of stored secrets.
	StoredSecrets int64 `json:"stored_secrets"`
	// SecretsOnOldKEK counts stored secrets not wrapped under the active
	// version — the number a rotation drains to zero by re-wrapping.
	SecretsOnOldKEK int64 `json:"secrets_on_old_kek"`
	// SecretsOnRetiredKEK counts stored secrets wrapped under a retired
	// version; they are undecryptable until the version is reinstated.
	SecretsOnRetiredKEK int64 `json:"secrets_on_retired_kek"`
}

// BuildKEKStatus assembles the rotation posture of one family.
func BuildKEKStatus(store KEKStatusStore, family string) (*KEKStatus, error) {
	if family == "" {
		return nil, fmt.Errorf("secret: KEK family is required")
	}
	versions, err := store.ListKEKVersions(family)
	if err != nil {
		return nil, err
	}
	counts, err := store.CountStoredSecretsByKEKLabel(family)
	if err != nil {
		return nil, err
	}

	st := &KEKStatus{Family: family}
	if len(versions) == 0 {
		st.NeverRotated = true
		versions = []models.KEKVersion{{
			Family:  family,
			Version: 1,
			Label:   family,
			Status:  models.KEKStatusActive,
		}}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })

	seen := make(map[string]bool, len(versions))
	for _, v := range versions {
		n := counts[v.Label]
		seen[v.Label] = true
		st.Versions = append(st.Versions, KEKVersionStatus{KEKVersion: v, Secrets: n})
		st.StoredSecrets += n
		if v.Status == models.KEKStatusActive {
			st.ActiveVersion, st.ActiveLabel = v.Version, v.Label
		} else {
			st.SecretsOnOldKEK += n
			if v.Status == models.KEKStatusRetired {
				st.SecretsOnRetiredKEK += n
			}
		}
	}
	// Secrets recorded under a label outside the lineage (should not happen,
	// but the report must not undercount): treat them as on an old KEK.
	for label, n := range counts {
		if !seen[label] {
			st.StoredSecrets += n
			st.SecretsOnOldKEK += n
		}
	}
	if st.ActiveLabel == "" {
		return nil, fmt.Errorf("secret: family %q has no active KEK version", family)
	}
	return st, nil
}

// RefreshKEKMetrics recomputes the per-family rotation gauges
// (secsy_secret_on_old_kek, secsy_secret_kek_active_version) from the store
// and returns operator-facing warning lines for families that still have
// secrets off the active KEK — the hook the expiry monitor calls on every
// scan tick. defaultFamily (the deployment-wide secret.kek_label; may be
// empty) is always included even before any secret is stored under it.
func RefreshKEKMetrics(store KEKStatusStore, defaultFamily string) ([]string, error) {
	families, err := store.ListKEKFamilies()
	if err != nil {
		return nil, err
	}
	if defaultFamily != "" {
		found := false
		for _, f := range families {
			if f == defaultFamily {
				found = true
				break
			}
		}
		if !found {
			families = append(families, defaultFamily)
		}
	}

	var warnings []string
	for _, family := range families {
		st, err := BuildKEKStatus(store, family)
		if err != nil {
			return warnings, fmt.Errorf("secret: KEK status for family %q: %w", family, err)
		}
		metrics.SecretsOnOldKEK.Set(float64(st.SecretsOnOldKEK), family)
		metrics.SecretKEKActiveVersion.Set(float64(st.ActiveVersion), family)
		if st.SecretsOnRetiredKEK > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"CRITICAL: %d stored secret(s) of KEK family %q are wrapped under a RETIRED KEK version and cannot be decrypted; reinstate the version or recover from escrow",
				st.SecretsOnRetiredKEK, family))
		} else if st.SecretsOnOldKEK > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"%d stored secret(s) of KEK family %q are still wrapped under an old KEK version; run `secsy-secret rewrap -all` to migrate them to version %d",
				st.SecretsOnOldKEK, family, st.ActiveVersion))
		}
	}
	return warnings, nil
}
