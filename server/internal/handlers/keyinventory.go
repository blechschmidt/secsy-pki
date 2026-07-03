package handlers

import (
	"net/http"
	"sort"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ProviderKeyEntry is one key held by the key provider, annotated with the CA
// (or role) that references it — the REST counterpart of `secsy-ca inventory`.
type ProviderKeyEntry struct {
	Label       string `json:"label"`
	KeyType     string `json:"key_type"`
	Extractable bool   `json:"extractable"`
	Sensitive   bool   `json:"sensitive"`
	// CALabel names the CA bound to this key, empty when the key is not
	// referenced by any CA record (e.g. a KEK, TSA, or signing key).
	CALabel string `json:"ca_label,omitempty"`
}

// KeyInventoryResponse reports the provider's key inventory with the
// non-extractability verdict the CLI inventory command prints.
type KeyInventoryResponse struct {
	Provider         string             `json:"provider"`
	Keys             []ProviderKeyEntry `json:"keys"`
	ExtractableCount int                `json:"extractable_count"`
	UnboundCount     int                `json:"unbound_count"`
}

// ListProviderKeys handles GET /api/inventory/keys: enumerate the keys the
// configured key provider holds and verify none is extractable. hsm:manage
// (admin) gated — the inventory names every key label on the token.
func (a *API) ListProviderKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}

	lister, ok := a.keyProvider.(keyprovider.KeyLister)
	if !ok {
		writeError(w, http.StatusNotImplemented, "the configured key provider (%s) does not support key inventory", a.keyProvider.Name())
		return
	}
	keys, err := lister.ListKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing keys: %v", err)
		return
	}

	// Map provider key labels to the CA that references them, mirroring the CLI.
	cas, err := a.db.ListCAs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing CAs: %v", err)
		return
	}
	caByLabel := map[string]string{}
	for _, c := range cas {
		label := pki.ExtractKeyLabel(c.PKCS11URI)
		if label == "" {
			label = c.Label
		}
		caByLabel[label] = c.Label
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].Label < keys[j].Label })
	resp := KeyInventoryResponse{Provider: a.keyProvider.Name(), Keys: []ProviderKeyEntry{}}
	for _, k := range keys {
		entry := ProviderKeyEntry{
			Label:       k.Label,
			KeyType:     k.KeyType,
			Extractable: k.Extractable,
			Sensitive:   k.Sensitive,
			CALabel:     caByLabel[k.Label],
		}
		if entry.Extractable {
			resp.ExtractableCount++
		}
		if entry.CALabel == "" {
			resp.UnboundCount++
		}
		resp.Keys = append(resp.Keys, entry)
	}
	writeJSON(w, http.StatusOK, resp)
}
