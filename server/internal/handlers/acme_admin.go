package handlers

import (
	"net/http"
	"strconv"

	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ACME operator-visibility endpoints. The ACME protocol endpoints themselves are
// authenticated by account keys (JWS) and served outside this API; these
// read-only endpoints let operators inspect ACME accounts and orders under the
// same RBAC read gate (audit:read) as the rest of the inventory.

// ListACMEAccounts returns registered ACME accounts (RBAC: read).
func (a *API) ListACMEAccounts(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	limit, offset := paginate(r, 100, 500)
	accounts, err := a.db.ListACMEAccounts(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list ACME accounts: %v", err)
		return
	}
	if accounts == nil {
		accounts = []models.ACMEAccount{}
	}
	writeJSON(w, http.StatusOK, accounts)
}

// ListACMEOrders returns ACME orders (RBAC: read).
func (a *API) ListACMEOrders(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	limit, offset := paginate(r, 100, 500)
	orders, err := a.db.ListACMEOrders(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list ACME orders: %v", err)
		return
	}
	if orders == nil {
		orders = []models.ACMEOrder{}
	}
	writeJSON(w, http.StatusOK, orders)
}

// paginate extracts limit/offset query params with a default and hard cap.
func paginate(r *http.Request, def, max int) (int, int) {
	limit, offset := def, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= max {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}
