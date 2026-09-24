//go:build sqlite

package acme

// Coverage for the account "orders" list (RFC 8555 §7.1.2.1). The resource is an
// enumeration of everything an account has ever ordered, so the access check is
// the whole story: it must return exactly the authenticated account's orders and
// refuse to enumerate anybody else's. A leak here hands an attacker the order URLs
// (and through them the identifier list) of every other subscriber.

import (
	"encoding/json"
	"net/http"
	"sort"
	"testing"
)

// accountOrders POST-as-GETs an account's orders list and returns the decoded
// "orders" array along with the raw response.
func accountOrders(t *testing.T, rc *rawClient, ordersURL string) (*http.Response, []byte, []string) {
	t.Helper()
	resp, body := rc.post(ordersURL, nil, false)
	var out struct {
		Orders []string `json:"orders"`
	}
	_ = json.Unmarshal(body, &out)
	return resp, body, out.Orders
}

// advertisedOrdersURL reads the "orders" link off the account object, so the tests
// address the resource the way a client discovers it rather than by string-building
// a URL the server may not actually serve.
func advertisedOrdersURL(t *testing.T, rc *rawClient) string {
	t.Helper()
	resp, body := rc.post(rc.kid, nil, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST-as-GET account = %d, want 200: %s", resp.StatusCode, body)
	}
	var acct struct {
		Orders string `json:"orders"`
	}
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatalf("decode account: %v (%s)", err, body)
	}
	if acct.Orders == "" {
		t.Fatalf("account object advertises no orders URL: %s", body)
	}
	return acct.Orders
}

// TestACME_AccountOrders_ListsOwnOrders confirms the list is complete and exact:
// every order the account placed appears once, and nothing else does.
func TestACME_AccountOrders_ListsOwnOrders(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	ordersURL := advertisedOrdersURL(t, rc)

	// Empty to start with — and a JSON array, not null, so clients can iterate it.
	resp, body, orders := accountOrders(t, rc, ordersURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("orders status = %d, want 200: %s", resp.StatusCode, body)
	}
	if len(orders) != 0 {
		t.Errorf("a fresh account lists %d orders, want none: %s", len(orders), body)
	}
	var shape struct {
		Orders *[]string `json:"orders"`
	}
	if err := json.Unmarshal(body, &shape); err != nil || shape.Orders == nil {
		t.Errorf("orders response must carry an \"orders\" array (got %s)", body)
	}

	// Place three orders and expect exactly those URLs back.
	want := make([]string, 0, 3)
	for _, domain := range []string{"o1.example.test", "o2.example.test", "o3.example.test"} {
		oresp, obody, _, orderURL := rc.newOrder("", domain)
		if oresp.StatusCode != http.StatusCreated {
			t.Fatalf("newOrder(%s) = %d: %s", domain, oresp.StatusCode, obody)
		}
		if orderURL == "" {
			t.Fatalf("newOrder(%s) returned no Location", domain)
		}
		want = append(want, orderURL)
	}

	_, body, orders = accountOrders(t, rc, ordersURL)
	sort.Strings(orders)
	sort.Strings(want)
	if len(orders) != len(want) {
		t.Fatalf("orders = %v, want %v: %s", orders, want, body)
	}
	for i := range want {
		if orders[i] != want[i] {
			t.Fatalf("orders = %v, want %v", orders, want)
		}
	}
}

// TestACME_AccountOrders_DoesNotLeakOtherAccounts is the access check: a second
// account's orders must never show up, and an account may not read another
// account's orders resource even though it authenticates perfectly well as itself.
func TestACME_AccountOrders_DoesNotLeakOtherAccounts(t *testing.T) {
	env := newTestEnv(t)

	alice := newRawClient(t, env.dirURL)
	alice.register()
	_, _, _, aliceOrder := alice.newOrder("", "alice-secret.example.test")
	aliceOrders := advertisedOrdersURL(t, alice)

	bob := newRawClient(t, env.dirURL)
	bob.register()
	_, _, _, bobOrder := bob.newOrder("", "bob.example.test")
	bobOrders := advertisedOrdersURL(t, bob)

	// Each account sees only its own order.
	_, abody, aList := accountOrders(t, alice, aliceOrders)
	if len(aList) != 1 || aList[0] != aliceOrder {
		t.Fatalf("alice's orders = %v, want [%s]: %s", aList, aliceOrder, abody)
	}
	_, bbody, bList := accountOrders(t, bob, bobOrders)
	if len(bList) != 1 || bList[0] != bobOrder {
		t.Fatalf("bob's orders = %v, want [%s]: %s", bList, bobOrder, bbody)
	}

	// Bob authenticating as Bob but addressing Alice's orders resource is refused.
	resp, body, leaked := accountOrders(t, bob, aliceOrders)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-account orders read = %d, want 401: %s", resp.StatusCode, body)
	}
	var prob Problem
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatalf("response is not a problem document: %v (%s)", err, body)
	}
	if prob.Type != probUnauthorized {
		t.Errorf("problem type = %q, want %q: %s", prob.Type, probUnauthorized, body)
	}
	if len(leaked) != 0 {
		t.Errorf("the rejected response leaked %d order URLs: %s", len(leaked), body)
	}
}

// TestACME_AccountOrders_RejectsBadAuthentication covers the remaining ways a
// request can fail to establish which account is asking: an embedded account key
// instead of a kid, a kid naming an account that does not exist, and a signature
// that does not verify under the named account's key.
func TestACME_AccountOrders_RejectsBadAuthentication(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	ordersURL := advertisedOrdersURL(t, rc)

	t.Run("embedded-jwk-instead-of-kid", func(t *testing.T) {
		resp, body := rc.post(ordersURL, nil, true)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("orders with an embedded jwk = %d, want 400: %s", resp.StatusCode, body)
		}
		var prob Problem
		_ = json.Unmarshal(body, &prob)
		if prob.Type != probMalformed {
			t.Errorf("problem type = %q, want %q: %s", prob.Type, probMalformed, body)
		}
	})

	t.Run("kid-names-a-nonexistent-account", func(t *testing.T) {
		impostor := newRawClient(t, env.dirURL)
		impostor.kid = rc.kid[:len(rc.kid)-len(idFromURL(rc.kid))] + "00000000-0000-0000-0000-000000000000"
		resp, body := impostor.post(impostor.kid+"/orders", nil, false)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("orders for an unknown account = %d, want 400: %s", resp.StatusCode, body)
		}
		var prob Problem
		_ = json.Unmarshal(body, &prob)
		if prob.Type != probAccountDoesntExist {
			t.Errorf("problem type = %q, want %q: %s", prob.Type, probAccountDoesntExist, body)
		}
	})

	t.Run("wrong-signing-key-for-the-named-account", func(t *testing.T) {
		// A stranger claims the victim's kid but signs with their own key: the
		// signature must not verify under the account's stored key.
		stranger := newRawClient(t, env.dirURL)
		stranger.kid = rc.kid
		resp, body, leaked := accountOrders(t, stranger, ordersURL)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("orders signed by the wrong key = %d, want 401: %s", resp.StatusCode, body)
		}
		if len(leaked) != 0 {
			t.Errorf("the rejected response leaked %d order URLs: %s", len(leaked), body)
		}
	})

	t.Run("deactivated-account", func(t *testing.T) {
		victim := newRawClient(t, env.dirURL)
		victim.register()
		vOrders := advertisedOrdersURL(t, victim)
		if r, b := victim.post(victim.kid, []byte(`{"status":"deactivated"}`), false); r.StatusCode != http.StatusOK {
			t.Fatalf("deactivate account = %d: %s", r.StatusCode, b)
		}
		resp, body, leaked := accountOrders(t, victim, vOrders)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("orders for a deactivated account = %d, want 401: %s", resp.StatusCode, body)
		}
		if len(leaked) != 0 {
			t.Errorf("a deactivated account still enumerated %d orders: %s", len(leaked), body)
		}
	})
}
