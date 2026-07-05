package acme

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// This file implements RFC 8739 — Short-Term, Automatically-Renewed (STAR)
// certificates (Task 136) — on top of the RFC 8555 order flow:
//
//   - The directory advertises meta.auto-renewal (StarConfig.wireMeta).
//   - newOrder accepts an "auto-renewal" object, validated against the server's
//     min/max bounds (resolveAutoRenewal) and persisted on the order.
//   - finalize issues the first short-lived certificate and records the replayable
//     CSR plus the next-renewal deadline (see issue.go).
//   - A leader-elected renewer (RunStarRenewer) re-issues each STAR certificate
//     ahead of expiry until its end-date.
//   - The stable star-certificate URL always returns the current certificate,
//     fetchable via unauthenticated GET when the order set allow-certificate-get.
//   - Canceling the order (POST status="canceled", see order.go) stops renewal and
//     makes the star-certificate URL answer 403 (autoRenewalCanceled).

const (
	// starRenewalCheckInterval is how often the leader-elected renewer polls for
	// STAR orders whose next-renewal deadline has arrived. It is well under any
	// realistic per-certificate lifetime so a due order is picked up promptly.
	starRenewalCheckInterval = time.Minute
	// starRenewalMinCushion is the floor on how far ahead of a certificate's expiry
	// the next renewal is scheduled, so even very short lifetimes leave a usable
	// overlap window for propagation.
	starRenewalMinCushion = 5 * time.Minute
	// starRenewalBatch bounds how many due orders a single sweep re-issues, so a
	// large backlog is drained across ticks rather than in one long HSM burst.
	starRenewalBatch = 500
)

// StarConfig enables and bounds RFC 8739 STAR certificates. A nil *StarConfig on
// the acme.Config leaves the feature off.
type StarConfig struct {
	// MinLifetime is the smallest per-certificate lifetime a client may request in
	// the newOrder "auto-renewal.lifetime". Default 1h.
	MinLifetime time.Duration
	// MaxLifetime is the largest per-certificate lifetime a client may request.
	// Default 7 days. STAR is meant for short-lived certificates, so this caps how
	// long any single certificate can live.
	MaxLifetime time.Duration
	// MaxDuration is the longest total recurrence (end-date − start-date) a client
	// may request. Default 365 days. It is advertised as meta.auto-renewal.max-duration.
	MaxDuration time.Duration
}

// withDefaults fills zero-valued bounds and lifts an inverted max above the min so
// every request in the closed interval is representable.
func (c StarConfig) withDefaults() StarConfig {
	if c.MinLifetime <= 0 {
		c.MinLifetime = time.Hour
	}
	if c.MaxLifetime <= 0 {
		c.MaxLifetime = 7 * 24 * time.Hour
	}
	if c.MaxDuration <= 0 {
		c.MaxDuration = 365 * 24 * time.Hour
	}
	if c.MaxLifetime < c.MinLifetime {
		c.MaxLifetime = c.MinLifetime
	}
	return c
}

// wireMeta renders the directory meta.auto-renewal advertisement (RFC 8739 §3.1).
func (c StarConfig) wireMeta() *metaAutoRenewal {
	return &metaAutoRenewal{
		MinLifetime:         int64(c.MinLifetime.Seconds()),
		MaxDuration:         int64(c.MaxDuration.Seconds()),
		AllowCertificateGet: true,
	}
}

// starEnabled reports whether RFC 8739 STAR support is configured.
func (s *Server) starEnabled() bool { return s.cfg.Star != nil }

// resolveAutoRenewal validates a newOrder "auto-renewal" object against the
// server's configured bounds and returns the resolved recurrence to persist, or a
// Problem to reject the order with. It is only reached when STAR is enabled.
func (s *Server) resolveAutoRenewal(req *autoRenewalRequest, now time.Time) (*models.ACMEAutoRenewal, *Problem) {
	star := s.cfg.Star
	if req.EndDate == "" {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "auto-renewal requires an \"end-date\"")
	}
	endDate, err := time.Parse(time.RFC3339, req.EndDate)
	if err != nil {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "auto-renewal \"end-date\" is not an RFC 3339 timestamp")
	}
	endDate = endDate.UTC()

	// start-date is optional and defaults to the order creation time.
	startDate := now
	if req.StartDate != "" {
		startDate, err = time.Parse(time.RFC3339, req.StartDate)
		if err != nil {
			return nil, newProblem(probMalformed, http.StatusBadRequest, "auto-renewal \"start-date\" is not an RFC 3339 timestamp")
		}
		startDate = startDate.UTC()
	}

	if req.Lifetime <= 0 {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "auto-renewal requires a positive \"lifetime\" (seconds)")
	}
	lifetime := time.Duration(req.Lifetime) * time.Second

	if !endDate.After(startDate) {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "auto-renewal \"end-date\" must be after \"start-date\"")
	}
	if !endDate.After(now) {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "auto-renewal \"end-date\" is in the past")
	}
	if lifetime < star.MinLifetime {
		return nil, newProblem(probMalformed, http.StatusBadRequest,
			fmt.Sprintf("auto-renewal \"lifetime\" %ds is below the server minimum of %ds",
				req.Lifetime, int64(star.MinLifetime.Seconds())))
	}
	if lifetime > star.MaxLifetime {
		return nil, newProblem(probMalformed, http.StatusBadRequest,
			fmt.Sprintf("auto-renewal \"lifetime\" %ds exceeds the server maximum of %ds",
				req.Lifetime, int64(star.MaxLifetime.Seconds())))
	}
	if dur := endDate.Sub(startDate); dur > star.MaxDuration {
		return nil, newProblem(probMalformed, http.StatusBadRequest,
			fmt.Sprintf("auto-renewal duration %ds exceeds the server maximum of %ds",
				int64(dur.Seconds()), int64(star.MaxDuration.Seconds())))
	}

	return &models.ACMEAutoRenewal{
		StartDate:           startDate,
		EndDate:             endDate,
		LifetimeSeconds:     int(req.Lifetime),
		AllowCertificateGet: req.AllowCertificateGet,
	}, nil
}

// starCertValidity returns the validity to issue the next STAR certificate with:
// the recurrence lifetime, capped so notAfter never exceeds the end-date. A
// non-positive result means the recurrence horizon has passed and no certificate
// should be issued.
func starCertValidity(ar *models.ACMEAutoRenewal, now time.Time) time.Duration {
	remaining := ar.EndDate.Sub(now)
	if remaining <= 0 {
		return 0
	}
	if lifetime := ar.Lifetime(); lifetime < remaining {
		return lifetime
	}
	return remaining
}

// starNextRenewal computes when the renewer should next re-issue, given the
// certificate just issued (notAfter). It returns nil when the certificate already
// runs to the recurrence horizon, which ends the recurrence.
func starNextRenewal(ar *models.ACMEAutoRenewal, notAfter time.Time) *time.Time {
	if !notAfter.Before(ar.EndDate) {
		return nil // this certificate already covers up to the end-date
	}
	cushion := starRenewalCushion(ar.Lifetime())
	next := notAfter.Add(-cushion).UTC()
	return &next
}

// starRenewalCushion is how far ahead of expiry to schedule the next renewal:
// a third of the lifetime, floored at starRenewalMinCushion and capped at half the
// lifetime so the renewal is always strictly before the certificate's midpoint-to-
// expiry and never before it was issued.
func starRenewalCushion(lifetime time.Duration) time.Duration {
	cushion := lifetime / 3
	if cushion < starRenewalMinCushion {
		cushion = starRenewalMinCushion
	}
	if half := lifetime / 2; cushion > half {
		cushion = half
	}
	return cushion
}

// ---- star-certificate serving --------------------------------------------

// handleStarCertificate serves the current STAR certificate to an account-
// authenticated POST-as-GET (RFC 8739 §3.4). The route stays mounted with STAR
// disabled so it answers with a proper ACME problem rather than a bare 404.
func (s *Server) handleStarCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.starEnabled() {
		s.writeProblem(w, newProblem(probMalformed, http.StatusNotFound, "STAR (auto-renewal) is not supported by this server"))
		return
	}
	acct, _, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	order, prob := s.loadStarOrder(r.PathValue("id"))
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if order.AccountID != acct.rec.ID {
		s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "STAR certificate not found for this account"))
		return
	}
	chain, prob := starCertificateBody(order)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	s.writeStarCertChain(w, chain, true)
}

// handleStarCertificateGET serves the current STAR certificate to an
// unauthenticated GET (RFC 8739 §3.4), honored only when the order requested
// allow-certificate-get. It is not part of the nonce-anchored POST flow, so it
// issues no Replay-Nonce.
func (s *Server) handleStarCertificateGET(w http.ResponseWriter, r *http.Request) {
	if !s.starEnabled() {
		s.writeProblemNoNonce(w, newProblem(probMalformed, http.StatusNotFound, "STAR (auto-renewal) is not supported by this server"))
		return
	}
	order, prob := s.loadStarOrder(r.PathValue("id"))
	if prob != nil {
		s.writeProblemNoNonce(w, prob)
		return
	}
	if order.AutoRenewal == nil || !order.AutoRenewal.AllowCertificateGet {
		// The order did not opt into unauthenticated retrieval; direct the client to
		// the authenticated POST-as-GET instead.
		s.writeProblemNoNonce(w, newProblem(probUnauthorized, http.StatusUnauthorized,
			"this STAR certificate must be fetched with an authenticated POST-as-GET"))
		return
	}
	chain, prob := starCertificateBody(order)
	if prob != nil {
		s.writeProblemNoNonce(w, prob)
		return
	}
	s.writeStarCertChain(w, chain, false)
}

// loadStarOrder loads a STAR order by id, mapping "not found" and "not a STAR
// order" to a 404 ACME problem so the star-certificate route never leaks whether
// a given id is a normal order.
func (s *Server) loadStarOrder(id string) (*models.ACMEOrder, *Problem) {
	order, err := s.db.GetACMEOrder(id)
	if err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "order lookup failed")
	}
	if order == nil || order.AutoRenewal == nil {
		return nil, newProblem(probMalformed, http.StatusNotFound, "STAR certificate not found")
	}
	return order, nil
}

// starCertificateBody returns the chain to serve for a STAR order, or the Problem
// explaining why it can't be served: a canceled recurrence answers 403
// autoRenewalCanceled (RFC 8739 §3.5); an order without a certificate yet answers
// 404.
func starCertificateBody(order *models.ACMEOrder) (string, *Problem) {
	if order.Status == models.ACMEOrderStatusCanceled {
		return "", newProblem(probAutoRenewalCanceled, http.StatusForbidden, "the STAR recurrence has been canceled")
	}
	if order.Certificate == "" {
		return "", newProblem(probMalformed, http.StatusNotFound, "the STAR certificate is not available yet")
	}
	return order.Certificate, nil
}

// writeStarCertChain writes a PEM certificate-chain body. The authenticated
// POST-as-GET carries a fresh nonce (withNonce); the unauthenticated GET does not.
func (s *Server) writeStarCertChain(w http.ResponseWriter, chain string, withNonce bool) {
	if withNonce {
		s.addNonce(w)
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(chain))
}

// ---- cancellation ---------------------------------------------------------

// cancelStarOrder handles a POST status="canceled" on a STAR order (RFC 8739
// §3.5): it stops the recurrence so the renewer issues no further certificates and
// the star-certificate URL begins answering 403. It is idempotent — a re-cancel
// just re-reports the canceled order.
func (s *Server) cancelStarOrder(w http.ResponseWriter, r *http.Request, acct *acmeAccount, order *models.ACMEOrder) {
	if order.AutoRenewal == nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "only STAR (auto-renewal) orders can be canceled"))
		return
	}
	if order.Status == models.ACMEOrderStatusCanceled {
		s.writeOrder(w, r, order) // idempotent
		return
	}
	canceled, err := s.db.CancelACMEStarOrder(order.ID)
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "canceling order"))
		return
	}
	if canceled {
		order.Status = models.ACMEOrderStatusCanceled
		order.StarNextRenewal = nil
		metrics.ACMEStarOrders.Inc("canceled")
		s.recordEvent(r, acct.rec.ID, audit.ActionACMEStar, order.ID, audit.ResultSuccess,
			"recurrence canceled; star-certificate now returns 403")
	} else if reload, _ := s.db.GetACMEOrder(order.ID); reload != nil {
		// Lost the race with a concurrent transition (or the order was already
		// terminal): report the authoritative current state.
		order = reload
	}
	s.writeOrder(w, r, order)
}

// ---- leader-elected renewer ----------------------------------------------

// RunStarRenewer re-issues due STAR certificates on a background loop until ctx is
// cancelled. Register it as a leader-elected job so a single replica drives the
// recurrence for the shared store (like the other periodic sweeps). It is a no-op
// when STAR is disabled.
func (s *Server) RunStarRenewer(ctx context.Context) {
	if !s.starEnabled() {
		return
	}
	t := time.NewTicker(starRenewalCheckInterval)
	defer t.Stop()
	for {
		if n, err := s.RenewDueSTAROrders(ctx); err != nil {
			log.Printf("acme: STAR renewal sweep: %v", err)
		} else if n > 0 {
			log.Printf("acme: renewed %d STAR certificate(s)", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RenewDueSTAROrders runs one renewal sweep: every valid STAR order whose
// next-renewal deadline has arrived is re-issued (or ended, past its horizon). It
// returns the number of certificates re-issued. Safe to call directly from tests.
func (s *Server) RenewDueSTAROrders(ctx context.Context) (int, error) {
	if !s.starEnabled() {
		return 0, nil
	}
	now := s.now().UTC()
	due, err := s.db.ListDueACMEStarOrders(now, starRenewalBatch)
	if err != nil {
		return 0, err
	}
	renewed := 0
	for i := range due {
		if s.renewStarOrder(ctx, &due[i], now) {
			renewed++
		}
	}
	return renewed, nil
}

// renewStarOrder re-issues one STAR order's certificate from its stored CSR and
// reschedules the next renewal. Past the recurrence horizon it clears the deadline
// instead, ending the recurrence. It reports whether a new certificate was issued.
// A failure is logged and counted but never fatal: the order keeps its deadline
// and is retried on the next sweep, so a transient HSM/CA outage self-heals.
func (s *Server) renewStarOrder(ctx context.Context, order *models.ACMEOrder, now time.Time) bool {
	ar := order.AutoRenewal
	if ar == nil {
		return false // defensive: the due-query only returns STAR orders
	}

	// Recurrence horizon reached: stop renewing and keep serving the last cert.
	validity := starCertValidity(ar, now)
	if validity <= 0 {
		if err := s.db.StopACMEStarRenewal(order.ID); err != nil {
			log.Printf("acme: STAR order %s: stopping renewal: %v", order.ID, err)
			return false
		}
		metrics.ACMEStarOrders.Inc("ended")
		s.recordBackgroundEvent(order.AccountID, audit.ActionACMEStar, order.ID, audit.ResultSuccess,
			"recurrence reached end-date "+rfc3339(ar.EndDate)+"; renewal stopped")
		return false
	}

	der, err := base64.RawURLEncoding.DecodeString(order.StarCSR)
	if err != nil {
		log.Printf("acme: STAR order %s: stored CSR is unreadable, cannot renew: %v", order.ID, err)
		metrics.ACMEStarOrders.Inc("renew_failed")
		return false
	}
	profileID := order.Profile
	if profileID == "" {
		profileID = s.cfg.Profile
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	authzs, _ := s.db.ListACMEAuthorizationsByOrder(order.ID)

	caID := s.cfg.CAID
	result, err := s.caMgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:              caID,
		CSRPEM:            csrPEM,
		Profile:           profileID,
		Validity:          validity,
		Marker:            models.CertMarkerACMEStar,
		RequestedBy:       "acme-star:" + order.AccountID,
		ACMEAccountURI:    s.backgroundAccountURI(order.AccountID),
		ValidationMethods: s.validationMethods(authzs),
	})
	if err != nil {
		log.Printf("acme: STAR order %s: re-issuance failed: %v", order.ID, err)
		metrics.ACMEStarOrders.Inc("renew_failed")
		s.recordBackgroundEvent(order.AccountID, audit.ActionACMEStar, order.ID, audit.ResultError,
			"renewal failed: "+err.Error())
		return false
	}

	nextRenewal := starNextRenewal(ar, result.Certificate.NotAfter)
	if err := s.db.RenewACMEStarOrder(order.ID, caID, result.Serial.String(), string(result.ChainPEM), nextRenewal); err != nil {
		log.Printf("acme: STAR order %s: recording renewal: %v", order.ID, err)
		metrics.ACMEStarOrders.Inc("renew_failed")
		return false
	}
	metrics.ACMEStarOrders.Inc("renewed")
	s.recordBackgroundEvent(order.AccountID, audit.ActionACMEStar, order.ID, audit.ResultSuccess,
		"renewed serial="+result.Serial.String()+" notAfter="+rfc3339(result.Certificate.NotAfter))
	return true
}

// backgroundAccountURI reconstructs an account's canonical URL outside a request,
// for the RFC 8657 CAA-binding facts threaded into a background renewal. It needs
// the configured BaseURL; when the origin is derived per-request instead (BaseURL
// empty) it returns "", which the CAA gate treats as an unrecorded accounturi
// (blocking only a name whose CAA record actually pins one).
func (s *Server) backgroundAccountURI(accountID string) string {
	if s.cfg.BaseURL == "" {
		return ""
	}
	return s.cfg.BaseURL + s.cfg.DirectoryPath + "/acct/" + accountID
}

// recordBackgroundEvent appends an audit event from a background job, where there
// is no request to source a client IP from. Mirrors recordEvent otherwise.
func (s *Server) recordBackgroundEvent(accountID, action, target, result, detail string) {
	e := &audit.Event{
		ID:         newUUID(),
		Actor:      "acme:" + accountID,
		ActorRoles: "acme",
		Action:     action,
		Target:     target,
		Result:     result,
		Detail:     detail,
	}
	if err := s.db.AppendEvent(e); err != nil {
		log.Printf("acme: failed to append audit event %q: %v", action, err)
	}
}

// wireAutoRenewalFrom renders a resolved recurrence as the order's "auto-renewal"
// object (RFC 8739 §3.1.1).
func wireAutoRenewalFrom(ar *models.ACMEAutoRenewal) *wireAutoRenewal {
	return &wireAutoRenewal{
		StartDate:           rfc3339(ar.StartDate),
		EndDate:             rfc3339(ar.EndDate),
		Lifetime:            int64(ar.LifetimeSeconds),
		AllowCertificateGet: ar.AllowCertificateGet,
	}
}
