package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/eventstream"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
)

// defaultStreamEventsHeartbeat is the interval between heartbeat frames on an idle
// StreamEvents stream when the request does not override it. It mirrors the REST
// SSE feed's cadence: often enough to keep an idle connection (and any
// intermediary) alive and let a client detect a half-open connection, but rare
// enough to be negligible.
const defaultStreamEventsHeartbeat = 15 * time.Second

// streamEventsReplayBatch bounds a single durable-log replay page so a long
// backlog is streamed incrementally rather than buffered whole in memory.
const streamEventsReplayBatch = 500

// StreamEvents subscribes the caller to the live tamper-evident audit/lifecycle
// event feed as a server stream — the gRPC peer of the REST Server-Sent-Events
// endpoint (GET /api/events/stream). It reuses the same in-process
// eventstream.Publisher (wired to the single audit-append chokepoint via
// DB.SetEventHook), the same authorization and tenant scoping (EventStreamScope,
// shared with the REST handler), and the same durable event_log cursor for
// replay — no eventing logic is duplicated.
//
// When resume_from_seq > 0 the durable log is replayed forward from that cursor
// (matching the tenant/action filter) before the live tail begins, and any
// overlap between the replay and the live ring is de-duplicated by sequence
// number, so a reconnecting client resumes without a gap or a repeat. Periodic
// heartbeat frames keep idle streams alive and expose half-open connections. A
// subscriber that cannot keep up is told (a lag frame) that its oldest
// undelivered events were dropped rather than ever blocking the audit-append hot
// path.
func (s *service) StreamEvents(req *pkiv1.StreamEventsRequest, stream grpc.ServerStreamingServer[pkiv1.StreamEventsResponse]) error {
	ctx := stream.Context()
	user := middleware.GetUserInfo(ctx)

	filter, err := s.api.EventStreamScope(user, req.GetAction(), req.GetTenant())
	if err != nil {
		return mapEventStreamScopeError(err)
	}

	// Subscribe BEFORE replaying the durable log: every event appended from this
	// point on is captured in the live ring, so the union of (replay ∪ live) has no
	// gap. Overlap is removed below by skipping any live event whose sequence number
	// was already covered by the replay.
	pub := s.api.EventPublisher()
	sub := pub.Subscribe(filter)
	defer pub.Unsubscribe(sub)

	// lastSeq is the highest sequence number the client has been told about (via a
	// replayed or live event). It is both the live-tail de-duplication watermark and
	// the resume cursor advertised in heartbeats.
	var lastSeq int64
	if resume := req.GetResumeFromSeq(); resume > 0 {
		lastSeq, err = s.replayEventLog(ctx, stream, filter, resume)
		if err != nil {
			return err
		}
	}

	heartbeat := time.NewTicker(streamEventsHeartbeatInterval(req.GetHeartbeatSeconds()))
	defer heartbeat.Stop()

	notify := sub.Notify()
	for {
		select {
		case <-ctx.Done():
			// The client went away (or the server is shutting down): unsubscribe
			// (deferred) and report the cancellation faithfully.
			return status.FromContextError(ctx.Err()).Err()
		case <-notify:
			events, dropped := sub.Drain()
			if dropped > 0 {
				// Report lag before the retained batch: the dropped events were older
				// than what remains queued, so telling the client "you missed N" first
				// preserves chronological sense.
				if err := stream.Send(lagFrame(dropped)); err != nil {
					return err
				}
			}
			for i := range events {
				// Drop any event already delivered by the replay (seq <= lastSeq), so a
				// resumed stream neither gaps nor repeats across the replay/live seam.
				if events[i].Seq <= lastSeq {
					continue
				}
				if err := stream.Send(auditEventFrame(&events[i])); err != nil {
					return err
				}
				lastSeq = events[i].Seq
			}
		case <-heartbeat.C:
			if err := stream.Send(heartbeatFrame(lastSeq)); err != nil {
				return err
			}
		}
	}
}

// replayEventLog streams the durable audit log forward from afterSeq, applying the
// same tenant/action filter as the live feed — ListEventsSince does not filter by
// tenant, so the confinement must be re-applied here, or a resumed tenant-scoped
// stream would leak other tenants' history. It pages in bounded batches so a long
// backlog cannot buffer unboundedly and returns the highest sequence number it
// scanned (matching or not), which becomes the live-tail de-duplication watermark.
func (s *service) replayEventLog(ctx context.Context, stream grpc.ServerStreamingServer[pkiv1.StreamEventsResponse], filter eventstream.Filter, afterSeq int64) (int64, error) {
	lastSeq := afterSeq
	for {
		if err := ctx.Err(); err != nil {
			return lastSeq, status.FromContextError(err).Err()
		}
		events, err := s.api.DB().ListEventsSince(lastSeq, streamEventsReplayBatch)
		if err != nil {
			return lastSeq, status.Errorf(codes.Internal, "replay audit log from seq %d: %v", lastSeq, err)
		}
		if len(events) == 0 {
			return lastSeq, nil
		}
		for i := range events {
			// Advance the watermark over every scanned event (even a filtered-out one),
			// so the live tail skips the whole scanned range and cannot double-send.
			lastSeq = events[i].Seq
			if !filter.Matches(&events[i]) {
				continue
			}
			if err := stream.Send(auditEventFrame(&events[i])); err != nil {
				return lastSeq, err
			}
		}
		if len(events) < streamEventsReplayBatch {
			return lastSeq, nil
		}
	}
}

// streamEventsHeartbeatInterval resolves the heartbeat cadence from the request:
// a non-positive value uses the default; an explicit value is clamped to a sane
// range so a client can neither request a busy sub-second heartbeat nor silence it
// past the point of usefulness.
func streamEventsHeartbeatInterval(seconds int32) time.Duration {
	if seconds <= 0 {
		return defaultStreamEventsHeartbeat
	}
	d := time.Duration(seconds) * time.Second
	if d < time.Second {
		d = time.Second
	}
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// auditEventFrame renders a sealed audit event as an event-stream frame.
func auditEventFrame(e *audit.Event) *pkiv1.StreamEventsResponse {
	return &pkiv1.StreamEventsResponse{
		Payload: &pkiv1.StreamEventsResponse_Event{Event: &pkiv1.AuditEvent{
			Seq:        e.Seq,
			Id:         e.ID,
			Timestamp:  timestamppb.New(e.Timestamp),
			Actor:      e.Actor,
			ActorName:  e.ActorName,
			ActorRoles: e.ActorRoles,
			Action:     e.Action,
			Tenant:     e.Tenant,
			Target:     e.Target,
			TargetName: e.TargetName,
			Result:     e.Result,
			Detail:     e.Detail,
			Ip:         e.IP,
			RequestId:  e.RequestID,
			PrevHash:   e.PrevHash,
			Hash:       e.Hash,
		}},
	}
}

// heartbeatFrame renders a periodic heartbeat carrying the current resume cursor.
func heartbeatFrame(lastSeq int64) *pkiv1.StreamEventsResponse {
	return &pkiv1.StreamEventsResponse{
		Payload: &pkiv1.StreamEventsResponse_Heartbeat{Heartbeat: &pkiv1.EventHeartbeat{
			Time:    timestamppb.New(time.Now().UTC()),
			LastSeq: lastSeq,
		}},
	}
}

// lagFrame renders a lag notice telling the client its buffer overflowed and
// dropped the given number of oldest undelivered events.
func lagFrame(dropped uint64) *pkiv1.StreamEventsResponse {
	return &pkiv1.StreamEventsResponse{
		Payload: &pkiv1.StreamEventsResponse_Lag{Lag: &pkiv1.EventLag{
			Dropped: dropped,
			Message: fmt.Sprintf("subscriber lagged: %d event(s) dropped; page the audit log to see the gap", dropped),
		}},
	}
}

// mapEventStreamScopeError maps the shared EventStreamScope authorization
// sentinels to gRPC status codes, mirroring how the REST handler maps them to
// 403/400.
func mapEventStreamScopeError(err error) error {
	switch {
	case errors.Is(err, handlers.ErrEventStreamTenantRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, handlers.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Errorf(codes.Internal, "event stream authorization failed: %v", err)
	}
}
