package task

import "context"

// ParticipantTracker acquires a linear lease before asynchronous work is
// published. Implementations must never use acquisition to suppress the work.
type ParticipantTracker interface {
	AcquireParticipant() ParticipantLease
}

// ParticipantLease is both one unit of live work and the parent capability
// for work spawned by that unit. Release must be safe against duplicate calls.
type ParticipantLease interface {
	ParticipantTracker
	Release(error)
}

type participantTrackerContextKey struct{}

type maskedParticipantTracker struct{}

func (maskedParticipantTracker) AcquireParticipant() ParticipantLease { return nil }

// ContextWithParticipantTracker attaches lifecycle bookkeeping without
// replacing any session-owned context value.
func ContextWithParticipantTracker(ctx context.Context, tracker ParticipantTracker) context.Context {
	if tracker == nil {
		return ctx
	}
	return context.WithValue(ctx, participantTrackerContextKey{}, tracker)
}

// ParticipantTrackerFromContext returns the nearest tracker, when present.
func ParticipantTrackerFromContext(ctx context.Context) ParticipantTracker {
	if ctx == nil {
		return nil
	}
	tracker, _ := ctx.Value(participantTrackerContextKey{}).(ParticipantTracker)
	return tracker
}

// ContextWithoutParticipantTracker masks an inherited observation tracker
// while preserving cancellation, deadlines, and all unrelated context values.
func ContextWithoutParticipantTracker(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, participantTrackerContextKey{}, maskedParticipantTracker{})
}

// AcquireParticipant acquires before a caller publishes asynchronous work.
// A nil result means that no valid observation lease was available; callers
// must still start and execute the work unchanged.
func AcquireParticipant(ctx context.Context) ParticipantLease {
	tracker := ParticipantTrackerFromContext(ctx)
	if tracker == nil {
		return nil
	}
	return tracker.AcquireParticipant()
}
