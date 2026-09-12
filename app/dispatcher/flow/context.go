package flow

import (
	"context"

	"github.com/xtls/xray-core/common/task"
)

type handleContextKey struct{}

// ContextWithHandle adds the exact root identity and participant tracker
// without replacing any session-owned context value.
func ContextWithHandle(ctx context.Context, handle *Handle) context.Context {
	if ctx == nil || handle == nil || handle.LogicalRoot() == nil {
		return ctx
	}
	ctx = task.ContextWithParticipantTracker(ctx, handle.LogicalRoot())
	return context.WithValue(ctx, handleContextKey{}, handle)
}

// HandleFromContext returns the exact admitted root handle, when present.
func HandleFromContext(ctx context.Context) *Handle {
	if ctx == nil {
		return nil
	}
	handle, _ := ctx.Value(handleContextKey{}).(*Handle)
	return handle
}

// SubmitErrorFromContext records a bounded terminal-outcome receipt for an
// admitted flow. It is additive to session-owned error feedback and never
// invokes foreign callbacks.
func SubmitErrorFromContext(ctx context.Context, err error) {
	if handle := HandleFromContext(ctx); handle != nil {
		handle.SubmitError(err)
	}
}
