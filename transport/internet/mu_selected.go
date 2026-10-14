package internet

import (
	"context"

	"github.com/xtls/xray-core/common/session"
)

type muTransportKey struct{}

// ContextWithMUTransport explicitly selects a clean shared carrier context.
func ContextWithMUTransport(ctx context.Context) context.Context {
	return context.WithValue(ctx, muTransportKey{}, true)
}

// MUSelected is a per-call fact; INTERNAL alone does not select a carrier mode.
func MUSelected(ctx context.Context) bool {
	selected, _ := ctx.Value(muTransportKey{}).(bool)
	return selected || session.LogicalObservationFromContext(ctx) != nil ||
		session.TrafficOriginFromContext(ctx) == session.TrafficOriginControlledMeasurement
}
