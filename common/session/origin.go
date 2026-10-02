package session

import "context"

type trafficOriginKey struct{}

// TrafficOrigin is execution provenance, independent of observation enablement.
// Unspecified is deliberately not an implicit logical USER admission.
type TrafficOrigin uint8

const (
	OriginUnspecified TrafficOrigin = iota
	OriginUser
	OriginMeasurement
)

func ContextWithTrafficOrigin(ctx context.Context, origin TrafficOrigin) context.Context {
	return context.WithValue(ctx, trafficOriginKey{}, origin)
}

func TrafficOriginFromContext(ctx context.Context) TrafficOrigin {
	origin, _ := ctx.Value(trafficOriginKey{}).(TrafficOrigin)
	return origin
}
