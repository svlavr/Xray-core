package session

import "context"

type udpPacketSourceKey struct{}

// ContextWithUDPPacketSource requests address-bearing UDP response framing.
// It is a request fact, not a source/route proof. Protocol owners may honor it
// on their supported path; callers still validate each observed packet source.
func ContextWithUDPPacketSource(ctx context.Context) context.Context {
	return context.WithValue(ctx, udpPacketSourceKey{}, true)
}

func UDPPacketSourceRequired(ctx context.Context) bool {
	required, _ := ctx.Value(udpPacketSourceKey{}).(bool)
	return required
}
