package inbound

import "context"

// PacketContext retains request values while a protocol's own association may
// outlive the first UDP source endpoint. Only the listener cancels this parent.
func (c *udpConn) PacketContext(values context.Context) context.Context {
	if c.packetCtx == nil {
		return values
	}
	return udpPacketContext{Context: c.packetCtx, values: context.WithoutCancel(values)}
}

type udpPacketContext struct {
	context.Context
	values context.Context
}

func (c udpPacketContext) Value(key any) any { return c.values.Value(key) }

// Allow WithCancel's propagation to use the listener without a waiter goroutine
// for each child, despite the separate request-value ancestry.
func (c udpPacketContext) AfterFunc(f func()) func() bool {
	return context.AfterFunc(c.Context, f)
}
