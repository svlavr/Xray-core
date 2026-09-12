package flow

import "github.com/xtls/xray-core/transport/pipe"

type nativePipeLifecycle struct {
	gate *DirectionGate
}

// NativePipeLifecycle adapts the common direction gate to the dispatcher-owned
// native pipe without adding a wrapper around Reader or Writer.
func NativePipeLifecycle(gate *DirectionGate) pipe.WriteLifecycle {
	if gate == nil {
		return nil
	}
	return &nativePipeLifecycle{gate: gate}
}

func (l *nativePipeLifecycle) BeginWrite() bool { return l.gate.reserve() }
func (l *nativePipeLifecycle) CompleteWrite(reserved bool, bytes uint64) {
	l.gate.complete(reserved, l.gate.byteScope, bytes)
}
func (l *nativePipeLifecycle) HalfClose()   { l.gate.HalfClose() }
func (l *nativePipeLifecycle) Seal()        { l.gate.Seal() }
func (l *nativePipeLifecycle) MarkDrained() { l.gate.MarkDrained() }

var _ pipe.WriteLifecycle = (*nativePipeLifecycle)(nil)
