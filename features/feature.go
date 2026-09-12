package features

import (
	"github.com/xtls/xray-core/common"
)

// Feature is the interface for Xray features. All features must implement this interface.
// All existing features have an implementation in app directory. These features can be replaced by third-party ones.
type Feature interface {
	common.HasType
	common.Runnable
}

// ShutdownPhase describes the dependency position of a Feature during an
// Instance shutdown. Feature remains source-compatible: implementations only
// need ShutdownPhaser when the canonical role inferred by core is not enough.
type ShutdownPhase uint8

const (
	ShutdownPhasePreOwner ShutdownPhase = iota
	ShutdownPhaseTrafficOwner
	ShutdownPhaseDispatcher
	ShutdownPhaseDependency
	ShutdownPhaseStats
	ShutdownPhaseLogger
)

// ShutdownPhaser assigns a role when a Feature has no canonical role inferred
// from its stable interface. Canonical dispatcher, manager, dependency, stats
// and logger roles take precedence. Unknown legacy features are traffic owners.
type ShutdownPhaser interface {
	ShutdownPhase() ShutdownPhase
}

// ObservationShutdown is an exclusive capability retained by Instance. It
// separates a dispatcher's owner-task join from final observation shutdown.
type ObservationShutdown interface {
	JoinShutdown() error
	FinalizeObservation() error
}

// ObservationShutdownAdopter transfers finalization authority before the
// Feature is published by Instance. A failed adoption transfers no ownership.
type ObservationShutdownAdopter interface {
	AdoptObservationShutdown() (ObservationShutdown, error)
}
