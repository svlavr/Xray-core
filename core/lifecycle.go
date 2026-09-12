package core

import (
	"github.com/xtls/xray-core/common/errors"
	common_log "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
)

type instancePhase uint8

const (
	instanceNew instancePhase = iota
	instanceStarting
	instanceRunning
	instanceRollingBack
	instanceClosing
	instanceClosed
)

// waitLifecycleCompletion waits without holding statusLock. The lock only
// arbitrates ownership of the runner and its receipt.
func (s *Instance) waitLifecycleCompletion(done <-chan struct{}) { <-done }

func (s *Instance) closeFeatures(featuresToClose []features.Feature) error {
	var errs []interface{}
	dispatcherJoined := true
	observationFinalized := true
	// Issue every supported stop/unblock signal before the first join-capable
	// Close. Owner-specific Close methods retain their normal saved receipts.
	for _, feature := range featuresToClose {
		if signaler, ok := feature.(interface{ SignalStop() }); ok {
			if err := signalFeature(signaler); err != nil {
				errs = append(errs, err)
			}
		}
	}
	phases, phaseErrs := s.shutdownPhases(featuresToClose)
	for _, err := range phaseErrs {
		errs = append(errs, err)
	}
	for phase := features.ShutdownPhasePreOwner; phase <= features.ShutdownPhaseDependency; phase++ {
		for i, feature := range featuresToClose {
			if phases[i] != phase {
				continue
			}
			var err error
			if phase == features.ShutdownPhaseDispatcher {
				if shutdown := s.observationShutdown(i, feature); shutdown != nil {
					err = joinObservationFeature(shutdown)
				} else {
					err = closeFeature(feature)
				}
			} else {
				err = closeFeature(feature)
			}
			if err != nil {
				errs = append(errs, err)
				if phase == features.ShutdownPhaseDispatcher {
					dispatcherJoined = false
				}
			}
		}
		if phase == features.ShutdownPhaseDispatcher && !dispatcherJoined {
			return combineFeatureCloseErrors(errs)
		}
	}
	// Observation stays writable through every traffic-owner receipt and is
	// finalized only after dispatcher tasks joined and dependencies released.
	for i, feature := range featuresToClose {
		if phases[i] != features.ShutdownPhaseDispatcher {
			continue
		}
		if shutdown := s.observationShutdown(i, feature); shutdown != nil {
			if err := finalizeObservationFeature(shutdown); err != nil {
				errs = append(errs, err)
				observationFinalized = false
			}
		}
	}
	if !observationFinalized {
		return combineFeatureCloseErrors(errs)
	}
	for _, phase := range []features.ShutdownPhase{features.ShutdownPhaseStats, features.ShutdownPhaseLogger} {
		for i, feature := range featuresToClose {
			if phases[i] == phase {
				if err := closeFeature(feature); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return combineFeatureCloseErrors(errs)
}

func combineFeatureCloseErrors(errs []interface{}) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.New("failed to close all features").Base(errors.New(serial.Concat(errs...)))
}

func (s *Instance) observationShutdown(i int, feature features.Feature) features.ObservationShutdown {
	if i < len(s.featureObservationShutdown) && s.featureObservationShutdown[i] != nil {
		return s.featureObservationShutdown[i]
	}
	// Direct Instance literals exist only in core tests. Preserve that narrow
	// construction path without exposing DefaultDispatcher finalization.
	shutdown, _ := feature.(features.ObservationShutdown)
	return shutdown
}

func (s *Instance) shutdownPhases(featuresToClose []features.Feature) ([]features.ShutdownPhase, []error) {
	phases := make([]features.ShutdownPhase, len(featuresToClose))
	var errs []error
	for i, feature := range featuresToClose {
		if i < len(s.featureShutdownPhases) {
			phases[i] = s.featureShutdownPhases[i]
			continue
		}
		phase, err := featureShutdownPhase(feature)
		if err != nil {
			// Cleanup must still run. Unknown/invalid legacy owners stop in the
			// earliest safe general phase while the contract error is reported.
			phase = features.ShutdownPhaseTrafficOwner
			errs = append(errs, err)
		}
		phases[i] = phase
	}
	return phases, errs
}

func featureShutdownPhase(feature features.Feature) (phase features.ShutdownPhase, err error) {
	if feature == nil {
		return features.ShutdownPhaseTrafficOwner, errors.New("nil feature has no shutdown phase")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			phase = features.ShutdownPhaseTrafficOwner
			err = errors.New("feature shutdown phase panic: ", recovered)
		}
	}()
	switch feature.(type) {
	case common_log.Handler:
		phase = features.ShutdownPhaseLogger
	case stats.Manager:
		phase = features.ShutdownPhaseStats
	case routing.Dispatcher:
		phase = features.ShutdownPhaseDispatcher
	case dns.Client, policy.Manager, routing.Router:
		phase = features.ShutdownPhaseDependency
	case inbound.Manager, outbound.Manager:
		phase = features.ShutdownPhaseTrafficOwner
	default:
		if phaser, ok := feature.(features.ShutdownPhaser); ok {
			phase = phaser.ShutdownPhase()
		} else {
			phase = features.ShutdownPhaseTrafficOwner
		}
	}
	if phase > features.ShutdownPhaseLogger {
		return features.ShutdownPhaseTrafficOwner, errors.New("invalid feature shutdown phase: ", phase)
	}
	return phase, nil
}

func joinObservationFeature(finalizer features.ObservationShutdown) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("observation owner join panic: ", recovered)
		}
	}()
	return finalizer.JoinShutdown()
}

func finalizeObservationFeature(finalizer features.ObservationShutdown) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("observation finalization panic: ", recovered)
		}
	}()
	return finalizer.FinalizeObservation()
}

func signalFeature(signaler interface{ SignalStop() }) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("feature stop signal panic: ", recovered)
		}
	}()
	signaler.SignalStop()
	return nil
}

func closeFeature(feature features.Feature) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("feature close panic: ", recovered)
		}
	}()
	return feature.Close()
}

func (s *Instance) finishLocked(phase instancePhase, startErr, closeErr error) {
	s.phase = phase
	s.running = phase == instanceRunning
	if startErr != nil {
		s.startResult = startErr
	}
	if closeErr != nil {
		s.closeResult = closeErr
	}
	done := s.lifecycleDone
	s.lifecycleDone = nil
	if done != nil {
		close(done)
	}
}

// admitFeatureStart linearizes one feature's startup right against Instance
// shutdown. Feature.Start runs outside statusLock so Close can still seal the
// transaction while an already admitted feature is blocked.
func (s *Instance) admitFeatureStart() bool {
	s.statusLock.Lock()
	admitted := s.phase == instanceStarting && !s.startupSealed
	s.statusLock.Unlock()
	return admitted
}

func (s *Instance) rollbackClosedStart() error {
	err := errors.New("instance closed while starting")
	s.statusLock.Lock()
	s.startupSealed = true
	s.phase = instanceRollingBack
	s.statusLock.Unlock()
	if s.retirementLedger != nil {
		s.retirementLedger.SealAndSnapshot()
	}
	if s.dialLifecycle != nil {
		s.dialLifecycle.Seal()
	}
	closeErr := s.closeFeatures(s.features)
	if s.dialLifecycle != nil {
		s.dialLifecycle.Wait()
	}
	if s.retirementLedger != nil {
		s.retirementLedger.Wait()
	}
	s.statusLock.Lock()
	s.finishLocked(instanceClosed, err, closeErr)
	s.statusLock.Unlock()
	return err
}

func (s *Instance) startLifecycle() (startErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.statusLock.Lock()
			s.startupSealed = true
			s.phase = instanceRollingBack
			s.statusLock.Unlock()
			if s.retirementLedger != nil {
				s.retirementLedger.SealAndSnapshot()
			}
			if s.dialLifecycle != nil {
				s.dialLifecycle.Seal()
			}
			closeErr := s.closeFeatures(s.features)
			if s.dialLifecycle != nil {
				s.dialLifecycle.Wait()
			}
			if s.retirementLedger != nil {
				s.retirementLedger.Wait()
			}
			s.statusLock.Lock()
			s.finishLocked(instanceClosed, errors.New("feature panic during start"), closeErr)
			s.statusLock.Unlock()
			panic(recovered)
		}
	}()
	for _, feature := range s.features {
		if !s.admitFeatureStart() {
			return s.rollbackClosedStart()
		}
		// Record before Start: Close is the only truthful rollback hook for a
		// feature whose Start has acquired resources before returning an error.
		if err := feature.Start(); err != nil {
			s.statusLock.Lock()
			s.startupSealed = true
			s.phase = instanceRollingBack
			s.statusLock.Unlock()
			if s.retirementLedger != nil {
				s.retirementLedger.SealAndSnapshot()
			}
			if s.dialLifecycle != nil {
				s.dialLifecycle.Seal()
			}
			closeErr := s.closeFeatures(s.features)
			if s.dialLifecycle != nil {
				s.dialLifecycle.Wait()
			}
			if s.retirementLedger != nil {
				s.retirementLedger.Wait()
			}
			result := errors.Combine(err, closeErr)
			s.statusLock.Lock()
			s.finishLocked(instanceClosed, result, closeErr)
			s.statusLock.Unlock()
			return result
		}
	}
	s.statusLock.Lock()
	if s.phase == instanceStarting && !s.startupSealed {
		s.finishLocked(instanceRunning, nil, nil)
		s.statusLock.Unlock()
		return nil
	}
	s.statusLock.Unlock()
	return s.rollbackClosedStart()
}

func (s *Instance) closeLifecycle() error {
	if s.retirementLedger != nil {
		s.retirementLedger.SealAndSnapshot()
	}
	if s.dialLifecycle != nil {
		s.dialLifecycle.Seal()
	}
	err := s.closeFeatures(s.features)
	if s.dialLifecycle != nil {
		s.dialLifecycle.Wait()
	}
	if s.retirementLedger != nil {
		s.retirementLedger.Wait()
	}
	s.statusLock.Lock()
	s.finishLocked(instanceClosed, nil, err)
	s.statusLock.Unlock()
	return err
}

// Start starts each feature exactly once. Feature Start and callbacks never run
// under statusLock; concurrent callers receive the first runner's receipt.
func (s *Instance) Start() error {
	for {
		s.statusLock.Lock()
		switch s.phase {
		case instanceNew:
			s.phase = instanceStarting
			s.lifecycleDone = make(chan struct{})
			s.statusLock.Unlock()
			err := s.startLifecycle()
			if err == nil {
				errors.LogWarning(s.ctx, "Xray ", Version(), " started")
			}
			return err
		case instanceStarting, instanceRollingBack:
			done := s.lifecycleDone
			s.statusLock.Unlock()
			s.waitLifecycleCompletion(done)
			s.statusLock.Lock()
			err := s.startResult
			s.statusLock.Unlock()
			return err
		case instanceClosing:
			done := s.lifecycleDone
			s.statusLock.Unlock()
			s.waitLifecycleCompletion(done)
		case instanceRunning:
			s.statusLock.Unlock()
			return s.startResult
		case instanceClosed:
			s.statusLock.Unlock()
			return errors.New("instance is closed")
		}
	}
}

// Close is one serialized cleanup transaction. During Start it seals later
// feature admissions and waits while the startup runner retains rollback
// ownership. It only reports CLOSED after every adopted feature is closed.
func (s *Instance) Close() error {
	for {
		s.statusLock.Lock()
		switch s.phase {
		case instanceNew, instanceRunning:
			s.startupSealed = true
			s.phase = instanceClosing
			s.running = false
			s.lifecycleDone = make(chan struct{})
			s.statusLock.Unlock()
			return s.closeLifecycle()
		case instanceStarting:
			// The startup runner retains cleanup ownership, but Close wins all
			// later feature admissions before sealing external lifecycle owners.
			s.startupSealed = true
			s.phase = instanceRollingBack
			if s.retirementLedger != nil {
				s.retirementLedger.SealAndSnapshot()
			}
			if s.dialLifecycle != nil {
				s.dialLifecycle.Seal()
			}
			done := s.lifecycleDone
			s.statusLock.Unlock()
			s.waitLifecycleCompletion(done)
		case instanceRollingBack, instanceClosing:
			s.startupSealed = true
			if s.retirementLedger != nil {
				s.retirementLedger.SealAndSnapshot()
			}
			if s.dialLifecycle != nil {
				s.dialLifecycle.Seal()
			}
			done := s.lifecycleDone
			s.statusLock.Unlock()
			s.waitLifecycleCompletion(done)
		case instanceClosed:
			err := s.closeResult
			s.statusLock.Unlock()
			return err
		}
	}
}
