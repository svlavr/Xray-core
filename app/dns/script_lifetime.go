package dns

import (
	"context"
	"errors"
	"fmt"
)

func (s *DNS) getScript() *scriptEngine {
	s.scriptMu.RLock()
	defer s.scriptMu.RUnlock()
	return s.script
}

func (s *DNS) setScript(engine *scriptEngine) {
	s.scriptMu.Lock()
	s.script = engine
	s.scriptMu.Unlock()
}

func (s *DNS) startNativeScript() error {
	if s.scriptProgram == nil {
		return nil
	}
	engine := newScriptEngineProgram(s.scriptProgram)
	if err := engine.start(s); err != nil {
		return err
	}
	s.setScript(engine)
	return nil
}

// initializeScript owns creation until the engine is installed or disposed.
// initDone is closed only after late creation can no longer escape retirement.
func (rt *dnsRuntime) initializeScript(owner *resolverOwner) <-chan error {
	result := make(chan error, 1)
	go func() {
		engine := newScriptEngineProgram(owner.resolver.scriptProgram)
		err := engine.start(owner.resolver)
		rt.mu.Lock()
		if err == nil && owner.ctx.Err() == nil {
			owner.resolver.setScript(engine)
			engine = nil
		} else if err == nil {
			err = owner.ctx.Err()
		}
		rt.mu.Unlock()
		if engine != nil {
			engine.close()
		}
		close(owner.initDone)
		result <- err
	}()
	return result
}

func (s *DNS) startRuntime() error {
	rt := s.runtime
	rt.mu.Lock()
	owner := rt.current
	if owner == nil || owner.ctx.Err() != nil {
		rt.mu.Unlock()
		return context.Canceled
	}
	if rt.started {
		rt.mu.Unlock()
		return nil
	}
	if owner.resolver.scriptProgram == nil {
		rt.started = true
		rt.mu.Unlock()
		return nil
	}
	select {
	case <-owner.initDone:
	default:
		rt.mu.Unlock()
		return fmt.Errorf("DNS script initialization in progress")
	}
	owner.initDone = make(chan struct{})
	rt.mu.Unlock()
	err := <-rt.initializeScript(owner)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if err == nil && rt.current == owner && owner.ctx.Err() == nil {
		rt.started = true
		return nil
	}
	if err == nil {
		err = context.Canceled
	}
	return err
}

// applyScript is the new script-enabled update path. Activation can perform
// external script actions; rejection preserves publication, not those actions.
func (s *DNS) applyScript(ctx context.Context, candidate *DNS) ApplyResult {
	var err error
	rt := s.runtime
	unsafe := resolverMayUseSystem(candidate)
	if unsafe && !rt.systemDNSMu.TryLock() {
		return ApplyResult{Err: fmt.Errorf("system DNS takeover prevents this DNS activation")}
	}
	rt.mu.Lock()
	var admissionErr error
	switch {
	case ctx.Err() != nil:
		admissionErr = ctx.Err()
	case rt.current == nil || rt.current.ctx.Err() != nil:
		admissionErr = context.Canceled
	case !rt.started:
		admissionErr = fmt.Errorf("script-enabled DNS update requires completed DNS.Start")
	case rt.closing != nil:
		admissionErr = fmt.Errorf("previous DNS activation or cleanup incomplete")
	}
	if admissionErr != nil {
		rt.mu.Unlock()
		if unsafe {
			rt.systemDNSMu.Unlock()
		}
		return ApplyResult{Err: admissionErr}
	}
	owner := newResolverOwner(candidate)
	owner.resolver.ctx = bindResolverContext(owner.ctx, rt, owner)
	owner.initDone = make(chan struct{})
	rt.closing = owner
	rt.mu.Unlock()
	if unsafe {
		rt.systemDNSMu.Unlock()
	}
	stopCaller := context.AfterFunc(ctx, func() {
		rt.mu.Lock()
		if rt.closing == owner && rt.current != owner {
			owner.cancel()
		}
		rt.mu.Unlock()
	})
	defer stopCaller()
	initialized := rt.initializeScript(owner)
	select {
	case err = <-initialized:
	case <-ctx.Done():
		err = ctx.Err()
	}
	rt.mu.Lock()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (owner.ctx.Err() != nil || rt.closing != owner || rt.current == nil || rt.current.ctx.Err() != nil) {
		err = context.Canceled
	}
	if err != nil {
		owner.cancel()
		rt.mu.Unlock()
		owner.startClose(rt)
		select {
		case <-owner.closeDone:
			return ApplyResult{Err: errors.Join(err, owner.closeErr)}
		case <-ctx.Done():
			return ApplyResult{Err: errors.Join(err, ctx.Err())}
		}
	}
	old := rt.current
	rt.current, rt.closing = owner, old
	old.cancel()
	rt.mu.Unlock()
	return rt.waitRetirement(ctx, old)
}

func (rt *dnsRuntime) waitRetirement(ctx context.Context, owner *resolverOwner) ApplyResult {
	owner.startClose(rt)
	select {
	case <-owner.closeDone:
		return ApplyResult{Applied: true, Err: owner.closeErr}
	case <-ctx.Done():
		return ApplyResult{Applied: true, Err: ctx.Err()}
	}
}
