package task

import (
	"context"

	"github.com/xtls/xray-core/common/signal/semaphore"
)

// OnSuccess executes g() after f() returns nil.
func OnSuccess(f func() error, g func() error) func() error {
	return func() error {
		if err := f(); err != nil {
			return err
		}
		return g()
	}
}

// Run executes a list of tasks in parallel, returns the first error encountered or nil if all tasks pass.
func Run(ctx context.Context, tasks ...func() error) error {
	return run(ctx, len(tasks), func(index int, _ context.Context) error {
		return tasks[index]()
	})
}

// RunWithContext executes tasks with the same first-error and no-join
// semantics as Run. Each task receives a context whose nearest participant
// tracker is the lease acquired for that task, so nested asynchronous work can
// acquire linearly before the task returns.
func RunWithContext(ctx context.Context, tasks ...func(context.Context) error) error {
	return run(ctx, len(tasks), func(index int, taskCtx context.Context) error {
		return tasks[index](taskCtx)
	})
}

func run(ctx context.Context, n int, execute func(int, context.Context) error) error {
	s := semaphore.New(n)
	done := make(chan error, 1)

	for index := 0; index < n; index++ {
		<-s.Wait()
		inheritedTracker := ParticipantTrackerFromContext(ctx)
		participant := AcquireParticipant(ctx)
		taskCtx := ctx
		if participant != nil {
			taskCtx = ContextWithParticipantTracker(ctx, participant)
		} else if inheritedTracker != nil {
			taskCtx = ContextWithoutParticipantTracker(ctx)
		}
		go func(index int, taskCtx context.Context, participant ParticipantLease) {
			var err error
			if participant != nil {
				defer func() { participant.Release(err) }()
			}
			err = execute(index, taskCtx)
			if err == nil {
				s.Signal()
				return
			}

			select {
			case done <- err:
			default:
			}
		}(index, taskCtx, participant)
	}

	/*
		if altctx := ctx.Value("altctx"); altctx != nil {
			ctx = altctx.(context.Context)
		}
	*/

	for i := 0; i < n; i++ {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-s.Wait():
		}
	}

	/*
		if cancel := ctx.Value("cancel"); cancel != nil {
			cancel.(context.CancelFunc)()
		}
	*/

	return nil
}
