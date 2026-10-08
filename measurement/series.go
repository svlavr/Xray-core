package measurement

import (
	"context"
	"errors"
	"sync"
)

// Sample preserves one invoked operation's receipt and error. Index is its
// zero-based position in the caller-requested series, not a success counter.
type Sample[T any] struct {
	Index   int
	Receipt T
	Err     error
}

// RunSeries invokes operation up to count times using at most parallel workers.
// operation must call a measurement method on e with the supplied context;
// its closure or index chooses the request and route. Those methods retain
// ownership of admission, so simultaneous series share e's execution limit.
// A series worker budget may be lower than that shared limit.
//
// Failures consume attempts without retry. Cancellation stops new work, joins
// invoked operations and returns their raw results ordered by Index. Unstarted
// attempts have no fabricated sample. The outer error reports invalid input or
// caller cancellation; operation errors remain in Sample.Err.
//
// The caller budgets both count and retained receipt data: result storage grows
// with invoked attempts and may include each receipt's bounded response body.
// No periodic scheduling, derived statistics or node-selection policy is added.
func RunSeries[T any](ctx context.Context, e *Executor, count, parallel int, operation func(context.Context, int) (T, error)) ([]Sample[T], error) {
	if ctx == nil || e == nil || cap(e.slots) == 0 || operation == nil || count <= 0 || parallel <= 0 {
		return nil, errors.New("invalid measurement series")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	workers := min(count, parallel, cap(e.slots))
	// Workers claim each index once and publish only invoked attempts. The
	// mutex protects these two small state changes, never the operation itself.
	var mu sync.Mutex
	var samples []Sample[T]
	var active sync.WaitGroup
	for range workers {
		active.Add(1)
		go func() {
			defer active.Done()
			for {
				mu.Lock()
				if len(samples) == count || ctx.Err() != nil {
					mu.Unlock()
					return
				}
				index := len(samples)
				samples = append(samples, Sample[T]{Index: index})
				mu.Unlock()
				receipt, err := operation(ctx, index)
				mu.Lock()
				samples[index].Receipt, samples[index].Err = receipt, err
				mu.Unlock()
			}
		}()
	}
	active.Wait()
	return samples, ctx.Err()
}
