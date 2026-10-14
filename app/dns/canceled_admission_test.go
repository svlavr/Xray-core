package dns

import (
	"context"
	"errors"
	"fmt"
	featuredns "github.com/xtls/xray-core/features/dns"
	"sync/atomic"
	"testing"
	"time"
)

// Blocking only a test context method controls the scheduling window without
// a production hook. The actual cancel state always comes from its native parent.
type delayedDNSAdmissionContext struct {
	context.Context
	calls   atomic.Int32
	gateAt  int32
	entered chan struct{}
	release chan struct{}
}

func (c *delayedDNSAdmissionContext) Err() error {
	if c.calls.Add(1) == c.gateAt {
		close(c.entered)
		<-c.release
	}
	return c.Context.Err()
}

// DoChan registers synchronously but can schedule its fresh callback late.
// Cancellation/Close before that callback admits work must start no native I/O.
func TestCachedFetchCanceledDelayedAdmissionStartsNoNewIO(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, closeOwner := range []bool{false, true} {
			t.Run(fmt.Sprintf("disabled=%v/close-before-admission=%v", disabled, closeOwner), func(t *testing.T) {
				cache := NewCacheController(t.Name(), disabled, false, 0)
				releaseWorker := make(chan struct{})
				defer func() {
					select {
					case <-releaseWorker:
					default:
						close(releaseWorker)
					}
					cache.Close()
				}()
				var attempts atomic.Int32
				server := &cancellationCachedNameserver{cache: cache}
				server.send = func(_ context.Context, _ chan<- error, fqdn string, _ featuredns.IPOption) {
					attempts.Add(1)
					cancellationTestPublish(server, fqdn)
				}
				if got := cancellationTestFetch(context.Background(), server); got.err != nil || len(got.ips) != 1 {
					t.Fatalf("first flight: %+v", got)
				}
				base, cancel := context.WithCancel(context.Background())
				defer cancel()
				delayed := &delayedDNSAdmissionContext{Context: base, gateAt: 2, entered: make(chan struct{}), release: releaseWorker}
				caller := make(chan cancellationFetchResult, 1)
				go func() { caller <- cancellationTestFetch(delayed, server) }()
				cancellationTestWait(t, delayed.entered)
				// Observe completion through native synchronous registration,
				// without inspecting private group duplicate/map state.
				observer := cache.requestGroup.DoChan("example.test.4", func() (any, error) {
					return result{error: errors.New("observer unexpectedly became leader")}, nil
				})
				if closeOwner {
					closed := make(chan struct{})
					go func() { cache.Close(); close(closed) }()
					select {
					case <-closed:
					case <-time.After(3 * time.Second):
						t.Fatal("Close waited for unadmitted callback")
					}
				} else {
					cancel()
				}
				if got := cancellationTestReceive(t, caller); !errors.Is(got.err, context.Canceled) {
					t.Fatalf("canceled delayed caller: %+v", got)
				}
				close(releaseWorker)
				select {
				case observed := <-observer:
					if got := observed.Val.(result); !errors.Is(got.error, context.Canceled) {
						t.Fatalf("admission result: %+v", got)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("native rejected callback did not finish")
				}
				joined := make(chan struct{})
				go func() { cache.workers.Wait(); close(joined) }()
				select {
				case <-joined:
				case <-time.After(3 * time.Second):
					t.Fatal("admitted work survived")
				}
				if attempts.Load() != 1 {
					t.Fatalf("rejected callback started native IO: %d", attempts.Load())
				}
				successor := cancellationTestFetch(context.Background(), server)
				if closeOwner {
					if !errors.Is(successor.err, context.Canceled) || attempts.Load() != 1 {
						t.Fatalf("post-Close publication: %+v attempts=%d", successor, attempts.Load())
					}
				} else if successor.err != nil || len(successor.ips) != 1 || attempts.Load() != 2 {
					t.Fatalf("live same-key successor: %+v attempts=%d", successor, attempts.Load())
				}
			})
		}
	}
}
