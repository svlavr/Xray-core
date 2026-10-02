package measurement_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/measurement"
)

// Isolate coordinator overhead; this benchmark performs no network operation.
func BenchmarkSeriesReceipts(b *testing.B) {
	e, err := measurement.New(new(core.Instance), 8)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, err := measurement.RunSeries(context.Background(), e, 1024, 8, func(_ context.Context, index int) (int, error) { return index, nil })
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestSeriesAttemptsPreserveReceiptsAndErrors(t *testing.T) {
	e := executor(t, instance(t))
	wantErr := errors.New("partial attempt")
	var invoked atomic.Int32
	samples, err := measurement.RunSeries(context.Background(), e, 5, 2, func(_ context.Context, index int) (string, error) {
		invoked.Add(1)
		if index == 1 {
			return "partial", wantErr
		}
		return fmt.Sprint(index), nil
	})
	if err != nil || len(samples) != 5 || invoked.Load() != 5 {
		t.Fatalf("series: samples=%v calls=%d error=%v", samples, invoked.Load(), err)
	}
	for index, sample := range samples {
		if sample.Index != index {
			t.Fatalf("unordered sample: %+v", sample)
		}
		if index == 1 {
			if sample.Receipt != "partial" || sample.Err != wantErr {
				t.Fatalf("partial facts lost: %+v", sample)
			}
		} else if sample.Receipt != fmt.Sprint(index) || sample.Err != nil {
			t.Fatalf("raw facts changed: %+v", sample)
		}
	}
}

func TestSeriesWorkerBudgetAndCancellation(t *testing.T) {
	for _, parallel := range []int{1, 3} {
		t.Run(fmt.Sprint(parallel), func(t *testing.T) {
			e, err := measurement.New(instance(t), 2)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{}, 3)
			type result struct {
				samples []measurement.Sample[int]
				err     error
			}
			done := make(chan result, 1)
			var invoked atomic.Int32
			go func() {
				samples, err := measurement.RunSeries(ctx, e, 20, parallel, func(ctx context.Context, index int) (int, error) {
					invoked.Add(1)
					entered <- struct{}{}
					<-ctx.Done()
					return index, ctx.Err()
				})
				done <- result{samples, err}
			}()
			workers := min(parallel, 2)
			for range workers {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("requested workers did not start")
				}
			}
			cancel()
			select {
			case r := <-done:
				if !errors.Is(r.err, context.Canceled) || len(r.samples) != workers || int(invoked.Load()) != workers {
					t.Fatalf("canceled series: %+v calls=%d", r, invoked.Load())
				}
				for _, sample := range r.samples {
					if sample.Receipt != sample.Index || !errors.Is(sample.Err, context.Canceled) {
						t.Fatalf("canceled attempt facts lost: %+v", sample)
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatal("series did not join canceled operations")
			}
		})
	}
}

func TestSeriesValidationAndPrecancel(t *testing.T) {
	e := executor(t, instance(t))
	op := func(context.Context, int) (int, error) { t.Error("invalid series invoked operation"); return 0, nil }
	for _, invalid := range []struct {
		count, parallel int
	}{{0, 1}, {-1, 1}, {1, 0}, {1, -1}} {
		if samples, err := measurement.RunSeries(context.Background(), e, invalid.count, invalid.parallel, op); err == nil || len(samples) != 0 {
			t.Fatalf("invalid counts: samples=%v error=%v", samples, err)
		}
	}
	for _, invalidExecutor := range []*measurement.Executor{nil, {}} {
		if _, err := measurement.RunSeries(context.Background(), invalidExecutor, 1, 1, op); err == nil {
			t.Fatal("invalid executor accepted")
		}
	}
	if _, err := measurement.RunSeries(nil, e, 1, 1, op); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := measurement.RunSeries[int](context.Background(), e, 1, 1, nil); err == nil {
		t.Fatal("nil operation accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if samples, err := measurement.RunSeries(ctx, e, 3, 2, op); !errors.Is(err, context.Canceled) || len(samples) != 0 {
		t.Fatalf("pre-cancel: samples=%v error=%v", samples, err)
	}
}

func TestSeriesCancellationJoinsUncooperativeAttempts(t *testing.T) {
	e, err := measurement.New(instance(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan int, 2)
	release := []chan struct{}{make(chan struct{}), make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(release[0]); close(release[1]) }) }
	defer unblock()
	type result struct {
		samples []measurement.Sample[int]
		err     error
	}
	done := make(chan result, 1)
	go func() {
		samples, err := measurement.RunSeries(ctx, e, 10, 2, func(_ context.Context, index int) (int, error) {
			entered <- index
			<-release[index]
			return index + 100, nil
		})
		done <- result{samples, err}
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("attempts did not start")
		}
	}
	cancel()
	select {
	case <-done:
		t.Fatal("series returned before invoked attempts joined")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case r := <-done:
		if !errors.Is(r.err, context.Canceled) || len(r.samples) != 2 {
			t.Fatalf("canceled series: %+v", r)
		}
		for index, sample := range r.samples {
			if sample.Index != index || sample.Receipt != index+100 || sample.Err != nil {
				t.Fatalf("invoked attempt's own facts changed: %+v", sample)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("series did not join released attempts")
	}
}

func TestHTTPSNodeSeriesShareExecutorLimit(t *testing.T) {
	v := instance(t)
	if err := core.AddOutboundHandler(v, config("second", false)); err != nil {
		t.Fatal(err)
	}
	e, err := measurement.New(v, 3)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var active, peak atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = io.WriteString(w, r.URL.Query().Get("node"))
		case <-r.Context().Done():
		}
	}))
	defer s.Close()
	defer unblock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		tag     string
		samples []measurement.Sample[measurement.HTTPSReceipt]
		err     error
	}
	done := make(chan result, 2)
	for _, tag := range []string{"exact", "second"} {
		go func() {
			req := request(s, measurement.ExactOutbound)
			req.Route.Tag, req.URL = tag, s.URL+"/?node="+tag
			samples, err := measurement.RunSeries(ctx, e, 4, 3, func(ctx context.Context, _ int) (measurement.HTTPSReceipt, error) {
				return e.HTTPS(ctx, req)
			})
			done <- result{tag, samples, err}
		}()
	}
	for range 3 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("shared executor did not admit three operations")
		}
	}
	unblock()
	for range 2 {
		select {
		case r := <-done:
			if r.err != nil || len(r.samples) != 4 {
				t.Fatalf("node %s series: %v, %d samples", r.tag, r.err, len(r.samples))
			}
			for _, sample := range r.samples {
				if sample.Err != nil || !sample.Receipt.BodyComplete || string(sample.Receipt.Body) != r.tag {
					t.Fatalf("node %s sample: %+v", r.tag, sample)
				}
			}
		case <-ctx.Done():
			t.Fatal("node series did not complete")
		}
	}
	if peak.Load() != 3 {
		t.Fatalf("shared parallelism: peak=%d, want 3", peak.Load())
	}
}
