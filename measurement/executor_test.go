package measurement_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/measurement"
)

func TestExecutorRejectsInvalidConcurrency(t *testing.T) {
	v := instance(t)
	for _, limit := range []int{-1, 0} {
		if e, err := measurement.New(v, limit); err == nil || e != nil {
			t.Fatalf("invalid limit %d: executor=%v error=%v", limit, e, err)
		}
	}
	if e, err := measurement.New(nil, 1); err == nil || e != nil {
		t.Fatalf("nil instance: executor=%v error=%v", e, err)
	}
}

func TestExecutorCallerConcurrencyAndSlotReuse(t *testing.T) {
	for _, limit := range []int{1, 2, 12} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			entered := make(chan struct{}, limit+1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				select {
				case <-release:
					_, _ = io.WriteString(w, "completed")
				case <-r.Context().Done():
				}
			}))
			defer s.Close()
			defer unblock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e, err := measurement.New(instance(t), limit)
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, limit)
			for i := range limit {
				kind := measurement.Direct
				if i%2 != 0 {
					kind = measurement.ExactOutbound
				}
				go func() {
					r, err := e.HTTPS(ctx, request(s, kind))
					if err == nil && (!r.BodyComplete || string(r.Body) != "completed") {
						err = fmt.Errorf("incomplete operation: %+v", r)
					}
					returned <- err
				}()
			}
			for range limit {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("configured concurrent operations did not all reach endpoint")
				}
			}
			queued := request(s, measurement.ExactOutbound)
			queued.Timeout = 50 * time.Millisecond
			if _, err := e.HTTPS(ctx, queued); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued operation: %v", err)
			}
			select {
			case <-entered:
				t.Fatal("operation exceeded caller concurrency limit")
			default:
			}
			unblock()
			for range limit {
				select {
				case err := <-returned:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("active operation did not complete")
				}
			}
			if _, err := e.HTTPS(ctx, request(s, measurement.Direct)); err != nil {
				t.Fatalf("completed slots were not reusable: %v", err)
			}
		})
	}
}
