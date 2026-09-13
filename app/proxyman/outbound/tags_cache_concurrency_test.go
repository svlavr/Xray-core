package outbound_test

import (
	"context"
	"sync"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	proxymanout "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/features/outbound"
)

type cacheTestHandler struct {
	outbound.Handler
	tag string
}

func (h *cacheTestHandler) Tag() string { return h.tag }
func (*cacheTestHandler) Close() error  { return nil }

// Keep the original TestTagsCache unchanged. This independent regression joins
// all workers and exercises concurrent native Select/cache invalidation only.
func TestForkTagsCacheConcurrentInvalidation(t *testing.T) {
	ctx := context.Background()
	m, err := proxymanout.New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	selectors := []string{"node-"}
	_ = m.Select(selectors) // prime the empty result
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = m.Select(selectors)
				}
			}
		})
	}
	defer func() { close(stop); wg.Wait(); _ = m.Close() }()
	for range 1000 {
		if err := m.AddHandler(ctx, &cacheTestHandler{tag: "node-A"}); err != nil {
			t.Fatal(err)
		}
		if got := m.Select(selectors); len(got) != 1 || got[0] != "node-A" {
			t.Fatalf("stale add result: %v", got)
		}
		if err := m.RemoveHandler(ctx, "node-A"); err != nil {
			t.Fatal(err)
		}
		if got := m.Select(selectors); len(got) != 0 {
			t.Fatalf("stale remove result: %v", got)
		}
	}
}
