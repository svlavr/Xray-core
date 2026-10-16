package dns

import (
	"context"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

func dnsTestContext(t testing.TB) context.Context {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.AddFeature(new(preparationDispatcher)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func dnsTestResolver(s *DNS, r *resolver) *resolver {
	r.owner = s
	r.ctx, r.cancel = context.WithCancel(context.WithValue(s.ctx, resolverContextKey{}, r))
	r.done = make(chan struct{})
	r.initialized = make(chan struct{})
	close(r.initialized)
	return r
}

func dnsTestFeature(t testing.TB, r *resolver) *DNS {
	t.Helper()
	if r.owner != nil {
		return r.owner
	}
	s := &DNS{ctx: dnsTestContext(t), pub: pubsub.NewService()}
	s.active = dnsTestResolver(s, r)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func dnsTestPrepare(t testing.TB, c *Config, d *preparationDispatcher, f featuredns.FakeDNSEngine) (*resolver, error) {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.AddFeature(d); err != nil {
		t.Fatal(err)
	}
	if f != nil {
		if err := instance.AddFeature(f); err != nil {
			t.Fatal(err)
		}
	}
	s := &DNS{ctx: context.WithValue(context.Background(), core.XrayKey(1), instance), pub: pubsub.NewService()}
	if err := s.requireReady(c); err != nil {
		return nil, err
	}
	r, err := s.newResolver(proto.Clone(c).(*Config), nil)
	if err == nil {
		s.active = r
		t.Cleanup(func() { _ = s.Close() })
	}
	return r, err
}

func dnsTestWaitRetirement(ctx context.Context, r *resolver) ApplyResult {
	select {
	case <-r.done:
		return ApplyResult{Applied: true, Err: r.closeErr}
	case <-ctx.Done():
		return ApplyResult{Applied: true, Err: ctx.Err()}
	}
}

// Inspect the restored native service under its mutex, counting only live
// subscriptions; closed channels remain indexed until native Cleanup runs.
func dnsTestLiveSubscribers(c *CacheController, key string) int {
	_ = c.pub.Cleanup()
	c.pub.RLock()
	defer c.pub.RUnlock()
	entry := reflect.ValueOf(c.pub).Elem().FieldByName("subs").MapIndex(reflect.ValueOf(c.keyPrefix + key))
	if entry.IsValid() {
		return entry.Len()
	}
	return 0
}

func dnsTestSubscribers(c *CacheController) int {
	return dnsTestLiveSubscribers(c, "pending.test.4") + dnsTestLiveSubscribers(c, "pending.test.6")
}

func TestStageBUDPNativeTruncationRetry(t *testing.T) {
	dispatcher := &stageBUDPDispatcher{first: make(chan struct{}), truncateFirst: true}
	server := stageBUDPServer(t, dispatcher)
	base := dnsTestContext(t)
	ips, _, err := server.QueryIP(base, "truncated.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal([]byte{192, 0, 2, 81}) {
		t.Fatalf("truncation: %v %v", ips, err)
	}
	if dispatcher.writes.Load() != 2 {
		t.Fatalf("normal plus EDNS retry: %d", dispatcher.writes.Load())
	}
}
