package dns

import (
	"context"
	"errors"
	stdnet "net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type cancellationCachedNameserver struct {
	cache *CacheController
	send  func(context.Context, chan<- error, string, dns_feature.IPOption)
}

func (s *cancellationCachedNameserver) getCacheController() *CacheController { return s.cache }

func (s *cancellationCachedNameserver) sendQuery(ctx context.Context, errs chan<- error, fqdn string, option dns_feature.IPOption) {
	s.send(ctx, errs, fqdn, option)
}

type cancellationFetchResult struct {
	ips []net.IP
	err error
}

type observedDoneContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

var cancellationTestOption = dns_feature.IPOption{IPv4Enable: true}

func cancellationTestFetch(ctx context.Context, s *cancellationCachedNameserver) cancellationFetchResult {
	return cancellationTestFetchOption(ctx, s, cancellationTestOption)
}

func cancellationTestFetchOption(ctx context.Context, s *cancellationCachedNameserver, option dns_feature.IPOption) cancellationFetchResult {
	ips, _, err := fetch(ctx, s, "example.test.", option)
	return cancellationFetchResult{ips: ips, err: err}
}

func cancellationTestPublish(s *cancellationCachedNameserver, fqdn string) {
	s.cache.pub.Publish(s.cache.keyPrefix+fqdn+"4", &IPRecord{
		IP:     []net.IP{{192, 0, 2, 1}},
		Expire: time.Now().Add(time.Minute),
		RCode:  dnsmessage.RCodeSuccess,
	})
}

func cancellationTestReceive(t *testing.T, ch <-chan cancellationFetchResult) cancellationFetchResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("cached fetch did not finish")
		return cancellationFetchResult{}
	}
}

func cancellationTestWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("cached fetch did not reach its barrier")
	}
}

func cancellationTestWaitSubscriberGone(t *testing.T, cache *CacheController, key string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		remaining := dnsTestLiveSubscribers(cache, key)
		if remaining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("cached fetch did not consume its first-family response")
		}
		runtime.Gosched()
	}
}

func TestCachedFetchCanceledLeaderRawClosedErrorRetriesForLiveFollower(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("cancel leader", true, false, 0)}
	defer s.cache.Close()
	started := make(chan struct{})
	var queries atomic.Int32
	s.send = func(ctx context.Context, errs chan<- error, fqdn string, _ dns_feature.IPOption) {
		if queries.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			errs <- stdnet.ErrClosed
			return
		}
		cancellationTestPublish(s, fqdn)
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leader := make(chan cancellationFetchResult, 1)
	go func() { leader <- cancellationTestFetch(leaderCtx, s) }()
	cancellationTestWait(t, started)

	followerCtx := &observedDoneContext{Context: context.Background(), entered: make(chan struct{})}
	follower := make(chan cancellationFetchResult, 1)
	go func() { follower <- cancellationTestFetch(followerCtx, s) }()
	cancellationTestWait(t, followerCtx.entered) // the follower has joined the in-flight singleflight call
	cancelLeader()

	if got := cancellationTestReceive(t, leader); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("leader error = %v, want context cancellation", got.err)
	}
	if got := cancellationTestReceive(t, follower); got.err != nil || len(got.ips) != 1 {
		t.Fatalf("follower result = %+v, want one IP without error", got)
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("queries = %d, want canceled leader and one retry", got)
	}
}

func TestCachedFetchEmptyIPv4CanceledIPv6RetriesForLiveFollower(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("empty IPv4", true, false, 0)}
	defer s.cache.Close()
	option := dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true}
	started := make(chan struct{})
	var queries atomic.Int32
	s.send = func(_ context.Context, _ chan<- error, fqdn string, _ dns_feature.IPOption) {
		if queries.Add(1) == 1 {
			s.cache.pub.Publish(s.cache.keyPrefix+fqdn+"4", &IPRecord{Expire: time.Now().Add(time.Minute), RCode: dnsmessage.RCodeSuccess})
			close(started)
			return
		}
		cancellationTestPublish(s, fqdn)
		s.cache.pub.Publish(s.cache.keyPrefix+fqdn+"6", &IPRecord{
			IP:     []net.IP{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			Expire: time.Now().Add(time.Minute),
			RCode:  dnsmessage.RCodeSuccess,
		})
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leader := make(chan cancellationFetchResult, 1)
	go func() { leader <- cancellationTestFetchOption(leaderCtx, s, option) }()
	cancellationTestWait(t, started)
	cancellationTestWaitSubscriberGone(t, s.cache, "example.test.4")

	followerCtx := &observedDoneContext{Context: context.Background(), entered: make(chan struct{})}
	follower := make(chan cancellationFetchResult, 1)
	go func() { follower <- cancellationTestFetchOption(followerCtx, s, option) }()
	cancellationTestWait(t, followerCtx.entered)
	cancelLeader()

	if got := cancellationTestReceive(t, leader); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("leader error = %v, want context cancellation", got.err)
	}
	if got := cancellationTestReceive(t, follower); got.err != nil || len(got.ips) != 2 {
		t.Fatalf("follower result = %+v, want both IP families without error", got)
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("queries = %d, want canceled partial leader and one retry", got)
	}
}

func TestCachedFetchCanceledFollowerLeavesLeaderAlive(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("cancel follower", true, false, 0)}
	defer s.cache.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	var queries atomic.Int32
	s.send = func(ctx context.Context, _ chan<- error, fqdn string, _ dns_feature.IPOption) {
		queries.Add(1)
		close(started)
		select {
		case <-release:
			cancellationTestPublish(s, fqdn)
		case <-ctx.Done():
		case <-s.cache.ctx.Done():
		}
	}

	leader := make(chan cancellationFetchResult, 1)
	go func() { leader <- cancellationTestFetch(context.Background(), s) }()
	cancellationTestWait(t, started)

	base, cancelFollower := context.WithCancel(context.Background())
	followerCtx := &observedDoneContext{Context: base, entered: make(chan struct{})}
	follower := make(chan cancellationFetchResult, 1)
	go func() { follower <- cancellationTestFetch(followerCtx, s) }()
	cancellationTestWait(t, followerCtx.entered)
	cancelFollower()
	if got := cancellationTestReceive(t, follower); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("follower error = %v, want context cancellation", got.err)
	}

	close(release)
	if got := cancellationTestReceive(t, leader); got.err != nil || len(got.ips) != 1 {
		t.Fatalf("leader result = %+v, want one IP without error", got)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("queries = %d, want one shared query", got)
	}
}

func TestCachedFetchCoalescesOrdinarySuccess(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("coalesced", true, false, 0)}
	defer s.cache.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	var queries atomic.Int32
	s.send = func(_ context.Context, _ chan<- error, fqdn string, _ dns_feature.IPOption) {
		queries.Add(1)
		close(started)
		select {
		case <-release:
			cancellationTestPublish(s, fqdn)
		case <-s.cache.ctx.Done():
		}
	}

	leader := make(chan cancellationFetchResult, 1)
	go func() { leader <- cancellationTestFetch(context.Background(), s) }()
	cancellationTestWait(t, started)
	followerCtx := &observedDoneContext{Context: context.Background(), entered: make(chan struct{})}
	follower := make(chan cancellationFetchResult, 1)
	go func() { follower <- cancellationTestFetch(followerCtx, s) }()
	cancellationTestWait(t, followerCtx.entered)
	close(release)

	for _, ch := range []<-chan cancellationFetchResult{leader, follower} {
		if got := cancellationTestReceive(t, ch); got.err != nil || len(got.ips) != 1 {
			t.Fatalf("shared result = %+v, want one IP without error", got)
		}
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("queries = %d, want one shared query", got)
	}
}

func TestCachedFetchCloseJoinsActiveWork(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("close", true, false, 0)}
	started := make(chan struct{})
	release := make(chan struct{})
	s.send = func(_ context.Context, _ chan<- error, _ string, _ dns_feature.IPOption) {
		close(started)
		<-s.cache.ctx.Done()
		<-release
	}

	caller := make(chan cancellationFetchResult, 1)
	go func() { caller <- cancellationTestFetch(context.Background(), s) }()
	cancellationTestWait(t, started)
	closed := make(chan struct{})
	go func() { s.cache.Close(); close(closed) }()
	cancellationTestWait(t, s.cache.ctx.Done())
	select {
	case <-closed:
		t.Fatal("Close returned before active query finished")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join active query")
	}
	if got := cancellationTestReceive(t, caller); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("caller error = %v, want owner cancellation", got.err)
	}
}

func TestCachedFetchOnlyCallerCancellationReleasesWork(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("only caller", true, false, 0)}
	started := make(chan struct{})
	workDone := make(chan struct{})
	s.send = func(ctx context.Context, _ chan<- error, _ string, _ dns_feature.IPOption) {
		close(started)
		<-ctx.Done()
		close(workDone)
	}

	ctx, cancel := context.WithCancel(context.Background())
	caller := make(chan cancellationFetchResult, 1)
	go func() { caller <- cancellationTestFetch(ctx, s) }()
	cancellationTestWait(t, started)
	cancel()
	if got := cancellationTestReceive(t, caller); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("caller error = %v, want context cancellation", got.err)
	}
	s.cache.Close()
	select {
	case <-workDone:
	default:
		t.Fatal("Close returned before canceled query released its work")
	}
}

func TestCachedFetchGenuineErrorDoesNotRetry(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("genuine error", true, false, 0)}
	defer s.cache.Close()
	want := dns_feature.RCodeError(dnsmessage.RCodeNameError)
	var queries atomic.Int32
	s.send = func(_ context.Context, _ chan<- error, fqdn string, _ dns_feature.IPOption) {
		queries.Add(1)
		s.cache.pub.Publish(s.cache.keyPrefix+fqdn+"4", &IPRecord{Expire: time.Now().Add(time.Minute), RCode: dnsmessage.RCodeNameError})
	}
	got := cancellationTestFetch(context.Background(), s)
	if !errors.Is(got.err, want) {
		t.Fatalf("genuine query error = %v, want %v", got.err, want)
	}
	if n := queries.Load(); n != 1 {
		t.Fatalf("queries = %d, want no retry", n)
	}
}

func TestCachedFetchRetiredOwnerDoesNotRetry(t *testing.T) {
	s := &cancellationCachedNameserver{cache: NewCacheController("retired", true, false, 0)}
	var queries atomic.Int32
	s.send = func(_ context.Context, _ chan<- error, _ string, _ dns_feature.IPOption) {
		queries.Add(1)
	}
	s.cache.Close()
	got := cancellationTestFetch(context.Background(), s)
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("retired owner error = %v, want context cancellation", got.err)
	}
	if n := queries.Load(); n != 0 {
		t.Fatalf("queries = %d, want none after retirement", n)
	}
}

// Native response notification precedes storing the record. Keep the cache's
// read lock after sendQuery admission so this ordering is deterministic.
func TestCachedQueryPublishesBeforeCacheStore(t *testing.T) {
	cache := NewCacheController(t.Name(), false, false, 0)
	server := &cancellationCachedNameserver{cache: cache}
	locked, release := make(chan struct{}), make(chan struct{})
	unlocked, updated := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(func() {
		cancel()
		releaseStore()
		cache.Close()
		select {
		case <-locked:
			for _, done := range []<-chan struct{}{unlocked, updated} {
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("native cache update did not join after releasing its read lock")
				}
			}
		default:
		}
	})
	var sends atomic.Int32
	server.send = func(_ context.Context, errs chan<- error, fqdn string, _ dns_feature.IPOption) {
		if sends.Add(1) != 1 {
			errs <- errors.New("warm lookup started another native query")
			return
		}
		cache.RLock()
		close(locked)
		go func() {
			<-release
			cache.RUnlock()
			close(unlocked)
		}()
		go func() {
			defer close(updated)
			cache.updateRecord(&dnsRequest{reqType: dnsmessage.TypeA, domain: fqdn, start: time.Now()}, &IPRecord{
				IP: []net.IP{{192, 0, 2, 83}}, Expire: time.Now().Add(time.Minute), RCode: dnsmessage.RCodeSuccess,
			})
		}()
	}
	const domain = "publication.example"
	ips, ttl, err := queryIP(ctx, server, domain, cancellationTestOption)
	if err != nil || ttl == 0 || len(ips) != 1 || ips[0].String() != "192.0.2.83" {
		t.Fatalf("native cold result before cache store: ips=%v ttl=%d error=%v", ips, ttl, err)
	}
	select {
	case <-locked:
	default:
		t.Fatal("native query completed before the cache read-lock barrier")
	}
	// The read lock remains held. Do not acquire another RLock while the native
	// cache writer is waiting; inspect this protected map directly instead.
	if cache.ips[Fqdn(domain)] != nil {
		t.Fatal("cold query required the native cache store to complete")
	}
	releaseStore()
	select {
	case <-updated:
	case <-ctx.Done():
		t.Fatal("native cache store did not finish after releasing its read lock")
	}
	ips, ttl, err = queryIP(ctx, server, domain, cancellationTestOption)
	if err != nil || ttl == 0 || len(ips) != 1 || ips[0].String() != "192.0.2.83" || sends.Load() != 1 {
		t.Fatalf("warm native cache result: ips=%v ttl=%d sends=%d error=%v", ips, ttl, sends.Load(), err)
	}
}
