package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	fdns "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type candidateNameserver struct {
	cache *CacheController
	send  func(context.Context, chan<- error, string, fdns.IPOption)
}

func (s *candidateNameserver) getCacheController() *CacheController { return s.cache }
func (s *candidateNameserver) sendQuery(ctx context.Context, ch chan<- error, fqdn string, opt fdns.IPOption) {
	s.send(ctx, ch, fqdn, opt)
}

func candidateCache(t *testing.T) *CacheController {
	c := NewCacheController(t.Name(), false, false, 0)
	t.Cleanup(c.Close)
	return c
}

func publishCandidate(c *CacheController, fqdn string, code dnsmessage.RCode) {
	rec := &IPRecord{Expire: time.Now().Add(time.Minute), RCode: code}
	if code == dnsmessage.RCodeSuccess {
		rec.IP = []xnet.IP{{192, 0, 2, 7}}
	}
	c.pub.Publish(c.keyPrefix+fqdn+"4", rec)
}

func TestCandidateDNSConfiguredDeadline(t *testing.T) {
	c := candidateCache(t)
	s := &candidateNameserver{cache: c}
	s.send = func(ctx context.Context, _ chan<- error, fqdn string, _ fdns.IPOption) {
		d, ok := ctx.Deadline()
		if !ok || time.Until(d) < 11*time.Second {
			t.Errorf("configured 12s deadline clamped: %v", time.Until(d))
		}
		publishCandidate(c, fqdn, dnsmessage.RCodeSuccess)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	ips, _, err := fetch(ctx, s, "deadline.example.", fdns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

func TestCandidateDNSIndependentWaiterCancellation(t *testing.T) {
	c := candidateCache(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	s := &candidateNameserver{cache: c}
	s.send = func(_ context.Context, _ chan<- error, fqdn string, _ fdns.IPOption) {
		close(entered)
		go func() { <-release; publishCandidate(c, fqdn, dnsmessage.RCodeSuccess) }()
	}
	leader, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	leaderResult := make(chan error, 1)
	go func() {
		ips, _, err := fetch(leader, s, "cancel.example.", fdns.IPOption{IPv4Enable: true})
		if err == nil && len(ips) != 1 {
			err = errors.New("missing leader answer")
		}
		leaderResult <- err
	}()
	<-entered
	follower, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := fetch(follower, s, "cancel.example.", fdns.IPOption{IPv4Enable: true})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("waiter did not cancel promptly")
	}
	close(release)
	if err := <-leaderResult; err != nil {
		t.Fatal(err)
	}
}

func TestCandidateDNSLiveFollowerAfterLeaderDeadline(t *testing.T) {
	c := candidateCache(t)
	entered := make(chan struct{})
	var attempts atomic.Int32
	s := &candidateNameserver{cache: c}
	s.send = func(ctx context.Context, ch chan<- error, fqdn string, _ fdns.IPOption) {
		if attempts.Add(1) == 1 {
			close(entered)
			go func() { <-ctx.Done(); ch <- ctx.Err() }()
			return
		}
		publishCandidate(c, fqdn, dnsmessage.RCodeSuccess)
	}
	leader, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := fetch(leader, s, "retry.example.", fdns.IPOption{IPv4Enable: true}); done <- err }()
	<-entered
	follower, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	ips, _, err := fetch(follower, s, "retry.example.", fdns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || attempts.Load() != 2 {
		t.Fatalf("ips=%v err=%v attempts=%d", ips, err, attempts.Load())
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestCandidateDNSNegativeResultStaysTerminal(t *testing.T) {
	c := candidateCache(t)
	s := &candidateNameserver{cache: c}
	s.send = func(_ context.Context, _ chan<- error, fqdn string, _ fdns.IPOption) {
		publishCandidate(c, fqdn, dnsmessage.RCodeNameError)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := doFetch(ctx, s, "negative.example.", fdns.IPOption{IPv4Enable: true})
	cancel()
	if result.interrupted || result.retryableLeaderExpiry || !errors.Is(result.error, fdns.RCodeError(dnsmessage.RCodeNameError)) {
		t.Fatalf("negative result relabeled: %+v", result)
	}
}
