package dns

import (
	"context"
	"fmt"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	featuredns "github.com/xtls/xray-core/features/dns"
)

type gatedSealServer struct {
	*silentCachedServer
	entered chan struct{}
	proceed chan struct{}
	calls   atomic.Int32
}

func (s *gatedSealServer) getCacheController() *CacheController {
	if s.calls.Add(1) == 1 {
		close(s.entered)
		<-s.proceed
	}
	return s.cache
}

func TestApplyPublicationCloseJoinsUnfinishedHandoff(t *testing.T) {
	server := &gatedSealServer{
		silentCachedServer: &silentCachedServer{cache: NewCacheController("publication", true, false, 0)},
		entered:            make(chan struct{}), proceed: make(chan struct{}),
	}
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(server.proceed) }) })
	d := newGenerationTestDNS(server)
	applied := make(chan ApplyResult, 1)
	go func() { applied <- ApplyConfig(context.Background(), d, staticConfig("new.test", 2)) }()
	select {
	case <-server.entered:
	case <-time.After(time.Second):
		t.Fatal("apply did not reach post-publication sealing")
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	var closeErr error
	early := false
	select {
	case closeErr = <-closed:
		early = true
	case <-time.After(30 * time.Millisecond):
	}
	unblock.Do(func() { close(server.proceed) })
	var result ApplyResult
	select {
	case result = <-applied:
	case <-time.After(time.Second):
		t.Fatal("apply did not finish")
	}
	if !early {
		select {
		case closeErr = <-closed:
		case <-time.After(time.Second):
			t.Fatal("whole close did not join the handoff")
		}
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if early {
		t.Fatal("whole Close returned before Apply could launch its retirement worker")
	}
	if result.Disposition != ApplyApplied || result.Retirement == nil {
		t.Fatalf("published apply result: %+v", result)
	}
	receipt := result.Retirement
	if retired := receipt.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal {
		t.Fatalf("closed generation receipt: %+v", retired)
	}
	receipt.mu.Lock()
	retainsRetry := receipt.retry != nil
	receipt.mu.Unlock()
	if retainsRetry {
		t.Fatal("terminal receipt retained/reinstalled the generation retry closure")
	}
}

func TestUDPTruncatedSuccessPreservesTransferredRay(t *testing.T) {
	dispatcher := new(dnsUDPContextDispatcher)
	server := NewClassicNameServer(net.UDPDestination(net.DomainAddress("resolver.test"), 53), dispatcher, true, false, 0, nil)
	t.Cleanup(func() { server.Close() })
	for _, suffix := range []byte{1, 2} {
		ctx := boundLookupContext(suffix)
		domain := fmt.Sprintf("query-%d.test.", suffix)
		server.sendQuery(ctx, nil, domain, featuredns.IPOption{IPv4Enable: true})
		server.Lock()
		var original *udpDnsRequest
		for _, request := range server.requests {
			if request.domain == domain {
				original = request
			}
		}
		server.Unlock()
		if original == nil || original.resource == nil {
			t.Fatal("query did not create a resource-owned pending request")
		}
		owner := original.resource
		server.handleResponse(ctx, truncatedUDPResponse(t, original.msg.ID), nil)
		server.Lock()
		var retried *udpDnsRequest
		for _, request := range server.requests {
			if request.domain == domain {
				retried = request
			}
		}
		server.Unlock()
		if retried == nil || retried.msg.ID == original.msg.ID || retried.resource != owner || len(retried.msg.Additionals) != 1 {
			t.Fatal("EDNS retry did not retain the transferred resource owner")
		}
		response := &mdns.Msg{MsgHdr: mdns.MsgHdr{Id: retried.msg.ID, Response: true}, Answer: []mdns.RR{
			&mdns.A{Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30}, A: stdnet.IPv4(192, 0, 2, suffix)},
		}}
		wire, err := response.Pack()
		if err != nil {
			t.Fatal(err)
		}
		server.handleResponse(ctx, &udp_proto.Packet{Payload: buf.FromBytes(wire)}, nil)
		select {
		case <-owner.finishAsync():
		case <-time.After(time.Second):
			t.Fatal("completed retry resource did not close")
		}
		server.Lock()
		pending, resources := len(server.requests), len(server.resourceOwners)
		server.Unlock()
		if pending != 0 || resources != 0 {
			t.Fatalf("completed retry retained owners: pending=%d resources=%d", pending, resources)
		}
	}
	dispatcher.mu.Lock()
	lookups := append([]net.IP(nil), dispatcher.lookups...)
	dispatcher.mu.Unlock()
	if len(lookups) != 2 || !lookups[0].Equal(net.IP{192, 0, 2, 1}) || !lookups[1].Equal(net.IP{192, 0, 2, 2}) {
		t.Fatalf("retries escaped their query rays or reused a stale binding: %v", lookups)
	}
}

func TestRetirementTerminalResultCannotBeRevertedByRetry(t *testing.T) {
	receipt := newRetirementReceipt(1)
	entered, proceed := make(chan struct{}), make(chan struct{})
	receipt.retry = func() RetirementResult {
		close(entered)
		<-proceed
		return RetirementResult{Generation: 1, Disposition: RetireFailed, Failure: FailureCleanup}
	}
	receipt.complete(RetirementResult{Generation: 1, Disposition: RetireFailed, Failure: FailureCleanup})
	done := make(chan RetirementResult, 1)
	go func() { done <- receipt.Retry(contextWithTimeout(t, time.Second)) }()
	<-entered
	// A whole-feature Close can successfully complete a later serialized
	// resource attempt before this retry publishes its older failed result.
	receipt.complete(RetirementResult{Generation: 1, Disposition: Retired, Terminal: true})
	close(proceed)
	if result := <-done; !result.Terminal || result.Disposition != Retired {
		t.Fatalf("older retry reverted terminal completion: %+v", result)
	}
	if result := receipt.Wait(context.Background()); !result.Terminal {
		t.Fatalf("receipt no longer terminal: %+v", result)
	}
}
