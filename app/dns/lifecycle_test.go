package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

type blockingLifecycleNameServer struct {
	entered   chan struct{}
	closeCall atomic.Int32
}

func (*blockingLifecycleNameServer) Name() string         { return "blocking" }
func (*blockingLifecycleNameServer) IsDisableCache() bool { return true }
func (s *blockingLifecycleNameServer) QueryIP(ctx context.Context, _ string, _ dns_feature.IPOption) ([]net.IP, uint32, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, 0, ctx.Err()
}
func (*blockingLifecycleNameServer) SignalStop() {}
func (s *blockingLifecycleNameServer) Close() error {
	s.closeCall.Add(1)
	return nil
}

func lifecycleDNS(t *testing.T, servers ...*blockingLifecycleNameServer) *DNS {
	t.Helper()
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	clients := make([]*Client, 0, len(servers))
	for _, server := range servers {
		clients = append(clients, &Client{
			server:    server,
			timeoutMs: time.Hour,
			ipOption:  &dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true},
		})
	}
	return &DNS{
		hosts:     hosts,
		clients:   clients,
		ctx:       ctx,
		cancel:    cancel,
		closeDone: make(chan struct{}),
		ipOption:  &dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true},
	}
}

func TestDNSGenerationCloseCancelsAndJoinsLookup(t *testing.T) {
	nameServer := &blockingLifecycleNameServer{entered: make(chan struct{}, 1)}
	dns := lifecycleDNS(t, nameServer)
	lookupDone := make(chan error, 1)
	go func() {
		_, _, err := dns.LookupIPContext(context.Background(), "example.com", dns_feature.IPOption{IPv4Enable: true})
		lookupDone <- err
	}()
	<-nameServer.entered
	if err := dns.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-lookupDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lookup error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS Close did not join lookup")
	}
	if nameServer.closeCall.Load() != 1 {
		t.Fatalf("nameserver close calls = %d, want 1", nameServer.closeCall.Load())
	}
	if _, _, err := dns.LookupIPContext(context.Background(), "example.com", dns_feature.IPOption{IPv4Enable: true}); err == nil {
		t.Fatal("closed DNS generation admitted lookup")
	}
}

func TestDNSParallelChildrenRegisterBeforePublicationAndJoin(t *testing.T) {
	first := &blockingLifecycleNameServer{entered: make(chan struct{}, 1)}
	second := &blockingLifecycleNameServer{entered: make(chan struct{}, 1)}
	dns := lifecycleDNS(t, first, second)
	dns.enableParallelQuery = true
	lookupDone := make(chan error, 1)
	go func() {
		_, _, err := dns.LookupIPContext(context.Background(), "example.org", dns_feature.IPOption{IPv4Enable: true})
		lookupDone <- err
	}()
	for _, entered := range []chan struct{}{first.entered, second.entered} {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("parallel DNS child was not published")
		}
	}
	if err := dns.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lookupDone:
	case <-time.After(time.Second):
		t.Fatal("DNS Close did not join parallel children")
	}
}

type dnsLifecycleTestKey string

func TestDNSResourceContextKeepsOwnerValuesAndWhitelistsRequestValues(t *testing.T) {
	ownerKey := dnsLifecycleTestKey("owner")
	requestKey := dnsLifecycleTestKey("request")
	owner := context.WithValue(context.Background(), ownerKey, "generation")
	request := context.WithValue(context.Background(), requestKey, "operation")

	ctx := toDnsResourceContext(owner, request, "udp:127.0.0.1:53")
	if got := ctx.Value(ownerKey); got != "generation" {
		t.Fatalf("owner value = %v, want generation", got)
	}
	if got := ctx.Value(requestKey); got != nil {
		t.Fatalf("request-private value escaped into cached resource: %v", got)
	}
}
