package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.zx2c4.com/wireguard/conn"
)

type resolveLegacyClient struct {
	dns.Client
	lookup func(string, dns.IPOption) ([]net.IP, uint32, error)
}

func (c *resolveLegacyClient) LookupIP(host string, option dns.IPOption) ([]net.IP, uint32, error) {
	return c.lookup(host, option)
}

type resolveCapableClient struct {
	*resolveLegacyClient
	lookupContext func(context.Context, string, dns.IPOption) ([]net.IP, uint32, error)
}

func (c *resolveCapableClient) LookupIPContext(ctx context.Context, host string, option dns.IPOption) ([]net.IP, uint32, error) {
	return c.lookupContext(ctx, host, option)
}

func TestWireGuardEndpointResolveCapableCancellation(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "native"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan context.Context, 1)
			exited := make(chan struct{})
			client := &resolveCapableClient{
				resolveLegacyClient: &resolveLegacyClient{lookup: func(string, dns.IPOption) ([]net.IP, uint32, error) {
					return nil, 0, errors.New("capable client used legacy lookup")
				}},
				lookupContext: func(ctx context.Context, host string, option dns.IPOption) ([]net.IP, uint32, error) {
					if host == "sibling.test" {
						return []net.IP{net.ParseIP("192.0.2.2")}, 60, nil
					}
					defer close(exited)
					entered <- ctx
					<-ctx.Done()
					return nil, 0, ctx.Err()
				},
			}
			parent := context.Background()
			if selected {
				parent = internet.ContextWithMUTransport(parent)
			}
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			b := &bind{ctx: ctx, resolveFunc: MakeResolveLocal(client, &internet.MemoryStreamConfig{})}
			result := make(chan error, 1)
			go func() {
				_, err := b.ParseEndpoint("blocked.test:51820")
				result <- err
			}()
			select {
			case actual := <-entered:
				if actual != ctx {
					t.Fatal("DNS did not receive the endpoint caller context")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("endpoint resolution did not enter capable DNS")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("endpoint cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("endpoint waiter survived cancellation")
			}
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				t.Fatal("capable DNS work survived cancellation")
			}
			b.SetCtx(parent)
			endpoint, err := b.ParseEndpoint("sibling.test:51821")
			if err != nil {
				t.Fatal(err)
			}
			want := netip.MustParseAddrPort("192.0.2.2:51821")
			if got := endpoint.(*conn.StdNetEndpoint).AddrPort; got.Addr().Unmap() != want.Addr().Unmap() || got.Port() != want.Port() {
				t.Fatalf("live sibling endpoint: %v", got)
			}
		})
	}
}

func TestWireGuardEndpointResolveLegacyCancellationKeepsSibling(t *testing.T) {
	entered := make(chan struct{})
	exited := make(chan struct{})
	release := make(chan struct{}, 1)
	defer close(release)
	client := &resolveLegacyClient{lookup: func(host string, option dns.IPOption) ([]net.IP, uint32, error) {
		if host == "sibling.test" {
			return []net.IP{net.ParseIP("192.0.2.2")}, 60, nil
		}
		defer close(exited)
		close(entered)
		<-release
		return []net.IP{net.ParseIP("192.0.2.1")}, 60, nil
	}}
	ctx, cancel := context.WithCancel(internet.ContextWithMUTransport(context.Background()))
	defer cancel()
	b := &bind{ctx: ctx, resolveFunc: MakeResolveLocal(client, &internet.MemoryStreamConfig{})}
	result := make(chan error, 1)
	go func() {
		_, err := b.ParseEndpoint("blocked.test:51820")
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint resolution did not enter legacy DNS")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("endpoint cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint waiter remained blocked on legacy DNS")
	}
	select {
	case <-exited:
		t.Fatal("legacy DNS unexpectedly exited before fixture release")
	default:
	}
	b.SetCtx(internet.ContextWithMUTransport(context.Background()))
	endpoint, err := b.ParseEndpoint("sibling.test:51821")
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddrPort("192.0.2.2:51821")
	if got := endpoint.(*conn.StdNetEndpoint).AddrPort; got.Addr().Unmap() != want.Addr().Unmap() || got.Port() != want.Port() {
		t.Fatalf("live sibling endpoint: %v", got)
	}
	// Release the owned legacy operation and join it; cancellation only bounded
	// its caller's wait and could not terminate this implementation's lookup.
	release <- struct{}{}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("released legacy DNS did not exit")
	}
}

func TestWireGuardEndpointResolvePreCanceledAndLiteral(t *testing.T) {
	var lookups atomic.Int32
	client := &resolveLegacyClient{lookup: func(string, dns.IPOption) ([]net.IP, uint32, error) {
		lookups.Add(1)
		return nil, 0, errors.New("unexpected DNS lookup")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &bind{ctx: ctx, resolveFunc: MakeResolveLocal(client, &internet.MemoryStreamConfig{})}
	if _, err := b.ParseEndpoint("blocked.test:51820"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled endpoint: %v", err)
	}
	endpoint, err := b.ParseEndpoint("[2001:db8::1]:51820")
	if err != nil {
		t.Fatal(err)
	}
	if got := endpoint.(*conn.StdNetEndpoint).AddrPort; got != netip.MustParseAddrPort("[2001:db8::1]:51820") {
		t.Fatalf("literal endpoint: %v", got)
	}
	if got := lookups.Load(); got != 0 {
		t.Fatalf("pre-canceled/literal endpoint started %d DNS lookups", got)
	}
}

func TestWireGuardEndpointResolveAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy internet.DomainStrategy
		ips      []net.IP
		want     string
	}{
		{"ipv4", internet.DomainStrategy_USE_IP4, []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}, "192.0.2.1:51820"},
		{"ipv6", internet.DomainStrategy_FORCE_IP6, []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, "[2001:db8::1]:51820"},
		{"prefer4-fallback", internet.DomainStrategy_USE_IP46, []net.IP{net.ParseIP("2001:db8::1")}, "[2001:db8::1]:51820"},
		{"prefer6-fallback", internet.DomainStrategy_USE_IP64, []net.IP{net.ParseIP("192.0.2.1")}, "192.0.2.1:51820"},
		{"empty4", internet.DomainStrategy_FORCE_IP4, []net.IP{net.ParseIP("2001:db8::1")}, ""},
		{"empty6", internet.DomainStrategy_USE_IP6, []net.IP{net.ParseIP("192.0.2.1")}, ""},
		{"empty", internet.DomainStrategy_AS_IS, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &resolveLegacyClient{lookup: func(host string, option dns.IPOption) ([]net.IP, uint32, error) {
				if host != "endpoint.test" || !option.IPv4Enable || !option.IPv6Enable || option.FakeEnable {
					return nil, 0, errors.New("unexpected endpoint lookup options")
				}
				return tc.ips, 60, nil
			}}
			settings := &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{DomainStrategy: tc.strategy}}
			b := &bind{ctx: context.Background(), resolveFunc: MakeResolveLocal(client, settings)}
			endpoint, err := b.ParseEndpoint("endpoint.test:51820")
			if tc.want == "" {
				if !errors.Is(err, dns.ErrEmptyResponse) {
					t.Fatalf("empty family: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Native ParseIP and AddrFromSlice retain IPv4-mapped addresses.
			want := netip.MustParseAddrPort(tc.want)
			if got := endpoint.(*conn.StdNetEndpoint).AddrPort; got.Addr().Unmap() != want.Addr().Unmap() || got.Port() != want.Port() {
				t.Fatalf("endpoint family: %v, want %s", got, tc.want)
			}
		})
	}
}
