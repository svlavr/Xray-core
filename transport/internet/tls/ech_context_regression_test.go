package tls

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http2"
)

type echContextDialer struct {
	dial func(context.Context, net.Destination, *internet.SocketConfig) (net.Conn, error)
}

func (d echContextDialer) Dial(ctx context.Context, _ net.Address, dest net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	return d.dial(ctx, dest, sockopt)
}

func (echContextDialer) DestIpAddress() net.IP { return nil }

func TestECHH2CForwardsDialContext(t *testing.T) {
	// Do not run in parallel: the native system dialer is process-wide.
	sockopt := &internet.SocketConfig{}
	server := "h2c://resolver.invalid:8443/dns-query"
	key := ECHCacheKey(server, "", sockopt)
	stopped := errors.New("fixture stops before network I/O")
	var seen context.Context
	internet.UseAlternativeSystemDialer(echContextDialer{dial: func(ctx context.Context, dest net.Destination, options *internet.SocketConfig) (net.Conn, error) {
		seen = ctx
		if dest.Address.Domain() != "resolver.invalid" || dest.Port != 8443 || options != sockopt {
			t.Errorf("destination/options changed: %v", dest)
		}
		if session.MitmServerNameFromContext(ctx) != "resolver.invalid" || session.MitmAlpn11FromContext(ctx) {
			t.Error("h2c host/ALPN metadata missing")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, stopped
	}})
	t.Cleanup(func() {
		internet.UseAlternativeSystemDialer(nil)
		if client, ok := clientForECHDOH.LoadAndDelete(key); ok {
			client.CloseIdleConnections()
		}
	})
	if _, _, err := dnsQuery(server, "target.invalid", sockopt); err == nil || seen == nil {
		t.Fatalf("query did not reach native dial owner: %v", err)
	}
	client, _ := clientForECHDOH.Load(key)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Transport.(*http2.Transport).DialTLSContext(ctx, "tcp", "resolver.invalid:8443", nil)
	if !errors.Is(err, context.Canceled) || seen.Err() != context.Canceled {
		t.Fatalf("derived transport context lost cancellation: %v", err)
	}
}
