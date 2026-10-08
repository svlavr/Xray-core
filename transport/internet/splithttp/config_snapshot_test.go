package splithttp_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestXHTTPManagerConfigSnapshotAndNilDefaults(t *testing.T) {
	config := &splithttp.XmuxConfig{CMaxReuseTimes: &splithttp.RangeConfig{From: 2, To: 2}}
	calls := 0
	m := splithttp.NewXmuxManager(config, func() splithttp.XmuxConn { calls++; return xmuxFixtureConn{} })
	config.CMaxReuseTimes.From, config.CMaxReuseTimes.To = 1, 1
	for range 4 {
		m.GetXmuxClient(context.Background())
	}
	if calls != 2 {
		t.Fatalf("caller mutation changed the private manager snapshot: %d connections", calls)
	}
	var nilCalls, emptyCalls int
	nilManager := splithttp.NewXmuxManager(nil, func() splithttp.XmuxConn { nilCalls++; return xmuxFixtureConn{} })
	emptyManager := splithttp.NewXmuxManager(&splithttp.XmuxConfig{}, func() splithttp.XmuxConn { emptyCalls++; return xmuxFixtureConn{} })
	for range 64 {
		nilManager.GetXmuxClient(context.Background()).AddRunning()
		emptyManager.GetXmuxClient(context.Background()).AddRunning()
	}
	if nilCalls != emptyCalls || nilCalls == 0 {
		t.Fatalf("nil configuration lost native defaults: nil%d empty%d", nilCalls, emptyCalls)
	}
}

type xmuxFixtureConn struct{}

func (xmuxFixtureConn) IsClosed() bool { return false }
