package mux

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type u2ContextProxy struct {
	contexts chan context.Context
	release  chan struct{}
}

func (p *u2ContextProxy) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	p.contexts <- ctx
	<-p.release
	common.Interrupt(link.Reader)
	_ = common.Close(link.Writer)
	return nil
}

func TestU2FactoryDetachedContext(t *testing.T) {
	type sentinelKey struct{}
	instance := new(core.Instance)
	for _, mode := range []string{"nil", "no-instance", "user", "internal", "measurement"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), sentinelKey{}, "caller-only")
			var want *core.Instance
			if mode != "nil" && mode != "no-instance" {
				want = instance
				ctx = context.WithValue(ctx, core.XrayKey(1), instance)
			}
			origin := session.TrafficOriginUser
			if mode == "internal" {
				origin = session.TrafficOriginInternal
			}
			if mode == "measurement" {
				origin = session.TrafficOriginControlledMeasurement
			}
			ctx = session.ContextWithTrafficOrigin(ctx, origin)
			ctx = session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{})
			ctx = session.ContextWithInbound(ctx, &session.Inbound{})
			ctx = session.ContextWithContent(ctx, &session.Content{})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 80)}})
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			cancel()
			if mode == "nil" {
				ctx = nil
			}
			proxy := &u2ContextProxy{contexts: make(chan context.Context, 1), release: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(proxy.release) }) }
			defer release()
			factory := &DialingWorkerFactory{Context: ctx, Proxy: proxy}
			worker, err := factory.Create()
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			var actual context.Context
			select {
			case actual = <-proxy.contexts:
			case <-time.After(time.Second):
				t.Fatal("carrier Process not started")
			}
			_, deadline := actual.Deadline()
			if core.FromContext(actual) != want || actual.Err() != nil || deadline || actual.Value(sentinelKey{}) != nil || session.TrafficOriginFromContext(actual) != session.TrafficOriginUnknown || session.LogicalObservationFromContext(actual) != nil || session.InboundFromContext(actual) != nil || session.ContentFromContext(actual) != nil {
				t.Fatal("carrier inherited caller lifetime or metadata, or lost instance")
			}
			outbounds := session.OutboundsFromContext(actual)
			if len(outbounds) != 1 || outbounds[0].Target != net.TCPDestination(muxCoolAddress, muxCoolPort) {
				t.Fatalf("synthetic carrier target: %+v", outbounds)
			}
			release()
			select {
			case <-actual.Done():
			case <-time.After(time.Second):
				t.Fatal("completed carrier retained local context")
			}
		})
	}
}
