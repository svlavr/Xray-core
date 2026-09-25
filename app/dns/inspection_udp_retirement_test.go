package dns

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	dnsproto "github.com/xtls/xray-core/common/protocol/dns"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type observedRetirementReader struct {
	response    chan buf.MultiBuffer
	waiting     chan struct{}
	release     chan struct{}
	waitOnce    sync.Once
	reads       atomic.Int32
	interrupted atomic.Int32
}

func (r *observedRetirementReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.reads.Add(1) == 1 {
		return <-r.response, nil
	}
	r.waitOnce.Do(func() { close(r.waiting) })
	<-r.release
	return nil, io.EOF
}

func (r *observedRetirementReader) Interrupt() { r.interrupted.Add(1) }

type observedRetirementWriter struct{ reader *observedRetirementReader }

func (w *observedRetirementWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if len(mb) == 0 {
		return nil
	}
	request := new(mdns.Msg)
	err := request.Unpack(mb[0].Bytes())
	buf.ReleaseMulti(mb)
	if err != nil {
		return err
	}
	response := new(mdns.Msg)
	response.SetReply(request)
	record, err := mdns.NewRR(request.Question[0].Name + " 60 IN A 192.0.2.88")
	if err != nil {
		return err
	}
	response.Answer = append(response.Answer, record)
	wire, err := response.Pack()
	if err != nil {
		return err
	}
	w.reader.response <- buf.MultiBuffer{buf.FromBytes(wire)}
	return nil
}

func (*observedRetirementWriter) Interrupt() {}

type observedRetirementDispatcher struct {
	routing.Dispatcher
	reader *observedRetirementReader
	writer *observedRetirementWriter
}

func (*observedRetirementDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*observedRetirementDispatcher) Start() error      { return nil }
func (*observedRetirementDispatcher) Close() error      { return nil }
func (d *observedRetirementDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return &transport.Link{Reader: d.reader, Writer: d.writer}, nil
}

func (*observedRetirementDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

type observedGatedLeg struct {
	dnsTCPTestExchange
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (e *observedGatedLeg) Finish() {
	if e.calls.Add(1) == 2 {
		e.once.Do(func() { close(e.started); <-e.release })
	}
	e.dnsTCPTestExchange.Finish()
}

type observedGatedRoot struct {
	dnsTCPTestExchange
	leg *observedGatedLeg
}

func (*observedGatedRoot) Ref() featurestats.FlowRef       { return featurestats.FlowRef{ID: 1} }
func (e *observedGatedRoot) NewLeg() featurestats.Exchange { return e.leg }

func TestObservedUDPGenerationRetirementWaitsForReaderJoin(t *testing.T) {
	reader := &observedRetirementReader{response: make(chan buf.MultiBuffer, 1), waiting: make(chan struct{}), release: make(chan struct{})}
	dispatcher := &observedRetirementDispatcher{reader: reader}
	dispatcher.writer = &observedRetirementWriter{reader: reader}
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dispatcher, true, false, 0, nil)
	stable := newGenerationTestDNS(server)
	generation, rootLease, err := stable.acquireCurrent()
	if err != nil {
		t.Fatal(err)
	}
	bound := generation.bind(context.Background(), rootLease)
	leg := &observedGatedLeg{started: make(chan struct{}), release: make(chan struct{})}
	root := &observedGatedRoot{leg: leg}
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(leg.release) }); _ = stable.Close() })
	routed, owner := beginRoutedDNSUDPObservationWithStore(bound, bound, server, *server.address, 1, make(chan error, 1), &udpBeginStore{exchange: root})
	if owner == nil {
		t.Fatal("observed owner missing")
	}
	reserved, release, err := dnsfeature.ReserveContextBinding(bound)
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := buildReqMsgs("observed-retire.test.", dnsfeature.IPOption{IPv4Enable: true}, server.newReqID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := &udpDnsRequest{dnsRequest: *reqs[0], ctx: reserved, owner: owner, release: release, resource: owner.resource}
	if !server.addPendingRequest(req) {
		t.Fatal("pending request rejected")
	}
	rootLease.release()
	packet, err := dnsproto.PackMessage(req.msg)
	if err != nil {
		t.Fatal(err)
	}
	owner.dispatcher.Dispatch(routed, *server.address, packet)
	select {
	case <-leg.started:
	case <-time.After(time.Second):
		t.Fatal("observed leg did not reach gated Finish")
	}
	generation.mu.Lock()
	leases := generation.leases
	generation.mu.Unlock()
	if leases != 0 {
		t.Fatalf("test must gate reader exit after lease release, leases=%d", leases)
	}
	apply := ApplyConfig(context.Background(), stable, staticConfig("new.test", 6))
	if apply.Disposition != ApplyApplied {
		t.Fatalf("apply: %+v", apply)
	}
	if wait := apply.Retirement.Wait(contextWithTimeout(t, 20*time.Millisecond)); wait.Disposition != WaitIncomplete || wait.Terminal {
		t.Fatalf("retired before observed reader joined: %+v", wait)
	}
	unblock.Do(func() { close(leg.release) })
	if retired := apply.Retirement.Wait(contextWithTimeout(t, time.Second)); retired.Disposition != Retired || !retired.Terminal {
		t.Fatalf("retirement after reader join: %+v", retired)
	}
	server.RLock()
	resources := len(server.resourceOwners)
	server.RUnlock()
	if resources != 0 || reader.interrupted.Load() == 0 {
		t.Fatalf("observed resource cleanup: resources=%d interrupted=%d", resources, reader.interrupted.Load())
	}
}

type udpBeginStore struct {
	exchange featurestats.Exchange
	stop     bool
}

func (*udpBeginStore) Info() featurestats.InspectionInfo { return featurestats.InspectionInfo{} }
func (s *udpBeginStore) Begin(_ featurestats.FlowKind, _ featurestats.TrafficOrigin, _, _ net.Destination, stop func() error) featurestats.Exchange {
	if s.stop {
		_ = stop()
	}
	return s.exchange
}

func (s *udpBeginStore) PrepareTCP(featurestats.TrafficOrigin, net.Destination, net.Destination, func() error) featurestats.Exchange {
	return s.exchange
}

func TestObservedUDPBeginImmediateStopAndFallbackCleanup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		store     featurestats.AdmissionStore
		wantOwner bool
	}{
		{"immediate-stop", &udpBeginStore{exchange: new(stoppedBeginExchange), stop: true}, true},
		{"nil-begin", &udpBeginStore{}, false},
		{"zero-ref", &udpBeginStore{exchange: new(dnsTCPTestExchange)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
			ctx, owner := beginRoutedDNSUDPObservationWithStore(context.Background(), context.Background(), server, *server.address, 1, make(chan error, 1), tc.store)
			if (owner != nil) != tc.wantOwner {
				t.Fatalf("owner=%v want=%v", owner != nil, tc.wantOwner)
			}
			if tc.wantOwner {
				if ctx.Err() == nil {
					t.Fatal("immediate stop did not cancel owner context")
				}
				<-owner.resource.finishAsync()
			} else {
				deadline := time.Now().Add(time.Second)
				for {
					server.RLock()
					resources := len(server.resourceOwners)
					server.RUnlock()
					if resources == 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("fallback retained resources=%d", resources)
					}
					time.Sleep(time.Millisecond)
				}
			}
			server.RLock()
			resources := len(server.resourceOwners)
			server.RUnlock()
			if resources != 0 {
				t.Fatalf("resources=%d", resources)
			}
		})
	}
}
