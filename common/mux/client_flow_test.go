package mux_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestClientWorkerMintsOneCarrierObservationConcurrently(t *testing.T) {
	fromCarrierReader, fromCarrierWriter := pipe.New(pipe.WithoutSizeLimit())
	toCarrierReader, toCarrierWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: fromCarrierReader, Writer: toCarrierWriter}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		common.Must(worker.Close())
		common.Interrupt(fromCarrierReader)
		common.Close(fromCarrierWriter)
		common.Interrupt(toCarrierReader)
		common.Close(toCarrierWriter)
	})

	const flowCount = 64
	carrier := new(clientMuxTestCarrier)
	newCalls := new(atomic.Int32)
	start := make(chan struct{})
	results := make(chan bool, flowCount)
	var waitGroup sync.WaitGroup
	waitGroup.Add(flowCount)
	for range flowCount {
		go func() {
			defer waitGroup.Done()
			logicalReader, logicalWriter := pipe.New(pipe.WithoutSizeLimit())
			responseReader, responseWriter := pipe.New(pipe.WithoutSizeLimit())
			common.Close(logicalWriter)
			defer common.Interrupt(responseReader)
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
				Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
			}})
			ctx = session.ContextWithMuxClientSessionObservation(ctx, &clientMuxTestScope{newCalls: newCalls, carrier: carrier})
			<-start
			results <- worker.Dispatch(ctx, &transport.Link{Reader: logicalReader, Writer: responseWriter})
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for result := range results {
		if !result {
			t.Fatal("unbounded test worker rejected a logical session")
		}
	}
	if got := newCalls.Load(); got != 1 {
		t.Fatalf("worker minted %d carrier observations, want 1", got)
	}
	if got := carrier.attachments.Load(); got != flowCount {
		t.Fatalf("worker attached %d logical sessions, want %d", got, flowCount)
	}
}

func TestClientWorkerMemoizesNilFlowCarrierOutcome(t *testing.T) {
	fromCarrierReader, fromCarrierWriter := pipe.New(pipe.WithoutSizeLimit())
	toCarrierReader, toCarrierWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: fromCarrierReader, Writer: toCarrierWriter}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		common.Must(worker.Close())
		common.Interrupt(fromCarrierReader)
		common.Close(fromCarrierWriter)
		common.Interrupt(toCarrierReader)
		common.Close(toCarrierWriter)
	})

	const flowCount = 64
	newCalls := new(atomic.Int32)
	start := make(chan struct{})
	results := make(chan bool, flowCount)
	var waitGroup sync.WaitGroup
	waitGroup.Add(flowCount)
	for range flowCount {
		go func() {
			defer waitGroup.Done()
			logicalReader, logicalWriter := pipe.New(pipe.WithoutSizeLimit())
			responseReader, responseWriter := pipe.New(pipe.WithoutSizeLimit())
			common.Close(logicalWriter)
			defer common.Interrupt(responseReader)
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
				Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
			}})
			ctx = session.ContextWithMuxClientSessionObservation(ctx, &clientMuxTestScope{newCalls: newCalls})
			<-start
			results <- worker.Dispatch(ctx, &transport.Link{Reader: logicalReader, Writer: responseWriter})
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for result := range results {
		if !result {
			t.Fatal("unbounded test worker rejected a logical session")
		}
	}
	if got := newCalls.Load(); got != 1 {
		t.Fatalf("worker retried nil carrier mint %d times, want 1", got)
	}
}

func TestFactoryMemoizesNilEarlyCarrierOutcome(t *testing.T) {
	authority := new(clientMuxNilCarrierAuthority)
	proxy := &clientMuxFlowBlockingProxy{started: make(chan struct{}), done: make(chan struct{})}
	worker, err := (&mux.DialingWorkerFactory{Proxy: proxy}).CreateWithMuxClientCarrierAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		common.Must(worker.Close())
		worker.Wait()
	})
	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("proxy Process was not published")
	}

	const flowCount = 64
	lazyCalls := new(atomic.Int32)
	start := make(chan struct{})
	results := make(chan bool, flowCount)
	var waitGroup sync.WaitGroup
	waitGroup.Add(flowCount)
	for range flowCount {
		go func() {
			defer waitGroup.Done()
			logicalReader, logicalWriter := pipe.New(pipe.WithoutSizeLimit())
			responseReader, responseWriter := pipe.New(pipe.WithoutSizeLimit())
			common.Close(logicalWriter)
			defer common.Interrupt(responseReader)
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
				Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
			}})
			ctx = session.ContextWithMuxClientSessionObservation(ctx, &clientMuxTestScope{newCalls: lazyCalls})
			<-start
			results <- worker.Dispatch(ctx, &transport.Link{Reader: logicalReader, Writer: responseWriter})
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for result := range results {
		if !result {
			t.Fatal("unbounded test worker rejected a logical session")
		}
	}
	if got := authority.calls.Load(); got != 1 {
		t.Fatalf("early authority called %d times, want 1", got)
	}
	if got := lazyCalls.Load(); got != 0 {
		t.Fatalf("nil early result reminted %d lazy carriers", got)
	}
}

type clientMuxTestScope struct {
	newCalls *atomic.Int32
	carrier  session.MuxClientCarrierObservation
}

func (s *clientMuxTestScope) NewCarrier() session.MuxClientCarrierObservation {
	s.newCalls.Add(1)
	return s.carrier
}

type clientMuxTestCarrier struct {
	attachments atomic.Int32
}

func (c *clientMuxTestCarrier) AttachTo(session.MuxClientSessionObservation) {
	c.attachments.Add(1)
}

type clientMuxNilCarrierAuthority struct{ calls atomic.Int32 }

func (a *clientMuxNilCarrierAuthority) NewMuxClientCarrierObservation() session.MuxClientCarrierObservation {
	a.calls.Add(1)
	return nil
}

type clientMuxFlowBlockingProxy struct {
	started chan struct{}
	done    chan struct{}
}

func (p *clientMuxFlowBlockingProxy) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) error {
	close(p.started)
	<-ctx.Done()
	close(p.done)
	return ctx.Err()
}
