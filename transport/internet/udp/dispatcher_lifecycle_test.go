package udp

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type lifecycleDispatcher struct {
	routing.Dispatcher
	dispatch func(context.Context, net.Destination) (*transport.Link, error)
}

func (d lifecycleDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.dispatch(ctx, dest)
}

func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UDP owner did not return")
	}
}

func TestUDPDispatcherReleasesUndispatchedPayload(t *testing.T) {
	for _, mode := range []string{"rejected", "closed", "missing-writer"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := pipe.New()
			t.Cleanup(reader.Interrupt)
			t.Cleanup(writer.Interrupt)
			var calls int
			d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
				calls++
				if mode == "rejected" {
					return nil, errors.New("rejected UDP ray")
				}
				return &transport.Link{Reader: reader}, nil
			}}, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
			done := make(chan struct{})
			d.callClose = func() error { close(done); return nil }
			t.Cleanup(func() {
				d.RemoveRay()
				if mode == "missing-writer" {
					lifecycleWait(t, done)
				}
			})
			if mode == "closed" {
				d.RemoveRay()
			}
			payload := buf.New()
			payload.WriteString("caller transfers ownership")
			t.Cleanup(payload.Release)
			d.Dispatch(context.Background(), net.UDPDestination(net.LocalHostIP, 53), payload)
			if !payload.IsEmpty() {
				t.Fatal("dispatcher retained an untransferred packet")
			}
			if mode == "closed" && calls != 0 {
				t.Fatal("closed dispatcher admitted another ray")
			}
		})
	}
}

type lifecycleResultReader struct {
	mb  buf.MultiBuffer
	err error
}

func (r *lifecycleResultReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, r.err
}

func TestUDPDispatcherDeliversPacketsBeforeReadError(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("read failed after packets")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			first, second := buf.New(), buf.New()
			first.WriteString("first packet")
			second.WriteString("second packet")
			defer first.Release()
			defer second.Release()
			dest := net.UDPDestination(net.LocalHostIP, 53)
			other := net.UDPDestination(net.LocalHostIP, 5353)
			second.UDP = &other
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entry := &connEntry{
				link: &transport.Link{Reader: &lifecycleResultReader{
					mb: buf.MultiBuffer{first, second}, err: terminal,
				}},
				cancel: cancel,
			}
			entry.timer = signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)
			defer entry.Close()
			var payloads []string
			var destinations []net.Destination
			closed := false
			handleInput(ctx, entry, dest, func(_ context.Context, packet *protocoludp.Packet) {
				payloads = append(payloads, packet.Payload.String())
				destinations = append(destinations, packet.Source)
				packet.Payload.Release()
			}, func() error { closed = true; return nil })
			if len(payloads) != 2 || payloads[0] != "first packet" || payloads[1] != "second packet" {
				t.Fatalf("positive read result discarded or reordered: %q", payloads)
			}
			if destinations[0] != dest || destinations[1] != other || !closed || ctx.Err() == nil {
				t.Fatalf("packet targets or termination lost: %v closed=%v err=%v", destinations, closed, ctx.Err())
			}
		})
	}
}

func TestUDPDispatcherConcurrentRayCloseAndReuse(t *testing.T) {
	var created atomic.Int64
	returned := make(chan struct{}, 128)
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		created.Add(1)
		reader, _ := pipe.New()
		return &transport.Link{Reader: reader}, nil
	}}, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
	d.callClose = func() error { returned <- struct{}{}; return nil }
	t.Cleanup(func() {
		d.RemoveRay()
		for range created.Load() {
			lifecycleWait(t, returned)
		}
	})
	dest := net.UDPDestination(net.LocalHostIP, 53)
	for range 64 {
		entry, err := d.getInboundRay(context.Background(), dest)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var closing sync.WaitGroup
		closing.Add(1)
		go func() {
			defer closing.Done()
			<-start
			entry.Close()
		}()
		close(start)
		if _, err := d.getInboundRay(context.Background(), dest); err != nil {
			t.Fatal(err)
		}
		closing.Wait()
		replacement, err := d.getInboundRay(context.Background(), dest)
		if err != nil || replacement == entry {
			t.Fatalf("closed ray reused: same=%v err=%v", replacement == entry, err)
		}
		// A late repeat close belongs only to the old ray.
		entry.Close()
		again, err := d.getInboundRay(context.Background(), dest)
		if err != nil || again != replacement {
			t.Fatalf("old close retired replacement: same=%v err=%v", again == replacement, err)
		}
	}
}

func TestUDPDispatcherIsolatesSuccessiveRayMetadata(t *testing.T) {
	initial := net.UDPDestination(net.LocalHostIP, 1)
	firstDest := net.UDPDestination(net.LocalHostIP, 53)
	secondDest := net.UDPDestination(net.LocalHostIP, 5353)
	history := &session.Outbound{Tag: "earlier-hop"}
	parentOutbound := &session.Outbound{Target: initial, Gateway: net.LocalHostIP}
	parentContent := &session.Content{Protocol: "initial", Attributes: map[string]string{"target": "initial"}, SkipDNSResolve: true}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{history, parentOutbound})
	ctx = session.ContextWithContent(ctx, parentContent)
	ctx = session.SetForcedOutboundTagToContext(ctx, "forced-udp")
	var rays []context.Context
	var forcedTags []string
	returned := make(chan struct{}, 2)
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
		// These are the mutable fields used by the native dispatcher/sniffer.
		outbounds := session.OutboundsFromContext(ctx)
		outbounds[len(outbounds)-1].Target = dest
		content := session.ContentFromContext(ctx)
		content.Protocol = dest.String()
		content.SetAttribute("target", dest.String())
		// routedDispatch consumes this attribute in the current ray only.
		forcedTags = append(forcedTags, session.GetForcedOutboundTagFromContext(ctx))
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		rays = append(rays, ctx)
		reader, _ := pipe.New()
		return &transport.Link{Reader: reader}, nil
	}}, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
	d.callClose = func() error { returned <- struct{}{}; return nil }
	t.Cleanup(func() {
		d.RemoveRay()
		for range rays {
			lifecycleWait(t, returned)
		}
	})
	first, err := d.getInboundRay(ctx, firstDest)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if _, err := d.getInboundRay(ctx, secondDest); err != nil {
		t.Fatal(err)
	}
	if len(rays) != 2 {
		t.Fatalf("ray count: %d", len(rays))
	}
	for i, dest := range []net.Destination{firstDest, secondDest} {
		outbounds := session.OutboundsFromContext(rays[i])
		content := session.ContentFromContext(rays[i])
		if outbounds[0] != history || outbounds[1].Target != dest || outbounds[1].Gateway != net.LocalHostIP ||
			content.Protocol != dest.String() || content.Attribute("target") != dest.String() || !content.SkipDNSResolve {
			t.Fatalf("ray %d metadata contaminated: outbound=%+v content=%+v", i, outbounds[1], content)
		}
		if forcedTags[i] != "forced-udp" || session.GetForcedOutboundTagFromContext(rays[i]) != "" {
			t.Fatalf("ray %d lost forced route or failed to consume it locally: %q", i, forcedTags[i])
		}
	}
	if parentOutbound.Target != initial || parentContent.Protocol != "initial" || parentContent.Attribute("target") != "initial" {
		t.Fatalf("dispatcher changed parent metadata: outbound=%+v content=%+v", parentOutbound, parentContent)
	}
	if session.GetForcedOutboundTagFromContext(ctx) != "forced-udp" {
		t.Fatal("ray consumed the caller's forced route for later replacements")
	}
}
