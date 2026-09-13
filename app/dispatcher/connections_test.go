package dispatcher

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type observationHandler struct {
	outbound.Handler
	tag string
	run func(context.Context, *transport.Link)
}

func (h *observationHandler) Tag() string                                        { return h.tag }
func (h *observationHandler) Dispatch(ctx context.Context, link *transport.Link) { h.run(ctx, link) }
func (*observationHandler) SenderSettings() *serial.TypedMessage                 { return nil }
func (*observationHandler) ProxySettings() *serial.TypedMessage                  { return nil }

type observationManager struct {
	outbound.Manager
	h *observationHandler
}

func (m observationManager) GetDefaultHandler() outbound.Handler {
	if m.h == nil {
		return nil
	}
	return m.h
}

func (m observationManager) GetHandler(tag string) outbound.Handler {
	if m.h != nil && m.h.tag == tag {
		return m.h
	}
	return nil
}

func observationLink() *transport.Link {
	return &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: buf.Discard}
}

func TestUserConnectionDispatchBoundary(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("example.test"), 443)
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(2); err != nil {
		t.Fatal(err)
	}
	h := &observationHandler{tag: "selected"}
	d.ohm = observationManager{h: h}
	calls := 0
	h.run = func(ctx context.Context, link *transport.Link) {
		calls++
		snapshot := d.ConnectionSnapshot()
		if len(snapshot.Connections) != 1 {
			t.Fatalf("live rows: %+v", snapshot)
		}
		row := snapshot.Connections[0]
		if row.ID == 0 || row.Started.IsZero() || row.Destination != dest.String() || !row.OutboundSelected || row.OutboundTag != "selected" || row.InboundTag != "socks" {
			t.Fatalf("wrong metadata: %+v", row)
		}
		// Real outbound code can mutate session facts after selection. The
		// snapshot and the registry must not retain pointers into that state.
		session.OutboundsFromContext(ctx)[0].Tag = "terminal"
		snapshot.Connections[0].OutboundTag = "consumer mutation"
		if d.ConnectionSnapshot().Connections[0].OutboundTag != "selected" {
			t.Fatal("metadata alias")
		}
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "socks", Source: net.TCPDestination(net.LocalHostIP, 1234)})
	if err := d.DispatchUserLink(ctx, dest, observationLink()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(d.ConnectionSnapshot().Connections) != 0 {
		t.Fatal("dispatch return did not retire row")
	}

	// Identical inbound metadata does not prove USER on the ordinary API.
	h.run = func(context.Context, *transport.Link) {
		if len(d.ConnectionSnapshot().Connections) != 0 {
			t.Fatal("ordinary dispatch classified as USER")
		}
	}
	if err := d.DispatchLink(ctx, dest, observationLink()); err != nil {
		t.Fatal(err)
	}
}

func TestUserConnectionNestedDispatchDoesNotInherit(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(4); err != nil {
		t.Fatal(err)
	}
	h := &observationHandler{tag: "top"}
	d.ohm = observationManager{h: h}
	depth := 0
	h.run = func(ctx context.Context, _ *transport.Link) {
		if depth == 0 {
			depth++
			// Keep all inherited values as a hostile helper counterexample;
			// only its normal outbound metadata is distinct.
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
			if err := d.DispatchLink(ctx, net.TCPDestination(net.LocalHostIP, 53), observationLink()); err != nil {
				t.Fatal(err)
			}
		}
		rows := d.ConnectionSnapshot().Connections
		if len(rows) != 1 || rows[0].Destination != "tcp:example.test:443" {
			t.Fatalf("helper changed rows: %+v", rows)
		}
	}
	if err := d.DispatchUserLink(context.Background(), net.TCPDestination(net.DomainAddress("example.test"), 443), observationLink()); err != nil {
		t.Fatal(err)
	}
}

func TestUserConnectionLimitAndFailure(t *testing.T) {
	dest := net.TCPDestination(net.LocalHostIP, 80)
	d := new(DefaultDispatcher)
	h := &observationHandler{tag: ""}
	d.ohm = observationManager{h: h}
	h.run = func(context.Context, *transport.Link) {
		if d.ConnectionSnapshot().Enabled {
			t.Fatal("tracking enabled by default")
		}
	}
	if err := d.DispatchUserLink(context.Background(), dest, observationLink()); err != nil {
		t.Fatal(err)
	}
	if err := d.EnableConnectionTracking(0); err == nil {
		t.Fatal("accepted zero limit")
	}
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	if err := d.EnableConnectionTracking(2); err == nil {
		t.Fatal("re-enabled tracking")
	}
	held := d.connections.begin(context.Background(), dest)
	h.run = func(context.Context, *transport.Link) {
		if s := d.ConnectionSnapshot(); len(s.Connections) != 1 || s.Dropped != 1 {
			t.Fatalf("capacity result: %+v", s)
		}
	}
	if err := d.DispatchUserLink(context.Background(), dest, observationLink()); err != nil {
		t.Fatal(err)
	}
	d.connections.end(held)
	// Missing selected handler is native dispatch failure, not a persistent row.
	d.ohm = observationManager{}
	if err := d.DispatchUserLink(context.Background(), dest, observationLink()); err != nil {
		t.Fatal(err)
	}
	if len(d.ConnectionSnapshot().Connections) != 0 {
		t.Fatal("missing-handler leak")
	}
	if err := d.DispatchUserLink(context.Background(), net.UDPDestination(net.LocalHostIP, 53), observationLink()); err == nil {
		t.Fatal("accepted UDP")
	}
	ctx := session.SetForcedOutboundTagToContext(context.Background(), "missing")
	if err := d.DispatchUserLink(ctx, dest, observationLink()); err != nil {
		t.Fatal(err)
	}
	if len(d.ConnectionSnapshot().Connections) != 0 {
		t.Fatal("forced-handler leak")
	}
}

func TestUserConnectionCloseRacesAndExhaustion(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(16); err != nil {
		t.Fatal(err)
	}
	dest := net.TCPDestination(net.LocalHostIP, 80)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 100 {
				id := d.connections.begin(context.Background(), dest)
				d.connections.selected(id, "node", "rule", dest)
				_ = d.ConnectionSnapshot()
				d.connections.end(id)
			}
		})
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	s := d.ConnectionSnapshot()
	if !s.Closed || len(s.Connections) != 0 {
		t.Fatalf("late publication: %+v", s)
	}
	if err := d.EnableConnectionTracking(1); err == nil {
		t.Fatal("enabled after close")
	}

	d = new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	d.connections.next = math.MaxUint64
	d.connections.dropped = math.MaxUint64
	if id := d.connections.begin(context.Background(), dest); id != 0 {
		t.Fatal("ID reused on overflow")
	}
	if d.ConnectionSnapshot().Dropped != math.MaxUint64 {
		t.Fatal("drop counter wrapped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if id := d.connections.begin(ctx, dest); id != 0 {
		t.Fatal("registered canceled request")
	}
}

func TestUserConnectionPanicCleanup(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("handler panic")
	d.ohm = observationManager{h: &observationHandler{run: func(context.Context, *transport.Link) { panic(sentinel) }}}
	func() {
		defer func() {
			if recover() != sentinel {
				t.Error("panic changed")
			}
		}()
		_ = d.DispatchUserLink(context.Background(), net.TCPDestination(net.LocalHostIP, 80), observationLink())
	}()
	if len(d.ConnectionSnapshot().Connections) != 0 {
		t.Fatal("panic retained row")
	}
}

func TestUserConnectionInstanceIsolation(t *testing.T) {
	a, b := new(DefaultDispatcher), new(DefaultDispatcher)
	for _, d := range []*DefaultDispatcher{a, b} {
		if err := d.EnableConnectionTracking(1); err != nil {
			t.Fatal(err)
		}
	}
	dest := net.TCPDestination(net.LocalHostIP, 80)
	aID, bID := a.connections.begin(context.Background(), dest), b.connections.begin(context.Background(), dest)
	if aID != 1 || bID != 1 {
		t.Fatal("IDs unexpectedly shared across instances")
	}
	if a.connections.begin(context.Background(), dest) != 0 {
		t.Fatal("limit not enforced")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	a.connections.selected(aID, "late", "late", dest)
	if rows := a.ConnectionSnapshot().Connections; len(rows) != 0 {
		t.Fatal("late selection recreated closed row")
	}
	b.connections.selected(bID, "B", "rule-B", dest)
	s := b.ConnectionSnapshot()
	if s.Closed || s.Dropped != 0 || len(s.Connections) != 1 || s.Connections[0].OutboundTag != "B" {
		t.Fatalf("cross-instance mutation: %+v", s)
	}
	b.connections.end(bID)
	if id := b.connections.begin(context.Background(), dest); id != 2 {
		t.Fatal("ID reused")
	}
	_ = b.Close()
}
