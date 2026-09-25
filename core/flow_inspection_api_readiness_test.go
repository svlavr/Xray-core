package core_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
)

type apiEarlyStopStore struct {
	fs.AdmissionStore
	view    fs.FlowInspection
	stopped fs.FlowRef
}

func (s *apiEarlyStopStore) Begin(kind fs.FlowKind, origin fs.TrafficOrigin, source, destination xnet.Destination, stop func() error) fs.Exchange {
	e := s.AdmissionStore.Begin(kind, origin, source, destination, stop)
	s.stopped = e.Ref()
	result, err := s.view.CloseFlows(context.Background(), []fs.FlowRef{e.Ref()})
	if err != nil || len(result) != 1 || result[0].Code != fs.CloseCodeAccepted {
		panic("early exact stop failed")
	}
	return e
}

type apiEarlyStopManager struct {
	*appstats.Manager
	store fs.AdmissionStore
}

func (m *apiEarlyStopManager) Observation() fs.AdmissionStore { return m.store }

type apiReadinessWriter struct{ closed atomic.Int32 }

func (w *apiReadinessWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return io.ErrClosedPipe
}
func (w *apiReadinessWriter) Close() error { w.closed.Add(1); return nil }

type apiReadinessReader struct{ interrupted atomic.Int32 }

func (r *apiReadinessReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }
func (r *apiReadinessReader) Interrupt()                                { r.interrupted.Add(1) }

type apiReadinessDispatcher struct {
	routing.Dispatcher
	active   atomic.Int32
	canceled atomic.Int32
	reader   *apiReadinessReader
	writer   *apiReadinessWriter
}

func (*apiReadinessDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*apiReadinessDispatcher) Start() error      { return nil }
func (*apiReadinessDispatcher) Close() error      { return nil }
func (d *apiReadinessDispatcher) Dispatch(ctx context.Context, _ xnet.Destination) (*transport.Link, error) {
	if ctx.Err() == nil {
		d.active.Add(1)
	} else {
		d.canceled.Add(1)
	}
	return &transport.Link{Reader: d.reader, Writer: d.writer}, nil
}

func TestFlowInspectionUDPEarlyStopPublication(t *testing.T) {
	for _, mode := range []string{"Dial-UDP", "DialUDP", "tagged-UDP"} {
		t.Run(mode, func(t *testing.T) {
			manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
			if err != nil {
				t.Fatal(err)
			}
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			raw := manager.Observation()
			var siblingStops atomic.Int32
			sibling := raw.Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { siblingStops.Add(1); return nil })
			early := &apiEarlyStopStore{AdmissionStore: raw, view: view}
			instance := new(core.Instance)
			if err := instance.AddFeature(&apiEarlyStopManager{Manager: manager, store: early}); err != nil {
				t.Fatal(err)
			}
			dispatcher := &apiReadinessDispatcher{reader: new(apiReadinessReader), writer: new(apiReadinessWriter)}
			if err := instance.AddFeature(dispatcher); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Close() })
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := session.ContextWithTrafficOrigin(parent, fs.TrafficOriginUser)
			ctx = context.WithValue(ctx, core.XrayKey(1), instance)
			dest := xnet.UDPDestination(xnet.LocalHostIP, 53)
			if mode == "DialUDP" {
				conn, err := core.DialUDP(ctx, instance)
				if err != nil {
					t.Fatal(err)
				}
				if n, _, err := conn.ReadFrom(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatalf("late packet connection remained live: %d %v", n, err)
				}
				_, _ = conn.WriteTo([]byte("closed"), dest.RawNetAddr())
				_ = conn.Close()
				if dispatcher.active.Load() != 0 || dispatcher.canceled.Load() != 0 {
					t.Fatal("closed packet owner dispatched a ray")
				}
			} else {
				var conn xnet.Conn
				if mode == "Dial-UDP" {
					conn, err = core.Dial(ctx, instance, dest)
				} else {
					conn, err = taggedimpl.DialTaggedOutbound(ctx, dispatcher, dest, "direct")
				}
				if err != nil {
					t.Fatal(err)
				}
				if n, err := conn.Write([]byte("closed")); n != 0 || err == nil {
					t.Fatalf("late stream connection remained live: %d %v", n, err)
				}
				_ = conn.Close()
				if dispatcher.active.Load() != 0 || dispatcher.canceled.Load() != 1 || dispatcher.writer.closed.Load() != 1 || dispatcher.reader.interrupted.Load() != 1 {
					t.Fatalf("dispatch/late close: active=%d canceled=%d writer=%d reader=%d", dispatcher.active.Load(), dispatcher.canceled.Load(), dispatcher.writer.closed.Load(), dispatcher.reader.interrupted.Load())
				}
			}
			if parent.Err() != nil || siblingStops.Load() != 0 {
				t.Fatal("early root stop canceled parent or sibling")
			}
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != sibling.Ref() {
				t.Fatalf("sibling inventory: %+v %v", live, err)
			}
			terminals, err := view.ReadTerminals(context.Background())
			if err != nil || len(terminals.Rows) != 1 || terminals.Rows[0].Flow.Ref != early.stopped || terminals.Rows[0].Reason != fs.EndReasonLocalStop {
				t.Fatalf("early terminal: %+v %v", terminals, err)
			}
		})
	}
}
