package core_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
)

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

// The retired close-before-API-attachment owner is gone. Native direct dispatch
// still receives cancellation and native connection close owns link cleanup.
func TestCoreDialCanceledNativeDispatch(t *testing.T) {
	for _, mode := range []string{"Dial-UDP", "tagged-UDP"} {
		t.Run(mode, func(t *testing.T) {
			instance := new(core.Instance)
			dispatcher := &apiReadinessDispatcher{reader: new(apiReadinessReader), writer: new(apiReadinessWriter)}
			if err := instance.AddFeature(dispatcher); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Close() })
			parent, cancel := context.WithCancel(context.Background())
			ctx := context.WithValue(parent, core.XrayKey(1), instance)
			cancel()
			dest := xnet.UDPDestination(xnet.LocalHostIP, 53)
			var conn xnet.Conn
			var err error
			if mode == "Dial-UDP" {
				conn, err = core.Dial(ctx, instance, dest)
			} else {
				conn, err = taggedimpl.DialTaggedOutbound(ctx, dispatcher, dest, "direct")
			}
			if err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Write([]byte("closed")); n != len("closed") || err != io.ErrClosedPipe {
				t.Fatalf("native writer error lost: %d %v", n, err)
			}
			_ = conn.Close()
			if dispatcher.active.Load() != 0 || dispatcher.canceled.Load() != 1 || dispatcher.writer.closed.Load() != 1 || dispatcher.reader.interrupted.Load() != 1 {
				t.Fatalf("native cancellation/close: active=%d canceled=%d writer=%d reader=%d", dispatcher.active.Load(), dispatcher.canceled.Load(), dispatcher.writer.closed.Load(), dispatcher.reader.interrupted.Load())
			}
		})
	}
}
