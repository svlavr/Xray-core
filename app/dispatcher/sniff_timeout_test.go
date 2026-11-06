package dispatcher

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type sniffTimeoutLower struct {
	calls   atomic.Int32
	release chan struct{}
	once    sync.Once
}

func (r *sniffTimeoutLower) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.calls.Add(1) != 1 {
		return nil, io.EOF
	}
	<-r.release
	return buf.MultiBuffer{buf.FromBytes([]byte("delayed"))}, io.EOF
}

func (r *sniffTimeoutLower) finish() { r.once.Do(func() { close(r.release) }) }

type sniffTimeoutReceipt struct {
	stats.Exchange
	decoded, selected uint64
	tag               string
}

func (r *sniffTimeoutReceipt) AddUplink(n uint64)          { r.decoded += n }
func (r *sniffTimeoutReceipt) AddSelectedUplink(n uint64)  { r.selected += n }
func (r *sniffTimeoutReceipt) Route(ref stats.OutboundRef) { r.tag = ref.Tag }

type sniffTimeoutRoute struct{ routing.Route }

func (sniffTimeoutRoute) GetOutboundTag() string { return "after-timeout" }
func (sniffTimeoutRoute) GetRuleTag() string     { return "timeout-continuation" }

type sniffTimeoutRouter struct {
	routing.Router
	calls    int
	protocol string
	target   net.Port
}

func (r *sniffTimeoutRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.calls++
	r.protocol, r.target = ctx.GetProtocol(), ctx.GetTargetPort()
	return sniffTimeoutRoute{}, nil
}

type sniffTimeoutManager struct {
	outbound.Manager
	handler outbound.Handler
}

func (m *sniffTimeoutManager) GetHandler(tag string) outbound.Handler {
	if tag == m.handler.Tag() {
		return m.handler
	}
	return nil
}

func (*sniffTimeoutManager) GetDefaultHandler() outbound.Handler { return nil }

type sniffTimeoutHandler struct {
	outbound.Handler
	lower   *sniffTimeoutLower
	payload string
	err     error
}

func (*sniffTimeoutHandler) Tag() string { return "after-timeout" }
func (h *sniffTimeoutHandler) Dispatch(_ context.Context, link *transport.Link) {
	// Data becomes available only after real routing has selected this handler.
	h.lower.finish()
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		h.payload += mb.String()
		buf.ReleaseMulti(mb)
		if err != nil {
			h.err = err
			return
		}
	}
}

func TestDispatchLinkContinuesAfterSniffTimeout(t *testing.T) {
	for _, observed := range []bool{false, true} {
		for _, prefix := range []string{"", "G"} {
			name := "native"
			if observed {
				name = "observed"
			}
			if prefix != "" {
				name += "/retained-prefix"
			}
			t.Run(name, func(t *testing.T) {
				lower := &sniffTimeoutLower{release: make(chan struct{})}
				t.Cleanup(lower.finish)
				var reader buf.Reader = lower
				if prefix != "" {
					reader = &buf.BufferedReader{Reader: reader, Buffer: buf.MultiBuffer{buf.FromBytes([]byte(prefix))}}
				}
				receipt := new(sniffTimeoutReceipt)
				ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
				ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{Enabled: true}})
				if observed {
					cursor := buf.NewInspectionReader(reader, receipt, lower.finish)
					t.Cleanup(cursor.Interrupt)
					reader = cursor
					ctx = session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{Exchange: receipt, SuppliedEndpoint: true})
				}
				router := new(sniffTimeoutRouter)
				handler := &sniffTimeoutHandler{lower: lower}
				dispatcher := &DefaultDispatcher{ohm: &sniffTimeoutManager{handler: handler}, router: router}
				destination := net.TCPDestination(net.LocalHostIP, 443)
				done := make(chan error, 1)
				go func() {
					done <- dispatcher.DispatchLink(ctx, destination, &transport.Link{Reader: reader, Writer: buf.Discard})
				}()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("sniff timeout prevented routing/forwarding continuation")
				}
				if router.calls != 1 || router.protocol != "" || router.target != destination.Port || handler.payload != prefix+"delayed" || handler.err != io.EOF || lower.calls.Load() != 1 {
					t.Fatalf("continuation changed: route=%+v payload=%q err=%v lower-reads=%d", router, handler.payload, handler.err, lower.calls.Load())
				}
				if observed && (receipt.tag != handler.Tag() || receipt.decoded != uint64(len(handler.payload)) || receipt.selected != receipt.decoded) {
					t.Fatalf("observation lost/doubled continuation: %+v", receipt)
				}
			})
		}
	}
}
