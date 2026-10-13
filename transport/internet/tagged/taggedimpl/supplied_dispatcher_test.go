package taggedimpl

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type taggedDispatcherMarkerKey struct{}

type taggedDispatcherFixture struct {
	link  *transport.Link
	err   error
	calls int
	ctx   context.Context
	dest  net.Destination
}

func (d *taggedDispatcherFixture) Type() interface{} { return routing.DispatcherType() }
func (*taggedDispatcherFixture) Start() error        { return nil }
func (*taggedDispatcherFixture) Close() error        { return nil }

func (d *taggedDispatcherFixture) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	d.calls++
	d.ctx, d.dest = ctx, dest
	return d.link, d.err
}

func (*taggedDispatcherFixture) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

type taggedDispatcherWriter struct{ bytes.Buffer }

func (w *taggedDispatcherWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b != nil {
			_, _ = w.Buffer.Write(b.Bytes())
		}
	}
	return nil
}

func TestDialTaggedOutboundUsesProvidedDispatcher(t *testing.T) {
	for _, test := range []struct {
		name string
		dest net.Destination
	}{
		{name: "tcp", dest: net.TCPDestination(net.LocalHostIP, 8080)},
		{name: "udp", dest: net.UDPDestination(net.LocalHostIP, 5353)},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := new(taggedDispatcherWriter)
			dispatcher := &taggedDispatcherFixture{link: &transport.Link{
				Reader: buf.NewReader(bytes.NewReader([]byte("reply"))),
				Writer: writer,
			}}
			instance := new(core.Instance) // Deliberately has no registered dispatcher feature.
			marker := &struct{ value string }{value: "caller-context-survives"}
			ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
			ctx = context.WithValue(ctx, taggedDispatcherMarkerKey{}, marker)

			conn, err := DialTaggedOutbound(ctx, dispatcher, test.dest, "chosen-outbound")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			if dispatcher.calls != 1 || dispatcher.dest.String() != test.dest.String() {
				t.Fatalf("dispatch calls/destination = %d/%s, want 1/%s", dispatcher.calls, dispatcher.dest, test.dest)
			}
			if core.FromContext(dispatcher.ctx) != instance || dispatcher.ctx.Value(taggedDispatcherMarkerKey{}) != marker {
				t.Fatal("tagged dial lost the caller context or core instance")
			}
			content := session.ContentFromContext(dispatcher.ctx)
			if content == nil || !content.SkipDNSResolve || session.GetForcedOutboundTagFromContext(dispatcher.ctx) != "chosen-outbound" {
				t.Fatalf("tagged content = %+v, forced tag = %q", content, session.GetForcedOutboundTagFromContext(dispatcher.ctx))
			}

			payload := []byte("request")
			if n, err := conn.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("write = %d/%d, %v", n, len(payload), err)
			}
			if writer.String() != string(payload) {
				t.Fatalf("dispatcher writer received %q", writer.String())
			}
			response := make([]byte, len("reply"))
			if _, err := io.ReadFull(conn, response); err != nil || string(response) != "reply" {
				t.Fatalf("read = %q, %v", response, err)
			}
		})
	}
}

func TestDialTaggedOutboundRequiresInstance(t *testing.T) {
	dispatcher := &taggedDispatcherFixture{link: &transport.Link{
		Reader: buf.NewReader(bytes.NewReader(nil)),
		Writer: buf.Discard,
	}}
	_, err := DialTaggedOutbound(context.Background(), dispatcher, net.TCPDestination(net.LocalHostIP, 80), "direct")
	if err == nil || !strings.Contains(err.Error(), "Instance context variable is not in context") {
		t.Fatalf("missing-instance error = %v", err)
	}
	if dispatcher.calls != 0 {
		t.Fatalf("missing-instance call dispatched %d times", dispatcher.calls)
	}
}

func TestDialTaggedOutboundForwardsDispatchError(t *testing.T) {
	want := stderrors.New("fixture dispatch failure")
	dispatcher := &taggedDispatcherFixture{err: want}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	_, err := DialTaggedOutbound(ctx, dispatcher, net.UDPDestination(net.LocalHostIP, 53), "direct")
	if !stderrors.Is(err, want) {
		t.Fatalf("dispatch error = %v, want %v", err, want)
	}
	if dispatcher.calls != 1 {
		t.Fatalf("dispatch calls = %d, want 1", dispatcher.calls)
	}
}
