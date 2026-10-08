package outbound

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	transportgrpc "github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	grpc "google.golang.org/grpc"
)

type inspectionHandler struct {
	fout.Handler
	tag      string
	startErr error
	closes   int
}

func (h *inspectionHandler) Tag() string  { return h.tag }
func (h *inspectionHandler) Start() error { return h.startErr }
func (h *inspectionHandler) Close() error { h.closes++; return nil }

func TestInspectionNativeHandlerReplacement(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	first := &inspectionHandler{tag: "reused"}
	if err = m.AddHandler(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	h := m.GetHandler("reused")
	if h != first {
		t.Fatal("entry missing")
	}
	def := m.GetDefaultHandler()
	if def != first {
		t.Fatal("default identity differs")
	}
	if err = m.RemoveHandler(context.Background(), "reused"); err != nil {
		t.Fatal(err)
	}
	if first.closes != 0 {
		t.Fatal("removal unexpectedly closed handler")
	}
	second := &inspectionHandler{tag: "reused"}
	if err = m.AddHandler(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	h = m.GetHandler("reused")
	if h != second {
		t.Fatal("replacement handler missing")
	}
	if err = m.Start(); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("native start failure")
	failed := &inspectionHandler{tag: "registered-before-start", startErr: failure}
	if err = m.AddHandler(context.Background(), failed); !errors.Is(err, failure) {
		t.Fatalf("start result: %v", err)
	}
	h = m.GetHandler(failed.tag)
	if h != failed {
		t.Fatal("failed Start lost native registered entry")
	}
}

func TestInspectionConcurrentNativeEntries(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				h := m.GetHandler("same")
				if h != nil && h.Tag() != "same" {
					t.Errorf("unexpected handler tag: %q", h.Tag())
					return
				}
				m.Select([]string{"same"})
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	for i := 0; i < 500; i++ {
		h := &inspectionHandler{tag: "same"}
		if err = m.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if err = m.RemoveHandler(context.Background(), "same"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInspectionNativeHandlerCloseRetiresGRPCOwner(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		for {
			var hunk encoding.Hunk
			if err := stream.RecvMsg(&hunk); err != nil {
				return err
			}
			if err := stream.SendMsg(&hunk); err != nil {
				return err
			}
		}
	}))
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); <-done })

	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, core.XrayKey(1), instance)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	handler, err := NewHandler(ctx, &core.OutboundHandlerConfig{
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
			ProtocolName:      "grpc",
			TransportSettings: []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&transportgrpc.Config{ServiceName: "owner-test"})}},
		}}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := handler.(*Handler)
	t.Cleanup(func() { _ = h.Close() })
	if h.streamSettings == nil || h.streamSettings.Owner == nil {
		t.Fatal("native handler has no transport owner")
	}
	destination := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*stdnet.TCPAddr).Port))
	conn, err := h.Dial(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != "alive" {
		t.Fatalf("echo: %q %v", response, err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if h.streamSettings.Owner.Err() == nil {
		t.Fatal("native handler close left transport owner active")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active gRPC stream survived handler close")
	}
	if next, err := h.Dial(ctx, destination); err == nil {
		_ = next.Close()
		t.Fatal("closed native handler admitted another gRPC client")
	}
}
