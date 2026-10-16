package wireguard

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

func TestWireGuardSelectedProvisionalFailureRetainsNativeDevice(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	base := context.WithValue(context.Background(), core.XrayKey(1), instance)
	base = session.ContextWithFullHandler(base, new(inspectionWGHandler))
	base = session.ContextWithStreamSettings(base, &internet.MemoryStreamConfig{})
	conf := &DeviceConfig{SecretKey: strings.Repeat("01", 32), Endpoint: []string{"10.232.78.2"}, DNS: []string{"127.0.0.1"}, Mtu: 1420, IsClient: true, NoKernelTun: true, Peers: []*PeerConfig{{PublicKey: strings.Repeat("02", 32), Endpoint: "127.0.0.1:9", AllowedIps: []string{"0.0.0.0/0"}}}}
	h, err := NewClient(base, conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	ctx := session.ContextWithOutbounds(internet.ContextWithMUTransport(base), []*session.Outbound{{}})
	device, stack, ipc := h.dev, h.tnet, h.ipc
	h.ipc = "private_key=invalid\n"
	if err := h.up(ctx); err == nil {
		t.Fatal("invalid provisional device configuration succeeded")
	}
	if h.dev != device || h.tnet != stack || h.ipc == "" {
		t.Fatal("failed setup lost native device, stack or retry configuration")
	}
	h.ipc = ipc
	if err := h.up(ctx); err != nil {
		t.Fatal(err)
	}
	if h.dev != device || h.tnet != stack || h.ipc != "" {
		t.Fatal("retry replaced native owner or retained applied IPC")
	}
	if err := h.up(ctx); err != nil || h.dev != device {
		t.Fatalf("ready retry replaced device: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if h.dev != nil {
		t.Fatal("terminal close retained device")
	}
	if err := h.up(ctx); err == nil {
		t.Fatal("terminal close admitted retry")
	}
}
