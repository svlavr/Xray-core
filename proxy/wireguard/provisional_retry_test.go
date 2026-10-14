package wireguard

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"golang.zx2c4.com/wireguard/tun"
)

func TestWireGuardSelectedProvisionalFailureRecreatesNativeTUN(t *testing.T) {
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
	// Construct a real native device, then make its configuration fail.
	conf.SecretKey = "invalid"
	if err := h.init(ctx); err == nil {
		t.Fatal("invalid provisional device configuration succeeded")
	}
	if h.dev != nil || h.tun != nil || h.tnet != nil || h.newTun == nil {
		t.Fatal("failed provisional initialization retained resources or lost retry constructor")
	}
	construct := h.newTun
	calls := 0
	h.newTun = func() (tun.Device, *Net, error) { calls++; return construct() }
	conf.SecretKey = strings.Repeat("01", 32)
	if err := h.init(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || h.dev == nil || h.tun == nil || h.tnet == nil {
		t.Fatal("retry did not recreate the real native TUN/device")
	}
	device := h.dev
	if err := h.init(ctx); err != nil || h.dev != device || calls != 1 {
		t.Fatalf("ready retry replaced native device: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if h.newTun != nil || h.tun != nil || h.dev != nil {
		t.Fatal("terminal close retained native retry admission")
	}
	if err := h.init(ctx); err == nil || calls != 1 {
		t.Fatal("terminal close reconstructed a device")
	}
}
