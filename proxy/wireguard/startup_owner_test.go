package wireguard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

type startupWGForeignHandler struct{ outbound.Handler }

func (*startupWGForeignHandler) Tag() string { return "foreign-request-handler" }

func TestWireGuardStartupUsesConstructorOwnerForSelectedBind(t *testing.T) {
	for _, mode := range []string{"native", "selected-missing-handler", "selected-foreign-handler"} {
		t.Run(mode, func(t *testing.T) {
			instance, err := core.New(&core.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			owner := new(inspectionWGHandler)
			base := context.WithValue(context.Background(), core.XrayKey(1), instance)
			construction := session.ContextWithFullHandler(base, owner)
			construction = session.ContextWithStreamSettings(construction, &internet.MemoryStreamConfig{})
			h, err := NewClient(construction, &DeviceConfig{SecretKey: strings.Repeat("01", 32), Endpoint: []string{"10.232.80.2"}, DNS: []string{"127.0.0.1"}, Mtu: 1420, IsClient: true, NoKernelTun: true, Peers: []*PeerConfig{{PublicKey: strings.Repeat("02", 32), Endpoint: "127.0.0.1:9", AllowedIps: []string{"0.0.0.0/0"}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			selected := mode != "native"
			request, cancel := context.WithCancel(base)
			defer cancel()
			request = session.ContextWithOutbounds(request, []*session.Outbound{{Gateway: net.LocalHostIP}})
			if selected {
				request = session.ContextWithTrafficOrigin(request, session.TrafficOriginControlledMeasurement)
			}
			if mode == "selected-foreign-handler" {
				request = session.ContextWithFullHandler(request, new(startupWGForeignHandler))
			}
			// Native proxyman supplies FullHandler only to construction. Measurement
			// Process requests may omit it; a request value cannot replace the owner.
			device := h.dev
			dialer := &inspectionWGDialer{contexts: make(chan context.Context, 8)}
			internet.UseAlternativeSystemDialer(dialer)
			defer internet.UseAlternativeSystemDialer(nil)
			if err := h.up(request); err != nil {
				t.Fatal(err)
			}
			if h.dev != device || !h.canup.Load() {
				t.Fatal("startup replaced native owner or failed to admit EventUp")
			}
			var physical context.Context
			select {
			case physical = <-dialer.contexts:
			case <-time.After(3 * time.Second):
				t.Fatal("native startup did not open its physical bind")
			}
			if selected {
				if session.FullHandlerFromContext(physical) != owner || session.TrafficOriginFromContext(physical) != session.TrafficOriginInternal || session.LogicalObservationFromContext(physical) != nil {
					t.Fatal("selected startup lost constructor owner or inherited logical accounting")
				}
				obs := session.OutboundsFromContext(physical)
				if len(obs) != 1 || obs[0].Tag != owner.Tag() || obs[0].Gateway != net.LocalHostIP || obs[0].Target != net.UDPDestination(net.LocalHostIP, 9) {
					t.Fatalf("selected backend metadata: %+v", obs)
				}
				cancel()
				if err := h.dev.Down(); err != nil {
					t.Fatal(err)
				}
				if err := h.dev.Up(); err != nil {
					t.Fatal(err)
				}
				select {
				case physical = <-dialer.contexts:
				case <-time.After(3 * time.Second):
					t.Fatal("selected reconnect inherited canceled caller")
				}
				if physical.Err() != nil || session.FullHandlerFromContext(physical) != owner || session.TrafficOriginFromContext(physical) != session.TrafficOriginInternal || session.LogicalObservationFromContext(physical) != nil {
					t.Fatal("durable selected reconnect lost native owner or isolation")
				}
			} else if internet.MUSelected(physical) || session.FullHandlerFromContext(physical) != nil {
				t.Fatal("ordinary native bind acquired a selected context or constructor-owner injection")
			}
		})
	}
}
