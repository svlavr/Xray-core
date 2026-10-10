package core_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	proxyhysteria "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/transport/internet"
)

type u2WirePacket struct {
	net.PacketConn
	closed chan struct{}
	once   sync.Once
}

func (p *u2WirePacket) Close() error {
	err := p.PacketConn.Close()
	p.once.Do(func() { close(p.closed) })
	return err
}

type u2WireDial struct {
	instance            *core.Instance
	isolated, muxTarget bool
	packet              *u2WirePacket
}

type u2WireWitness struct {
	dest  cnet.Destination
	lower internet.DefaultSystemDialer
	mu    sync.Mutex
	dials []u2WireDial
}

func (w *u2WireWitness) Dial(ctx context.Context, source cnet.Address, dest cnet.Destination, options *internet.SocketConfig) (cnet.Conn, error) {
	conn, err := w.lower.Dial(ctx, source, dest, options)
	if err != nil || dest != w.dest {
		return conn, err
	}
	packet := conn.(*cnet.PacketConnWrapper)
	p := &u2WirePacket{PacketConn: packet.PacketConn, closed: make(chan struct{})}
	packet.PacketConn = p
	_, deadline := ctx.Deadline()
	obs := session.OutboundsFromContext(ctx)
	dial := u2WireDial{
		instance: core.FromContext(ctx), packet: p,
		isolated:  !deadline && session.LogicalObservationFromContext(ctx) == nil && session.TrafficOriginFromContext(ctx) == session.TrafficOriginUnknown && session.InboundFromContext(ctx) == nil && session.ContentFromContext(ctx) == nil,
		muxTarget: len(obs) == 1 && obs[0].Target == cnet.TCPDestination(cnet.DomainAddress("v1.mux.cool"), 9527),
	}
	w.mu.Lock()
	w.dials = append(w.dials, dial)
	w.mu.Unlock()
	return conn, nil
}
func (*u2WireWitness) DestIpAddress() cnet.IP { return nil }

func (w *u2WireWitness) carrier(t *testing.T, instance *core.Instance) *u2WirePacket {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var found []u2WireDial
	for _, d := range w.dials {
		if d.instance == instance {
			found = append(found, d)
		}
	}
	if len(found) != 1 || !found[0].isolated || !found[0].muxTarget {
		t.Fatalf("shared Hysteria MUX carrier evidence: %+v", found)
	}
	return found[0].packet
}

func u2HysteriaMuxConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	config := inspectionHysteriaConfig(t)
	message, err := config.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender := message.(*proxyman.SenderConfig)
	sender.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4, XudpConcurrency: 4}
	config.SenderSettings = serial.ToTypedMessage(sender)
	return config
}

func u2TCPExchange(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("TCP write: %d %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(c, response); err != nil || !bytes.Equal(response, transformOutboundStatsTCPPayload(payload)) {
		t.Fatalf("TCP response: %x %v", response, err)
	}
}

func u2APIInstance(t *testing.T, enabled bool, outbound *core.OutboundHandlerConfig) (*core.Instance, fs.FlowInspection, func()) {
	t.Helper()
	v, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&appstats.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&dispatcher.Config{})}, Outbound: []*core.OutboundHandlerConfig{outbound}})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	closeInstance := func() {
		once.Do(func() {
			if err := v.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(closeInstance)
	var view fs.FlowInspection
	if enabled {
		view, err = core.EnableFlowInspection(v, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	return v, view, closeInstance
}

func u2APITCP(t *testing.T, v *core.Instance, destination cnet.Destination, payload []byte) net.Conn {
	t.Helper()
	c, err := core.Dial(inspectionAPIContext(v, fs.TrafficOriginUser), v, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	u2TCPExchange(t, c, payload)
	return c
}

func TestU2HysteriaMuxWireLifecycle(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	for _, network := range []string{"tcp", "udp"} {
		for _, enabled := range []bool{false, true} {
			name := network + "/off"
			if enabled {
				name = network + "/on"
			}
			t.Run(name, func(t *testing.T) {
				config := u2HysteriaMuxConfig(t)
				proxy, err := config.ProxySettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				server := proxy.(*proxyhysteria.ClientConfig).Server
				w := &u2WireWitness{dest: cnet.UDPDestination(server.Address.AsAddress(), cnet.Port(server.Port))}
				internet.UseAlternativeSystemDialer(w)
				t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
				payload, extra := []byte("mux first and sibling"), []byte("mux sibling survives")
				var v, independent *core.Instance
				var view fs.FlowInspection
				var continueSibling, continueIndependent func()
				var closeOwner, closeIndependent func()
				if network == "tcp" {
					v, view, closeOwner = u2APIInstance(t, enabled, config)
					destination := startOutboundStatsTCPServer(t)
					first := u2APITCP(t, v, destination, payload)
					sibling := u2APITCP(t, v, destination, payload)
					continueSibling = func() { u2TCPExchange(t, sibling, extra) }
					_ = first.Close()
					if enabled {
						inspectionWait(t, func() bool { live, _ := view.ReadLiveInto(nil); return len(live.Rows) == 1 })
					}
					independent, _, closeIndependent = u2APIInstance(t, false, config)
					other := u2APITCP(t, independent, destination, payload)
					continueIndependent = func() { u2TCPExchange(t, other, extra) }
				} else {
					const mask = byte(0x61)
					destination := startOutboundStatsUDPServer(t, mask)
					var address *net.UDPAddr
					v, view, address = inspectionUDPInboundThrough(t, destination, enabled, false, config)
					first, sibling := inspectionUDPClient(t), inspectionUDPClient(t)
					inspectionUDPExchange(t, first, address, payload, mask)
					inspectionUDPExchange(t, sibling, address, payload, mask)
					continueSibling = func() { inspectionUDPExchange(t, sibling, address, extra, mask) }
					if enabled {
						var ref fs.FlowRef
						inspectionWait(t, func() bool {
							live, _ := view.ReadLiveInto(nil)
							for _, row := range live.Rows {
								if row.Source.Port == cnet.Port(first.LocalAddr().(*net.UDPAddr).Port) {
									ref = row.Ref
								}
							}
							return len(live.Rows) == 2 && ref.ID != 0
						})
						outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
						if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
							t.Fatalf("exact UDP child stop: %v %v", outcomes, err)
						}
					} else {
						_ = first.Close()
					}
					var independentAddress *net.UDPAddr
					independent, _, independentAddress = inspectionUDPInboundThrough(t, destination, false, false, config)
					other := inspectionUDPClient(t)
					inspectionUDPExchange(t, other, independentAddress, payload, mask)
					continueIndependent = func() { inspectionUDPExchange(t, other, independentAddress, extra, mask) }
					closeOwner = func() {
						if err := v.Close(); err != nil {
							t.Error(err)
						}
					}
					closeIndependent = func() {
						if err := independent.Close(); err != nil {
							t.Error(err)
						}
					}
				}
				carrier := w.carrier(t, v)
				otherCarrier := w.carrier(t, independent)
				continueSibling()
				if enabled {
					inspectionOutboundTotals(t, view, config.Tag, uint64(2*len(payload)+len(extra)))
				}
				if w.carrier(t, v) != carrier {
					t.Fatal("child cancellation replaced shared carrier")
				}
				closeOwner()
				select {
				case <-carrier.closed:
				case <-time.After(5 * time.Second):
					t.Fatal("owning instance left Hysteria carrier socket open")
				}
				select {
				case <-otherCarrier.closed:
					t.Fatal("instance shutdown closed independent carrier")
				default:
				}
				continueIndependent()
				closeIndependent()
				select {
				case <-otherCarrier.closed:
				case <-time.After(5 * time.Second):
					t.Fatal("independent carrier did not retire")
				}
			})
		}
	}
}
