package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

type (
	closeOnlyHold    struct{ accepted chan net.Conn }
	closeOnlyHandler struct {
		mu       sync.Mutex
		hold     map[string]*closeOnlyHold
		nextHold *closeOnlyHold
		conns    []net.Conn
		stop     chan struct{}
		wg       sync.WaitGroup
	}
)

func (h *closeOnlyHandler) HandleConnection(c cnet.Conn, _ cnet.Destination) {
	h.mu.Lock()
	h.conns = append(h.conns, c)
	hold := h.hold[c.RemoteAddr().String()]
	if h.nextHold != nil {
		hold = h.nextHold
		h.nextHold = nil
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()
	defer c.Close()
	if hold != nil {
		hold.accepted <- c
		<-h.stop
		return
	}
	p := make([]byte, 65536)
	for {
		n, err := c.Read(p)
		if err != nil {
			return
		}
		if _, err := c.Write(p[:n]); err != nil {
			return
		}
	}
}

type closeOnlyPause struct {
	requested atomic.Bool
	entered   chan struct{}
	resume    chan struct{}
	once      sync.Once
}

func (p *closeOnlyPause) release() { p.once.Do(func() { close(p.resume) }) }

type closeOnlyPair struct {
	client, server *netTun
	network        *Net
	handler        *closeOnlyHandler
	pause          *closeOnlyPause
	pauseDevice    *netTun
	dialed         []net.Conn
}

func newCloseOnlyPair(t *testing.T, inbound bool) *closeOnlyPair {
	t.Helper()
	h := &closeOnlyHandler{hold: make(map[string]*closeOnlyHold), stop: make(chan struct{})}
	server, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.67.0.1")}, nil, 1420, h)
	if err != nil {
		t.Fatal(err)
	}
	client, network, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.67.0.2")}, nil, 1420, nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	pause := &closeOnlyPause{entered: make(chan struct{}, 1), resume: make(chan struct{})}
	pair := &closeOnlyPair{client: client.(*netTun), server: server.(*netTun), network: network, handler: h, pause: pause, pauseDevice: client.(*netTun)}
	if inbound {
		pair.pauseDevice = server.(*netTun)
	}
	var pumps sync.WaitGroup
	for _, direction := range [][2]*netTun{{pair.client, pair.server}, {pair.server, pair.client}} {
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			p, sizes := make([]byte, 65536), make([]int, 1)
			for {
				if direction[0] == pair.pauseDevice && pause.requested.Load() {
					select {
					case pause.entered <- struct{}{}:
					default:
					}
					<-pause.resume
				}
				if _, err := direction[0].Read([][]byte{p}, sizes, 0); err != nil {
					return
				}
				if _, err := direction[1].Write([][]byte{bytes.Clone(p[:sizes[0]])}, 0); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		// This is the ONLY connection cleanup registration. Registering per-dial
		// Close callbacks would run first in LIFO order and mask the baseline defect
		// by blocking before either shared device gets its terminal signal.
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			pause.release()
			pair.client.Close()
			pair.server.Close()
			pumps.Wait()
			for _, c := range pair.dialed {
				c.Close()
			}
			h.mu.Lock()
			conns := append([]net.Conn(nil), h.conns...)
			h.mu.Unlock()
			for _, c := range conns {
				c.Close()
			}
			close(h.stop)
			h.wg.Wait()
		}()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("device/connection/pump/handler teardown exceeded 3s")
		}
	})
	return pair
}

func closeOnlyDial(t *testing.T, p *closeOnlyPair, protocol string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := p.network.DialContext(ctx, protocol, "10.67.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	p.dialed = append(p.dialed, c)
	return c
}

func closeOnlyEcho(c net.Conn, message string) error {
	done := make(chan error, 1)
	go func() {
		if n, err := c.Write([]byte(message)); err != nil || n != len(message) {
			done <- fmt.Errorf("write %d: %v", n, err)
			return
		}
		got := make([]byte, len(message))
		_, err := io.ReadFull(c, got)
		if err == nil && string(got) != message {
			err = fmt.Errorf("payload %q", got)
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		c.Close()
		return errors.New("echo exceeded 1s")
	}
}

func closeOnlyFill(t *testing.T, p *closeOnlyPair) {
	t.Helper()
	p.pause.requested.Store(true)
	if err := p.pauseDevice.WritePacket([]byte{0}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.pause.entered:
	case <-time.After(time.Second):
		t.Fatal("pump did not reach paused barrier")
	}
	// The fault setup is identical on baseline/candidate: enqueue filler packets
	// directly after the external pump barrier, without depending on EAGAIN.
	for len(p.pauseDevice.packets) < cap(p.pauseDevice.packets) {
		packet := buf.FromBytes([]byte{0})
		select {
		case p.pauseDevice.packets <- packet:
		default:
			packet.Release()
			t.Fatal("queue capacity changed during paused fill")
		}
	}
	if len(p.pauseDevice.packets) != netTunQueue {
		t.Fatalf("queue fault not reached: %d", len(p.pauseDevice.packets))
	}
}

func closeOnlyWaitEnqueue(t *testing.T) {
	t.Helper()
	// The fault is observed at the real device enqueue owner, with no production hook.
	for until := time.Now().Add(time.Second); time.Now().Before(until); time.Sleep(time.Millisecond) {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		if strings.Contains(string(stack[:n]), "(*netTun).WritePacket(") || strings.Contains(string(stack[:n]), "(*netTun).WritePacketContext(") || strings.Contains(string(stack[:n]), "(*netTun).writePacket(") {
			return
		}
	}
	t.Fatal("victim did not reach full device enqueue")
}

func TestNetTUNFlowCloseWithFullQueue(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, inbound := range []bool{false, true} {
			name := protocol + map[bool]string{false: "-outbound", true: "-inbound"}[inbound]
			t.Run(name, func(t *testing.T) {
				p := newCloseOnlyPair(t, inbound)
				hold := &closeOnlyHold{accepted: make(chan net.Conn, 1)}
				if protocol == "tcp" {
					p.handler.mu.Lock()
					p.handler.nextHold = hold
					p.handler.mu.Unlock()
				}
				victimClient := closeOnlyDial(t, p, protocol)
				var capturedPeer net.Conn
				if protocol == "tcp" {
					select {
					case capturedPeer = <-hold.accepted:
					case <-time.After(time.Second):
						t.Fatal("TCP peer not admitted")
					}
				}
				sibling := closeOnlyDial(t, p, protocol)
				if err := closeOnlyEcho(sibling, "sibling-before"); err != nil {
					t.Fatal(err)
				}

				var victim net.Conn = victimClient
				var peer net.Conn
				if protocol == "udp" {
					p.handler.mu.Lock()
					p.handler.hold[victimClient.LocalAddr().String()] = hold
					p.handler.mu.Unlock()
					if _, err := victimClient.Write([]byte("open")); err != nil {
						t.Fatal(err)
					}
					select {
					case peer = <-hold.accepted:
					case <-time.After(time.Second):
						t.Fatal("UDP peer not admitted")
					}
					got := make([]byte, 4)
					if _, err := peer.Read(got); err != nil || string(got) != "open" {
						t.Fatalf("UDP initial packet %q %v", got, err)
					}
				} else {
					peer = capturedPeer
				}
				if inbound {
					victim = peer
				}

				manager := new(appstats.Manager)
				view, err := manager.EnableInspection(fs.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				defer manager.Close()
				var flow fs.Exchange
				if writer, ok := victim.(buf.Writer); ok {
					kind := cnet.Network_TCP
					if protocol == "udp" {
						kind = cnet.Network_UDP
					}
					flow = manager.Observation().Begin(kind, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
					defer flow.Finish()
					buf.AttachWriterReceipt(writer, flow)
				}
				closeOnlyFill(t, p)
				type result struct {
					n   int
					err error
				}
				written := make(chan result, 1)
				read := make(chan result, 1)
				payload := bytes.Repeat([]byte{'p'}, 32<<10)
				if protocol == "udp" {
					payload = payload[:900]
				}
				go func() { n, err := victim.Write(payload); written <- result{n, err} }()
				go func() { n, err := victim.Read(make([]byte, 8)); read <- result{n, err} }()
				closeOnlyWaitEnqueue(t)
				select {
				case got := <-written:
					t.Fatalf("write completed before close: %+v", got)
				case <-time.After(20 * time.Millisecond):
				}
				select {
				case got := <-read:
					t.Fatalf("read completed before close: %+v", got)
				default:
				}
				closed := make(chan error, 1)
				go func() {
					closed <- victim.Close()
				}()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("victim Close exceeded 1s with pump paused")
				}
				var accepted int
				select {
				case got := <-written:
					accepted = got.n
					if got.err == nil {
						t.Fatalf("blocked write succeeded after close: %+v", got)
					}
					if protocol == "tcp" && (got.n <= 0 || got.n >= len(payload)) {
						t.Fatalf("missing partial prefix: %+v", got)
					}
					if protocol == "udp" && got.n != 0 {
						t.Fatalf("unadmitted datagram accepted: %+v", got)
					}
				case <-time.After(time.Second):
					t.Fatal("writer did not join before paused pump release")
				}

				select {
				case got := <-read:
					if got.n != 0 || got.err == nil {
						t.Fatalf("closed read: %+v", got)
					}
				case <-time.After(time.Second):
					t.Fatal("reader did not join before paused pump release")
				}

				if flow != nil {
					totals, err := view.ReadTotals()
					if err != nil || totals.User.Downlink != uint64(accepted) {
						t.Fatalf("prefix receipt=%+v accepted=%d err=%v", totals, accepted, err)
					}
				}
				select {
				case <-p.pause.resume:
					t.Fatal("pump released before victim join assertions")
				default:
				}
				p.pause.release()
				if err := closeOnlyEcho(sibling, "same-sibling-after"); err != nil {
					t.Fatalf("same sibling failed: %v", err)
				}
				fresh := closeOnlyDial(t, p, protocol)
				if err := closeOnlyEcho(fresh, "new-flow-after"); err != nil {
					t.Fatalf("new flow failed: %v", err)
				}
				receiver := peer
				if inbound {
					receiver = victimClient
				}
				if receiver != nil {
					tail := make(chan result, 1)
					go func() { n, err := receiver.Read(make([]byte, len(payload))); tail <- result{n, err} }()
					select {
					case got := <-tail:
						if got.n != 0 {
							t.Fatalf("unaccepted tail appeared: %+v", got)
						}
					case <-time.After(40 * time.Millisecond):
						receiver.Close()
						select {
						case got := <-tail:
							if got.n != 0 {
								t.Fatalf("tail after stop: %+v", got)
							}
						case <-time.After(time.Second):
							t.Fatal("tail reader did not join")
						}
					}
				}
				if flow != nil {
					totals, err := view.ReadTotals()
					if err != nil || totals.User.Downlink != uint64(accepted) {
						t.Fatalf("late duplicate prefix receipt: %+v %v", totals, err)
					}
				}
				t.Logf("queue=%d protocol=%s inbound=%v accepted=%d reader_writer_joined_before_pump=true sibling=true newflow=true", netTunQueue, protocol, inbound, accepted)
			})
		}
	}
}
