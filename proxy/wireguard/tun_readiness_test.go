package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"golang.zx2c4.com/wireguard/tun"
)

type readinessTestTun struct {
	events chan tun.Event
	closes atomic.Int32
}

type readinessOutcomeTestTun struct {
	*readinessTestTun
	outcome error
}

func (d *readinessOutcomeTestTun) closeOutcome() error { return d.outcome }

type closeFirstOutcomeTestTun struct {
	*readinessTestTun
	done    chan struct{}
	once    sync.Once
	outcome error
}

func (d *closeFirstOutcomeTestTun) Close() error {
	d.once.Do(func() {
		d.readinessTestTun.Close()
		close(d.done)
	})
	return nil
}

func (d *closeFirstOutcomeTestTun) closeOutcome() error {
	<-d.done
	return d.outcome
}

func (d *readinessTestTun) File() *os.File                         { return nil }
func (d *readinessTestTun) Read([][]byte, []int, int) (int, error) { return 0, os.ErrClosed }
func (d *readinessTestTun) Write([][]byte, int) (int, error)       { return 0, os.ErrClosed }
func (d *readinessTestTun) MTU() (int, error)                      { return 1500, nil }
func (d *readinessTestTun) Name() (string, error)                  { return "test", nil }
func (d *readinessTestTun) Events() <-chan tun.Event               { return d.events }
func (d *readinessTestTun) BatchSize() int                         { return 1 }
func (d *readinessTestTun) Close() error {
	d.closes.Add(1)
	return nil
}

func TestReadinessTunDefersEventsAndJoins(t *testing.T) {
	source := &readinessTestTun{events: make(chan tun.Event, 3)}
	source.events <- tun.EventUp
	source.events <- tun.EventMTUUpdate
	wrapped := newReadinessTun(source)

	select {
	case event := <-wrapped.Events():
		t.Fatalf("event %v published before readiness", event)
	case <-time.After(10 * time.Millisecond):
	}
	wrapped.markReady()
	for _, want := range []tun.Event{tun.EventUp, tun.EventMTUUpdate} {
		select {
		case got := <-wrapped.Events():
			if got != want {
				t.Fatalf("event=%v want=%v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("ready event was not published")
		}
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := wrapped.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if source.closes.Load() != 1 {
		t.Fatalf("underlying closes=%d", source.closes.Load())
	}
	if _, ok := <-wrapped.Events(); ok {
		t.Fatal("event output remained open after Close")
	}
}

func TestReadinessTunCloseUnblocksPreReadyEvent(t *testing.T) {
	source := &readinessTestTun{events: make(chan tun.Event, 1)}
	source.events <- tun.EventUp
	wrapped := newReadinessTun(source)
	done := make(chan struct{})
	go func() {
		_ = wrapped.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not join pre-ready relay")
	}
}

func TestNetConnectionsCancelAndSeal(t *testing.T) {
	var peersMu sync.Mutex
	var peers []net.Conn
	dial := func(context.Context, netip.AddrPort) (net.Conn, error) {
		client, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return client, nil
	}
	network := newNet(dial, func(ctx context.Context, _, remote netip.AddrPort) (net.Conn, error) {
		return dial(ctx, remote)
	}, nil, true, true)

	ctx, cancel := context.WithCancel(context.Background())
	_, err := network.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("[::1]:1"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	peersMu.Lock()
	firstPeer := peers[0]
	peersMu.Unlock()
	_ = firstPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = firstPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("context cancellation did not close returned connection")
	}

	_, err = network.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("[::1]:2"))
	if err != nil {
		t.Fatal(err)
	}
	network.closeConnections()
	peersMu.Lock()
	secondPeer := peers[1]
	peersMu.Unlock()
	_ = secondPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = secondPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("registry seal did not close returned connection")
	}
	if _, err = network.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("[::1]:3")); err == nil {
		t.Fatal("post-seal dial was published")
	}

	peersMu.Lock()
	defer peersMu.Unlock()
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func TestNetTrackedUDPPreservesPacketView(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	network := newNet(
		func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, errors.New("unused") },
		func(context.Context, netip.AddrPort, netip.AddrPort) (net.Conn, error) {
			packet, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			return &internet.PacketConnWrapper{PacketConn: packet, Dest: peer.LocalAddr()}, nil
		}, nil, true, false,
	)
	conn, err := network.DialUDPAddrPort(context.Background(), netip.AddrPort{}, netip.MustParseAddrPort("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	packet, _, err := internet.PacketConnView(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = packet.WriteTo([]byte{1}, peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err = packet.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerProcessAdmissionCancelsAndJoins(t *testing.T) {
	handlerCtx, cancel := context.WithCancel(context.Background())
	h := &Handler{ctx: handlerCtx, cancel: cancel, closeDone: make(chan struct{})}
	processCtx, finish, err := h.beginProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- h.Close() }()
	select {
	case <-processCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("handler Close did not cancel admitted Process")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("handler Close returned before Process receipt: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	finish()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler Close did not join Process receipt")
	}
	if _, _, err := h.beginProcess(context.Background()); err == nil {
		t.Fatal("post-seal Process admission succeeded")
	}
}

func TestHandlerCloseReturnsCachedInitRollbackOutcome(t *testing.T) {
	want := errors.New("kernel cleanup remains unproven")
	underlying := &readinessOutcomeTestTun{
		readinessTestTun: &readinessTestTun{events: make(chan tun.Event)},
		outcome:          want,
	}
	wrapped := newReadinessTun(underlying)
	handlerCtx, cancel := context.WithCancel(context.Background())
	h := &Handler{ctx: handlerCtx, cancel: cancel, tun: wrapped, closeDone: make(chan struct{})}
	if err := h.Close(); !errors.Is(err, want) {
		t.Fatalf("Close err=%v want=%v", err, want)
	}
	if err := h.Close(); !errors.Is(err, want) {
		t.Fatalf("repeated Close err=%v want=%v", err, want)
	}
}

func TestHandlerCloseStartsRawPreInitCloseBeforeOutcome(t *testing.T) {
	want := errors.New("pre-init cleanup failed")
	device := &closeFirstOutcomeTestTun{
		readinessTestTun: &readinessTestTun{events: make(chan tun.Event)},
		done:             make(chan struct{}),
		outcome:          want,
	}
	handlerCtx, cancel := context.WithCancel(context.Background())
	h := &Handler{ctx: handlerCtx, cancel: cancel, tun: device, closeDone: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- h.Close() }()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("Close err=%v want=%v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-init Handler.Close deadlocked before raw Close")
	}
}
