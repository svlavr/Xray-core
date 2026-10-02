package measurement_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/measurement"
)

func udpFixture(t *testing.T, handle func(net.PacketConn, []byte, net.Addr)) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(packet)
			if err != nil {
				return
			}
			handle(pc, append([]byte(nil), packet[:n]...), addr)
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return pc
}

func udpRequest(addr net.Addr, kind measurement.RouteKind) measurement.UDPEchoRequest {
	r := measurement.UDPEchoRequest{Route: measurement.Route{Kind: kind}, Destination: addr.(*net.UDPAddr).AddrPort(), Count: 3, PacketBytes: 64, Interval: 10 * time.Millisecond, ReplyWait: 80 * time.Millisecond, Timeout: 2 * time.Second, MaxReplies: 64}
	r.Destination = netip.AddrPortFrom(r.Destination.Addr().Unmap(), r.Destination.Port())
	if kind == measurement.ExactOutbound {
		r.Route.Tag = "exact"
	}
	return r
}

func TestUDPEchoDirectExactAndOrdinarySibling(t *testing.T) {
	pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) { pc.WriteTo(b, a) })
	v := instance(t)
	e := executor(t, v)
	// Keep an ordinary native packet session active across both measurement closes.
	ordinaryCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ordinaryCtx = session.SetForcedOutboundTagToContext(ordinaryCtx, "exact")
	dest, _ := xnet.ParseDestination("udp:" + pc.LocalAddr().String())
	ordinary, err := core.Dial(ordinaryCtx, v, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	ordinaryDone := make(chan error, 1)
	go func() {
		for range 2 {
			_, err := ordinary.Write([]byte("ordinary"))
			if err != nil {
				ordinaryDone <- err
				return
			}
			var packet [64]byte
			n, err := ordinary.Read(packet[:])
			if err != nil || string(packet[:n]) != "ordinary" {
				ordinaryDone <- errors.Join(err, errors.New("ordinary sibling did not echo"))
				return
			}
		}
		ordinaryDone <- nil
	}()
	inbound := &session.Inbound{User: &protocol.MemoryUser{Email: "ordinary"}}
	content := &session.Content{Attributes: map[string]string{"forcedOutboundTag": "trap"}}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.ContextWithTrafficOrigin(ctx, session.OriginUser)
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		got, err := e.UDPEcho(ctx, udpRequest(pc.LocalAddr(), kind))
		if err != nil || !got.WindowComplete || len(got.Sends) != 3 || len(got.Replies) != 3 || got.Elapsed <= 0 {
			t.Fatalf("kind=%d %+v %v", kind, got, err)
		}
		for i, s := range got.Sends {
			if s.Sequence != uint32(i) || s.WriterBytes != 64 || s.WriteReturned == nil || s.Error != nil {
				t.Fatalf("write facts %+v", s)
			}
		}
		for _, reply := range got.Replies {
			if reply.Issue != measurement.UDPReplyValid || reply.Sequence == nil || reply.RoundTrip == nil || reply.Duplicate || reply.Bytes != 64 || reply.Source != udpRequest(pc.LocalAddr(), kind).Destination {
				t.Fatalf("reply facts %+v", reply)
			}
		}

	}
	if inbound.User.Email != "ordinary" || content.Attribute("forcedOutboundTag") != "trap" || session.TrafficOriginFromContext(ctx) != session.OriginUser {
		t.Fatal("caller-owned session mutated")
	}
	select {
	case err := <-ordinaryDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary packet path stalled")
	}
	// A real post-measurement write exercises continuity after measurement closes.
	if _, err := ordinary.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		var packet [64]byte
		n, err := ordinary.Read(packet[:])
		if string(packet[:n]) != "after" {
			err = errors.Join(err, errors.New("post-measurement echo mismatch"))
		}
		read <- err
	}()
	select {
	case err := <-read:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("measurement closed ordinary sibling")
	}
}

func TestUDPEchoReorderedDuplicateLateMalformedAndAbsence(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		t.Run(map[measurement.RouteKind]string{measurement.Direct: "direct", measurement.ExactOutbound: "exact"}[kind], func(t *testing.T) {
			var first []byte
			pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) {
				switch binary.BigEndian.Uint32(b[20:24]) {
				case 0:
					first = b
				case 1: // Deliberately no reply to sequence 1.
				case 2:
					pc.WriteTo(b, a)
					pc.WriteTo(first, a)
					pc.WriteTo(first, a)
					bad := append([]byte(nil), b...)
					bad[4] ^= 1
					pc.WriteTo(bad, a)
					bad[4] ^= 1
					binary.BigEndian.PutUint32(bad[20:24], ^uint32(0))
					pc.WriteTo(bad, a)
					pc.WriteTo([]byte("short"), a)
					bad = append([]byte(nil), b...)
					bad[30] ^= 1
					pc.WriteTo(bad, a)
				}
			})
			r := udpRequest(pc.LocalAddr(), kind)
			r.Interval, r.ReplyWait = 80*time.Millisecond, 60*time.Millisecond
			got, err := executor(t, instance(t)).UDPEcho(context.Background(), r)
			if err != nil || !got.WindowComplete || len(got.Replies) != 7 || len(got.Sends) != 3 {
				t.Fatalf("train %+v %v", got, err)
			}
			if *got.Replies[0].Sequence != 2 || *got.Replies[1].Sequence != 0 || got.Replies[1].Duplicate || !got.Replies[1].Late || !got.Replies[2].Duplicate || !got.Replies[2].Late || got.Replies[3].Issue != measurement.UDPReplyWrongNonce || got.Replies[4].Issue != measurement.UDPReplyUnsentSequence || got.Replies[5].Issue != measurement.UDPReplyMalformed || got.Replies[6].Issue != measurement.UDPReplyMalformed {
				t.Fatalf("lost classifications %+v", got.Replies)
			}
			for _, reply := range got.Replies {
				if reply.Sequence != nil && *reply.Sequence == 1 {
					t.Fatal("synthetic reply for absent sequence")
				}
			}
		})
	}
}

func TestUDPEchoWrongAddressAndVisibleOversizedEmptyPackets(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		other, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { other.Close() })
		pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) {
			other.WriteTo(b, a)
			pc.WriteTo(make([]byte, 1600), a)
			pc.WriteTo(nil, a)
			pc.WriteTo(b, a)
		})
		r := udpRequest(pc.LocalAddr(), kind)
		r.Count, r.Interval = 1, 0
		got, err := executor(t, instance(t)).UDPEcho(context.Background(), r)
		if err != nil || !got.WindowComplete {
			t.Fatalf("train %+v %v", got, err)
		}
		var wrongSource, oversized, empty, valid bool
		for _, reply := range got.Replies {
			wrongSource = wrongSource || reply.Issue == measurement.UDPReplyWrongSource
			oversized = oversized || reply.Bytes == 1600 && reply.Issue == measurement.UDPReplyMalformed
			empty = empty || reply.Bytes == 0 && reply.Issue == measurement.UDPReplyMalformed
			valid = valid || reply.Issue == measurement.UDPReplyValid
		}
		if !wrongSource || !oversized || !valid || kind == measurement.Direct && !empty {
			t.Fatalf("missing raw native-visible facts %+v", got.Replies)
		}
	}
}

func TestUDPEchoReplyLimitDeadlineCancelAndMissing(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) {
			for range 12 {
				pc.WriteTo(b, a)
			}
		})
		e := executor(t, instance(t))
		r := udpRequest(pc.LocalAddr(), kind)
		r.MaxReplies = 2
		got, err := e.UDPEcho(context.Background(), r)
		if !errors.Is(err, measurement.ErrUDPReplyLimit) || !got.ReplyLimitHit || len(got.Replies) != 2 || got.WindowComplete {
			t.Fatalf("flood %+v %v", got, err)
		}
		opened := make(chan struct{}, 1)
		quiet := udpFixture(t, func(net.PacketConn, []byte, net.Addr) {
			select {
			case opened <- struct{}{}:
			default:
			}
		})
		r = udpRequest(quiet.LocalAddr(), kind)
		r.Count, r.Interval, r.ReplyWait, r.Timeout = 1, 0, time.Second, time.Second
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := e.UDPEcho(ctx, r); done <- err }()
		select {
		case <-opened:
		case <-time.After(time.Second):
			t.Fatal("not exercising active packet read")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel %v", err)
		}
		r.Count, r.Interval, r.ReplyWait, r.Timeout = 3, 80*time.Millisecond, 80*time.Millisecond, time.Second
		deadlineCtx, stopDeadline := context.WithTimeout(context.Background(), 120*time.Millisecond)
		got, err = e.UDPEcho(deadlineCtx, r)
		stopDeadline()
		if !errors.Is(err, context.DeadlineExceeded) || len(got.Sends) == 0 || got.WindowComplete {
			t.Fatalf("deadline partial %+v %v", got, err)
		}
		r.Route = measurement.Route{Kind: measurement.ExactOutbound, Tag: "missing"}
		got, err = e.UDPEcho(context.Background(), r)
		if err == nil || len(got.Replies) != 0 {
			t.Fatalf("fallback %+v %v", got, err)
		}
		got, err = e.UDPEcho(ctx, r)
		if !errors.Is(err, context.Canceled) || got.Elapsed != 0 {
			t.Fatalf("precancel %+v %v", got, err)
		}
	}
}

func TestUDPEchoInputRepresentation(t *testing.T) {
	e := executor(t, instance(t))
	base := udpRequest(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, measurement.Direct)
	for _, change := range []func(*measurement.UDPEchoRequest){
		func(r *measurement.UDPEchoRequest) { r.Count = 0 },
		func(r *measurement.UDPEchoRequest) { r.PacketBytes = 23 },
		func(r *measurement.UDPEchoRequest) { r.PacketBytes = 65536 },
		func(r *measurement.UDPEchoRequest) { r.MaxReplies = 0 },
		func(r *measurement.UDPEchoRequest) { r.Interval = -1 },
		func(r *measurement.UDPEchoRequest) { r.Count, r.Interval = 3, time.Duration(1<<63-1)/2+1 },
		func(r *measurement.UDPEchoRequest) { r.Timeout = 0 },
		func(r *measurement.UDPEchoRequest) { r.Route.Tag = "illegal" },
	} {
		r := base
		change(&r)
		if got, err := e.UDPEcho(context.Background(), r); err == nil || len(got.Sends) != 0 || got.Replies != nil {
			t.Fatalf("invalid representation: %+v %v", got, err)
		}
	}
	if got, err := e.UDPEcho(nil, base); err == nil || got.Replies != nil {
		t.Fatalf("nil context receipt: %+v %v", got, err)
	}
}

func TestUDPEchoEmptyRepliesRetainReturnedRepresentation(t *testing.T) {
	pc := udpFixture(t, func(net.PacketConn, []byte, net.Addr) {})
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		r := udpRequest(pc.LocalAddr(), kind)
		r.Count, r.Interval, r.ReplyWait = 1, 0, 20*time.Millisecond
		got, err := e.UDPEcho(context.Background(), r)
		if err != nil || !got.WindowComplete || len(got.Sends) != 1 || got.Replies == nil || len(got.Replies) != 0 || got.ReplyLimitHit {
			t.Fatalf("empty reply window on route %v: %+v %v", kind, got, err)
		}
	}
}

func TestUDPEchoConcurrentDistinctNonces(t *testing.T) {
	pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) { pc.WriteTo(b, a) })
	e := executor(t, instance(t))
	var wg sync.WaitGroup
	nonces := make(chan [16]byte, 12)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kind := measurement.Direct
			if i%2 != 0 {
				kind = measurement.ExactOutbound
			}
			got, err := e.UDPEcho(context.Background(), udpRequest(pc.LocalAddr(), kind))
			if err != nil || len(got.Replies) != 3 || !got.WindowComplete {
				t.Errorf("concurrent %+v %v", got, err)
			}
			nonces <- got.Nonce
		}()
	}
	wg.Wait()
	close(nonces)
	seen := make(map[[16]byte]bool)
	for nonce := range nonces {
		if seen[nonce] {
			t.Fatal("nonce cross-talk")
		}
		seen[nonce] = true
	}
}
