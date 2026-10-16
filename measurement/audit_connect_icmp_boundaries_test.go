package measurement

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// This host witness records fatal native controller errors after upstream #7173.
// It does not establish a proxy's
// destination-connect boundary. Global mutation stays in an isolated child,
// following the external measurement_test dialer fixture convention.
func TestAuditConnectControllerErrorRejectsConnection(t *testing.T) {
	const key = "XRAY_MEASUREMENT_AUDIT_CONNECT_CHILD"
	if os.Getenv(key) != t.Name() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.timeout=10s", "-test.v")
		cmd.Env = append(os.Environ(), key+"="+t.Name())
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated native connect witness: %v\n%s", err, output)
		}
		t.Logf("isolated native connect evidence:\n%s", output)
		return
	}

	internet.UseAlternativeSystemDialer(nil)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
	internet.ControllersLock.Lock()
	original := internet.Controllers
	internet.Controllers = nil
	internet.ControllersLock.Unlock()
	t.Cleanup(func() {
		internet.ControllersLock.Lock()
		internet.Controllers = original
		internet.ControllersLock.Unlock()
	})

	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := ln.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	type peerResult struct {
		n   int
		err error
	}
	peerDone := make(chan peerResult, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			peerDone <- peerResult{err: err}
			return
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			peerDone <- peerResult{err: err}
			return
		}
		var b [1]byte
		n, err := conn.Read(b[:])
		peerDone <- peerResult{n: n, err: err}
	}()

	controllerErr := errors.New("audit native controller sentinel")
	var calls atomic.Int32
	if err := internet.RegisterDialerController(func(network, address string, _ syscall.RawConn) error {
		calls.Add(1)
		if network != "tcp4" || address != ln.Addr().String() {
			t.Errorf("controller endpoint: %s %s, want tcp4 %s", network, address, ln.Addr())
		}
		return controllerErr
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.TCPConnect(context.Background(), TCPConnectRequest{
		Route: Route{Kind: Direct}, Destination: ln.Addr().(*net.TCPAddr).AddrPort(), Timeout: 2 * time.Second,
	})
	if !errors.Is(err, controllerErr) || r.DestinationConnected || calls.Load() != 1 || r.NativeDialElapsed == nil || *r.NativeDialElapsed < 0 || r.Elapsed != *r.NativeDialElapsed {
		t.Fatalf("native connect after fatal controller error: %+v, %v, calls=%d", r, err, calls.Load())
	}
	_ = ln.Close()
	select {
	case peer := <-peerDone:
		if peer.n != 0 || !errors.Is(peer.err, net.ErrClosed) {
			t.Fatalf("listener accepted despite controller rejection: n=%d err=%v", peer.n, peer.err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("native connect did not close its socket")
	}
	t.Logf("controller_calls=%d connected=%t listener_closed=true application_bytes=0 native_dial=%s elapsed=%s", calls.Load(), r.DestinationConnected, *r.NativeDialElapsed, r.Elapsed)
}

// These are private exchange/parser and cancellation witnesses. Injecting
// quoted ICMP control frames does not exercise a kernel error queue, privileged
// sockets, a real router, an Android device, or ICMP controller rejection.
func TestAuditICMPQuotedControlBoundary(t *testing.T) {
	for _, fixture := range []struct {
		name        string
		destination netip.Addr
		controlType icmp.Type
	}{
		{"ipv4-unreachable", netip.MustParseAddr("127.0.0.1"), ipv4.ICMPTypeDestinationUnreachable},
		{"ipv6-unreachable", netip.MustParseAddr("::1"), ipv6.ICMPTypeDestinationUnreachable},
		{"ipv6-too-big", netip.MustParseAddr("::1"), ipv6.ICMPTypePacketTooBig},
	} {
		for _, outcome := range []string{"echo", "timeout"} {
			t.Run(fixture.name+"/"+outcome, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				payload := []byte("quoted-control-echo-fixture")
				protocol, replyType := 58, icmp.Type(ipv6.ICMPTypeEchoReply)
				if fixture.destination.Is4() {
					protocol, replyType = 1, ipv4.ICMPTypeEchoReply
				}
				var controlWire, echoWire []byte
				var receipt ICMPEchoReceipt
				c := &blockedEchoConn{closed: make(chan struct{})}
				defer c.Close()
				c.write = func(wire []byte, _ net.Addr) (int, error) {
					request, err := icmp.ParseMessage(protocol, wire)
					if err != nil {
						return 0, err
					}
					var header []byte
					if fixture.destination.Is4() {
						header, err = (&ipv4.Header{Version: 4, Len: ipv4.HeaderLen, TotalLen: ipv4.HeaderLen + len(wire), TTL: 64, Protocol: 1, Src: fixture.destination.AsSlice(), Dst: fixture.destination.AsSlice()}).Marshal()
						if err != nil {
							return 0, err
						}
					} else {
						header = make([]byte, ipv6.HeaderLen)
						header[0], header[6], header[7] = 0x60, 58, 64
						binary.BigEndian.PutUint16(header[4:6], uint16(len(wire)))
						copy(header[8:24], fixture.destination.AsSlice())
						copy(header[24:40], fixture.destination.AsSlice())
					}
					quote := append(header, wire...)
					control := &icmp.Message{Type: fixture.controlType, Body: &icmp.DstUnreach{Data: quote}}
					if fixture.controlType == ipv6.ICMPTypePacketTooBig {
						control.Body = &icmp.PacketTooBig{MTU: 1280, Data: quote}
					}
					controlWire, err = control.Marshal(nil)
					if err != nil {
						return 0, err
					}
					// Prove the fixture is a parseable control frame quoting this
					// exact request, rather than a generic malformed packet.
					parsed, err := icmp.ParseMessage(protocol, controlWire)
					if err != nil {
						return 0, err
					}
					var quoted []byte
					switch body := parsed.Body.(type) {
					case *icmp.DstUnreach:
						quoted = body.Data
					case *icmp.PacketTooBig:
						quoted = body.Data
					}
					if parsed.Type != fixture.controlType || !bytes.HasPrefix(quoted, quote) {
						return 0, errors.New("invalid quoted-control fixture")
					}
					request.Type = replyType
					echoWire, err = request.Marshal(nil)
					return len(wire), err
				}
				reads := 0
				blocked := make(chan struct{})
				c.read = func(p []byte) (int, net.Addr, error) {
					reads++
					peer := &net.IPAddr{IP: fixture.destination.AsSlice()}
					if reads == 1 {
						return copy(p, controlWire), peer, nil
					}
					if receipt.RoundTrip != nil || receipt.ReplySource.IsValid() || receipt.ReplyBytes != 0 {
						return 0, nil, errors.New("quoted control manufactured Echo facts")
					}
					if outcome == "echo" {
						return copy(p, echoWire), peer, nil
					}
					close(blocked)
					<-c.closed
					return 0, nil, net.ErrClosed
				}
				done := make(chan error, 1)
				go func() { done <- exchangeICMPEcho(ctx, c, fixture.destination, payload, false, &receipt) }()
				if outcome == "timeout" {
					select {
					case <-blocked:
					case <-time.After(2 * time.Second):
						t.Fatal("control-only exchange did not reach its blocked read")
					}
				}
				select {
				case err := <-done:
					if reads != 2 || receipt.WrittenBytes == nil || *receipt.WrittenBytes != len(payload)+8 {
						t.Fatalf("control exchange lost write/read facts: %+v, %v, reads=%d", receipt, err, reads)
					}
					if outcome == "echo" {
						if err != nil || receipt.RoundTrip == nil || receipt.ReplySource != fixture.destination || receipt.ReplyBytes != len(echoWire) {
							t.Fatalf("matching Echo after control: %+v, %v", receipt, err)
						}
					} else {
						if !errors.Is(err, net.ErrClosed) || !errors.Is(ctx.Err(), context.DeadlineExceeded) || receipt.RoundTrip != nil || receipt.ReplySource.IsValid() || receipt.ReplyBytes != 0 {
							t.Fatalf("control-only deadline facts: %+v, %v / %v", receipt, err, ctx.Err())
						}
						select {
						case <-c.closed:
						default:
							t.Fatal("deadline did not close the fake packet owner")
						}
					}
				case <-time.After(2 * time.Second):
					t.Fatal("private ICMP exchange did not finish")
				}
				t.Logf("control=%s outcome=%s reads=%d written=%d echo_observed=%t reply_bytes=%d", fixture.name, outcome, reads, *receipt.WrittenBytes, receipt.RoundTrip != nil, receipt.ReplyBytes)
			})
		}
	}
}
