package measurement

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type echoTestConn struct {
	write func([]byte, net.Addr) (int, error)
	read  func([]byte) (int, net.Addr, error)
}

func (c *echoTestConn) WriteTo(p []byte, addr net.Addr) (int, error) { return c.write(p, addr) }
func (c *echoTestConn) ReadFrom(p []byte) (int, net.Addr, error)     { return c.read(p) }
func (*echoTestConn) Close() error                                   { return nil }
func (*echoTestConn) LocalAddr() net.Addr                            { return &net.IPAddr{} }
func (*echoTestConn) SetDeadline(time.Time) error                    { return nil }
func (*echoTestConn) SetReadDeadline(time.Time) error                { return nil }
func (*echoTestConn) SetWriteDeadline(time.Time) error               { return nil }

func TestICMPEchoCorrelationAndPartialIO(t *testing.T) {
	native := errors.New("native ICMP failure")
	for _, mode := range []string{"valid", "datagram-id", "wrong-source", "wrong-type", "wrong-code", "wrong-id", "wrong-sequence", "wrong-payload", "malformed", "checksum", "short-write", "partial-error", "read-error", "reply-error", "reply-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			payload := []byte("unpredictable-echo-fixture")
			destination := netip.MustParseAddr("127.0.0.1")
			var sent *icmp.Message
			c := &echoTestConn{}
			c.write = func(p []byte, addr net.Addr) (int, error) {
				var err error
				sent, err = icmp.ParseMessage(1, p)
				if err != nil {
					t.Fatal(err)
				}
				if sent.Type != ipv4.ICMPTypeEcho || sent.Code != 0 || !bytes.Equal(sent.Body.(*icmp.Echo).Data, payload) {
					t.Fatal("wrong native ICMP serialization")
				}
				if _, ok := addr.(*net.UDPAddr); ok != (mode == "datagram-id") {
					t.Fatal("wrong native endpoint address shape")
				}
				if mode == "short-write" {
					return 7, nil
				}
				if mode == "partial-error" {
					return 7, native
				}
				return len(p), nil
			}
			reads := 0
			c.read = func(p []byte) (int, net.Addr, error) {
				reads++
				if mode == "read-error" {
					return 0, nil, native
				}
				m := *sent
				m.Type = ipv4.ICMPTypeEchoReply
				echo := *sent.Body.(*icmp.Echo)
				m.Body = &echo
				addr := &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
				if mode == "datagram-id" {
					echo.ID++ // The native ping socket may rewrite this identifier.
				}
				if reads == 1 {
					switch mode {
					case "wrong-source":
						addr.IP = net.IPv4(127, 0, 0, 2)
					case "wrong-type":
						m.Type = ipv4.ICMPTypeEcho
					case "wrong-code":
						m.Code = 1
					case "wrong-id":
						echo.ID++
					case "wrong-sequence":
						echo.Seq++
					case "wrong-payload":
						echo.Data = []byte("other-echo-payload")
					case "malformed":
						return copy(p, []byte{0, 1}), addr, nil
					}
				}
				wire, err := m.Marshal(nil)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "checksum" && reads == 1 {
					wire[2] ^= 1
				}
				if mode == "reply-error" {
					err = native
				}
				if mode == "reply-cancel" {
					cancel()
					err = native
				}
				return copy(p, wire), addr, err
			}
			var receipt ICMPEchoReceipt
			err := exchangeICMPEcho(ctx, c, destination, payload, mode == "datagram-id", &receipt)
			switch mode {
			case "short-write", "partial-error", "read-error":
				want := native
				if mode == "short-write" {
					want = io.ErrShortWrite
				}
				if !errors.Is(err, want) || receipt.RoundTrip != nil || receipt.ReplySource.IsValid() || receipt.WrittenBytes == nil {
					t.Fatalf("partial ICMP facts: %+v, %v", receipt, err)
				}
				if mode != "read-error" && *receipt.WrittenBytes != 7 {
					t.Fatal("lost positive partial ICMP write")
				}
			default:
				wantError := mode == "reply-error" || mode == "reply-cancel"
				if (err != nil) != wantError || wantError && !errors.Is(err, native) || receipt.RoundTrip == nil || receipt.ReplySource != destination || receipt.ReplyBytes != len(payload)+8 {
					t.Fatalf("correlated ICMP facts: %+v, %v", receipt, err)
				}
				if mode == "wrong-source" || mode == "wrong-type" || mode == "wrong-code" || mode == "wrong-id" || mode == "wrong-sequence" || mode == "wrong-payload" || mode == "malformed" || mode == "checksum" {
					if reads != 2 {
						t.Fatal("unrelated/invalid ICMP packet manufactured completion")
					}
				}
			}
		})
	}
}

type blockedEchoConn struct {
	echoTestConn
	closed chan struct{}
	once   sync.Once
}

func (c *blockedEchoConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestICMPEchoBlockedReadCancellationAndDeadline(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if timeout {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		}
		func() {
			defer cancel()
			entered := make(chan struct{})
			c := &blockedEchoConn{closed: make(chan struct{})}
			defer c.Close()
			c.write = func(p []byte, _ net.Addr) (int, error) { return len(p), nil }
			c.read = func([]byte) (int, net.Addr, error) {
				close(entered)
				<-c.closed
				return 0, nil, net.ErrClosed
			}
			var receipt ICMPEchoReceipt
			done := make(chan error, 1)
			go func() {
				done <- exchangeICMPEcho(ctx, c, netip.MustParseAddr("127.0.0.1"), []byte("bounded-echo-fixture"), false, &receipt)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("ICMP did not enter its read owner")
			}
			if !timeout {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, net.ErrClosed) || ctx.Err() == nil || receipt.RoundTrip != nil || receipt.WrittenBytes == nil || *receipt.WrittenBytes != 28 {
					t.Fatalf("blocked ICMP facts: %+v, %v / %v", receipt, err, ctx.Err())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("ICMP cancellation retained a blocked reader")
			}
		}()
	}
}

func nativeEchoCapability(t *testing.T, destination netip.Addr) {
	t.Helper()
	network, local, protocol := "ip4:icmp", "0.0.0.0", 1
	requestType, replyType := icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply)
	if destination.Is6() {
		network, local, protocol = "ip6:ipv6-icmp", "::", 58
		requestType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	datagram := runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin" || runtime.GOOS == "ios"
	if datagram {
		network = "udp4"
		if destination.Is6() {
			network = "udp6"
		}
	}
	c, err := icmp.ListenPacket(network, local)
	if err != nil {
		t.Skip("independent native ICMP socket unavailable:", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	data := []byte("independent-native-echo")
	wire, err := (&icmp.Message{Type: requestType, Body: &icmp.Echo{ID: 17, Seq: 1, Data: data}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	var peer net.Addr = &net.IPAddr{IP: destination.AsSlice()}
	if datagram {
		peer = &net.UDPAddr{IP: destination.AsSlice()}
	}
	if _, err := c.WriteTo(wire, peer); err != nil {
		t.Skip("independent native ICMP send unavailable:", err)
	}
	packet := make([]byte, 65536)
	for {
		n, _, err := c.ReadFrom(packet)
		if err != nil {
			t.Skip("independent native ICMP echo unavailable:", err)
		}
		m, err := icmp.ParseMessage(protocol, packet[:n])
		if err == nil && m.Type == replyType {
			if echo, ok := m.Body.(*icmp.Echo); ok && bytes.Equal(echo.Data, data) {
				return
			}
		}
	}
}

func TestICMPEchoNativeLoopbackControllersAndSeries(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			destination := netip.MustParseAddr(address)
			nativeEchoCapability(t, destination)
			e, err := New(nil, 2)
			if err != nil {
				t.Fatal(err)
			}
			request := ICMPEchoRequest{Route: Route{Kind: Direct}, Destination: destination, PayloadBytes: 24, Timeout: time.Second}
			internet.ControllersLock.Lock()
			original := internet.Controllers
			internet.ControllersLock.Unlock()
			defer func() {
				internet.ControllersLock.Lock()
				internet.Controllers = original
				internet.ControllersLock.Unlock()
			}()
			var mu sync.Mutex
			calls := 0
			controllerErr := errors.New("ICMP controller rejected socket")
			internet.ControllersLock.Lock()
			internet.Controllers = append(original[:len(original):len(original)], func(network, target string, raw syscall.RawConn) error {
				addrPort, err := netip.ParseAddrPort(target)
				if err != nil || addrPort.Port() != 0 || addrPort.Addr() != destination || !addrPort.Addr().IsLoopback() {
					t.Error("ICMP controller lost native endpoint/loopback parsing")
				}
				switch network {
				case "ip4", "udp4":
					if !destination.Is4() {
						t.Error("ICMP controller received the wrong IPv4 family")
					}
				case "ip6", "udp6":
					if !destination.Is6() {
						t.Error("ICMP controller received the wrong IPv6 family")
					}
				default:
					t.Errorf("ICMP controller received an unsupported native family: %s", network)
				}
				mu.Lock()
				calls++
				mu.Unlock()
				return raw.Control(func(uintptr) {})
			})
			internet.ControllersLock.Unlock()
			samples, err := RunSeries(context.Background(), e, 4, 2, func(ctx context.Context, _ int) (ICMPEchoReceipt, error) { return e.ICMPEcho(ctx, request) })
			if err != nil || len(samples) != 4 || calls != 4 {
				t.Fatalf("native ICMP series: %d samples, %d controllers, %v", len(samples), calls, err)
			}
			seen := make(map[[16]byte]bool)
			for _, sample := range samples {
				r := sample.Receipt
				if sample.Err != nil || r.RoundTrip == nil || r.ReplySource != destination || r.WrittenBytes == nil || *r.WrittenBytes != 32 || r.ReplyBytes != 32 || seen[r.Nonce] {
					t.Fatalf("native ICMP receipt association: %+v, %v", r, sample.Err)
				}
				seen[r.Nonce] = true
			}
			internet.ControllersLock.Lock()
			internet.Controllers = append(internet.Controllers, func(string, string, syscall.RawConn) error { return controllerErr })
			internet.ControllersLock.Unlock()
			if r, err := e.ICMPEcho(context.Background(), request); !errors.Is(err, controllerErr) || r.WrittenBytes != nil || r.RoundTrip != nil {
				t.Fatalf("controller rejection sent an echo: %+v, %v", r, err)
			}
		})
	}
}

func TestICMPEchoRejectedRequests(t *testing.T) {
	e := &Executor{slots: make(chan struct{}, 1)}
	request := ICMPEchoRequest{Route: Route{Kind: Direct}, Destination: netip.MustParseAddr("127.0.0.1"), PayloadBytes: 24, Timeout: time.Second}
	for _, change := range []func(*ICMPEchoRequest){
		func(r *ICMPEchoRequest) { r.Route = Route{Kind: ExactOutbound, Tag: "node"} },
		func(r *ICMPEchoRequest) { r.Destination = netip.Addr{} },
		func(r *ICMPEchoRequest) { r.PayloadBytes = 15 },
		func(r *ICMPEchoRequest) { r.PayloadBytes = 65508 },
		func(r *ICMPEchoRequest) { r.Timeout = 0 },
	} {
		r := request
		change(&r)
		if got, err := e.ICMPEcho(context.Background(), r); err == nil || got.WrittenBytes != nil || got.Elapsed != 0 {
			t.Fatalf("rejected ICMP request: %+v, %v", got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := e.ICMPEcho(ctx, request); !errors.Is(err, context.Canceled) || got.Elapsed != 0 || got.WrittenBytes != nil {
		t.Fatalf("precanceled ICMP request: %+v, %v", got, err)
	}
}
