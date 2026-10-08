package internet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

type trackedUDPReservation struct {
	net.PacketConn
	closed int
}

func (r *trackedUDPReservation) Close() error {
	r.closed++
	return r.PacketConn.Close()
}

func TestSystemUDPReservationOwnership(t *testing.T) {
	for _, mode := range []string{"success", "controller-error", "cancel-before", "cancel-during-control", "ipv4-socket"} {
		t.Run(mode, func(t *testing.T) {
			guard, err := net.ListenPacket("udp4", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			r := &trackedUDPReservation{PacketConn: guard}
			t.Cleanup(func() { guard.Close() })
			port := guard.LocalAddr().(*net.UDPAddr).Port
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel-before" {
				cancel()
			}
			source := &net.UDPAddr{IP: net.IPv4zero}
			if mode == "ipv4-socket" {
				source.IP = net.IPv4(127, 0, 0, 1)
			}
			sentinel := errors.New("controller refused socket")
			calls := 0
			var finalRaw syscall.RawConn
			lc := &net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
				calls++
				finalRaw = raw
				wantNetwork := "udp6"
				if mode == "ipv4-socket" {
					wantNetwork = "udp4"
					if r.closed != 1 {
						t.Error("IPv4 reservation is still held before IPv4 bind")
					}
				} else if r.closed != 0 {
					t.Error("reservation released before dual-stack bind")
				}
				if network != wantNetwork || address != source.String() {
					t.Errorf("controller inputs=%s %s want=%s %s", network, address, wantNetwork, source)
				}
				if mode == "controller-error" {
					return sentinel
				}
				if mode == "cancel-during-control" {
					cancel()
				}
				return nil
			}}
			packet, err := listenReservedUDP(ctx, lc, source, r)
			if r.closed != 1 {
				t.Fatalf("reservation close calls=%d", r.closed)
			}
			if mode == "controller-error" || mode == "cancel-before" || mode == "cancel-during-control" {
				want := sentinel
				if mode != "controller-error" {
					want = context.Canceled
				}
				if packet != nil || !errors.Is(err, want) {
					t.Fatalf("packet=%v error=%v want=%v", packet, err, want)
				}
				if finalRaw != nil {
					if rawErr := finalRaw.Control(func(uintptr) {}); !errors.Is(rawErr, net.ErrClosed) {
						t.Fatalf("failed creation retained native descriptor: %v", rawErr)
					}
				}
				probe, bindErr := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
				if bindErr != nil {
					t.Fatalf("failed creation retained port %d: %v", port, bindErr)
				}
				probe.Close()
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				if packet.LocalAddr().(*net.UDPAddr).Port != port {
					t.Fatal("final socket did not use reserved port")
				}
				probe, bindErr := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
				if probe != nil {
					probe.Close()
				}
				if !errors.Is(bindErr, syscall.EADDRINUSE) {
					t.Fatalf("IPv4 binder acquired final socket's port: %v", bindErr)
				}
			}
			wantCalls := 1
			if mode == "cancel-before" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("controller calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}

func TestSystemUDPReservationIPv6Conflict(t *testing.T) {
	guard := udpFixture(t, "udp4", "0.0.0.0:0")
	port := guard.LocalAddr().(*net.UDPAddr).Port
	v6Holder := udpFixture(t, "udp6", fmt.Sprintf("[::]:%d", port))
	r := &trackedUDPReservation{PacketConn: guard}
	packet, err := listenReservedUDP(context.Background(), new(net.ListenConfig), &net.UDPAddr{IP: net.IPv4zero}, r)
	if packet != nil || !errors.Is(err, syscall.EADDRINUSE) || r.closed != 1 {
		t.Fatalf("packet=%v error=%v reservation closes=%d", packet, err, r.closed)
	}
	// The colliding external holder is not part of failed-creation cleanup.
	peer := udpFixture(t, "udp6", "[::1]:0")
	payload := []byte("external-IPv6-holder-stays-open")
	sendUDPPayload(t, peer, &net.UDPAddr{IP: net.IPv6loopback, Port: port}, payload)
	readUDPPayload(t, v6Holder, payload)
}

func TestSystemUDPReservationBothFamilies(t *testing.T) {
	v4 := udpFixture(t, "udp4", "127.0.0.1:0")
	v6 := udpFixture(t, "udp6", "[::1]:0")
	for _, first := range []net.PacketConn{v4, v6} {
		t.Run(first.LocalAddr().String(), func(t *testing.T) {
			destAddr := first.LocalAddr().(*net.UDPAddr)
			dest := xnet.UDPDestination(xnet.IPAddress(destAddr.IP), xnet.Port(destAddr.Port))
			conn, err := new(DefaultSystemDialer).Dial(context.Background(), nil, dest, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			packet := conn.(*xnet.PacketConnWrapper)
			local := conn.LocalAddr().(*net.UDPAddr)
			if local.IP.To4() != nil || !local.IP.IsUnspecified() {
				t.Fatalf("lost dual-stack wildcard bind: %v", local)
			}
			for i, peer := range []net.PacketConn{v4, v6} {
				request := []byte{byte(i), 1, 2, 3}
				sendUDPPayload(t, packet, peer.LocalAddr(), request)
				source := readUDPPayload(t, peer, request)
				reply := []byte{byte(i), 9, 8, 7}
				sendUDPPayload(t, peer, source, reply)
				actual := readUDPPayload(t, packet, reply)
				if actual.String() != peer.LocalAddr().String() {
					t.Fatalf("source=%v want=%v", actual, peer.LocalAddr())
				}
			}
			wrong := []byte("IPv6-wrong-source-visible-for-IPv4-target")
			sendUDPPayload(t, v6, &net.UDPAddr{IP: net.IPv6loopback, Port: local.Port}, wrong)
			if actual := readUDPPayload(t, packet, wrong); actual.String() != v6.LocalAddr().String() {
				t.Fatalf("wrong-source metadata=%v", actual)
			}
		})
	}
}

// The opt-in hosted pass preserves finite sample size, actual native binds,
// payload correlation and all failures. It is independent of Measurement parsing.
func TestSystemUDPReservationAllocation(t *testing.T) {
	attempts := 128
	if os.Getenv("XRAY_NATIVE_UDP_DIAGNOSTICS") == "1" {
		attempts = 10000
	}
	for _, reusable := range []bool{false, true} {
		t.Run(fmt.Sprintf("reusable=%t", reusable), func(t *testing.T) {
			peer := udpFixture(t, "udp4", "127.0.0.1:0")
			occupied := map[int]bool{peer.LocalAddr().(*net.UDPAddr).Port: true}
			if reusable {
				for range 8 {
					p, err := new(DefaultListener).ListenPacket(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { p.Close() })
					occupied[p.LocalAddr().(*net.UDPAddr).Port] = true
				}
			}
			dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(peer.LocalAddr().(*net.UDPAddr).Port))
			var first, last string
			for i := range attempts {
				conn, err := new(DefaultSystemDialer).Dial(context.Background(), nil, dest, nil)
				if err != nil {
					t.Fatal(err)
				}
				port := conn.LocalAddr().(*net.UDPAddr).Port
				if occupied[port] {
					conn.Close()
					t.Fatalf("index=%d native=%v selected an occupied IPv4 port", i, conn.LocalAddr())
				}
				if first == "" {
					first = conn.LocalAddr().String()
				}
				last = conn.LocalAddr().String()
				func() {
					defer conn.Close()
					packet := conn.(*xnet.PacketConnWrapper)
					request := []byte(fmt.Sprintf("native-request:%d", i))
					sendUDPPayload(t, packet, peer.LocalAddr(), request)
					source := readUDPPayload(t, peer, request)
					reply := []byte(fmt.Sprintf("native-reply:%d", i))
					sendUDPPayload(t, peer, source, reply)
					if actual := readUDPPayload(t, packet, reply); actual.String() != peer.LocalAddr().String() {
						t.Fatalf("index=%d unexpected reply source=%v", i, actual)
					}
				}()
			}
			t.Logf("attempts=%d occupied=%d first_bind=%s last_bind=%s peer=%s correlated_replies=%d", attempts, len(occupied), first, last, peer.LocalAddr(), attempts)
		})
	}
}

func TestSystemUDPReservationInterface(t *testing.T) {
	peer := udpFixture(t, "udp4", "127.0.0.1:0")
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(peer.LocalAddr().(*net.UDPAddr).Port))
	conn, err := new(DefaultSystemDialer).Dial(context.Background(), nil, dest, &SocketConfig{Interface: iface.Name})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packet := conn.(*xnet.PacketConnWrapper)
	raw, err := packet.PacketConn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var bound int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		bound, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF)
	}); err != nil || optionErr != nil || bound != iface.Index {
		t.Fatalf("bound interface=%d want=%d raw error=%v option error=%v", bound, iface.Index, err, optionErr)
	}
	request := []byte("bound-interface")
	sendUDPPayload(t, packet, peer.LocalAddr(), request)
	source := readUDPPayload(t, peer, request)
	sendUDPPayload(t, peer, source, request)
	readUDPPayload(t, packet, request)
}

func TestSystemUDPReservationCustomOptions(t *testing.T) {
	for _, opt := range []struct {
		name  string
		level int
		opt   int
	}{
		{"v6-only", unix.IPPROTO_IPV6, unix.IPV6_V6ONLY},
		{"reuse-port", unix.SOL_SOCKET, unix.SO_REUSEPORT},
	} {
		t.Run(opt.name, func(t *testing.T) {
			peer := udpFixture(t, "udp6", "[::1]:0")
			dest := xnet.UDPDestination(xnet.LocalHostIPv6, xnet.Port(peer.LocalAddr().(*net.UDPAddr).Port))
			conn, err := new(DefaultSystemDialer).Dial(context.Background(), nil, dest, &SocketConfig{
				CustomSockopt: []*CustomSockopt{{Network: "udp6", Level: strconv.Itoa(opt.level), Opt: strconv.Itoa(opt.opt), Value: "1", Type: "int"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			packet := conn.(*xnet.PacketConnWrapper)
			raw, err := packet.PacketConn.(*net.UDPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var actual int
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				actual, optionErr = unix.GetsockoptInt(int(fd), opt.level, opt.opt)
			}); err != nil || optionErr != nil || actual == 0 {
				t.Fatalf("option=%d raw error=%v option error=%v", actual, err, optionErr)
			}
			request := []byte(opt.name)
			sendUDPPayload(t, packet, peer.LocalAddr(), request)
			source := readUDPPayload(t, peer, request)
			sendUDPPayload(t, peer, source, request)
			readUDPPayload(t, packet, request)
		})
	}
}
