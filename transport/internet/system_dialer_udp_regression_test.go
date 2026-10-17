package internet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func udpFixture(t *testing.T, network, address string) net.PacketConn {
	t.Helper()
	peer, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return peer
}

func readUDPPayload(t *testing.T, packet net.PacketConn, want []byte) net.Addr {
	t.Helper()
	if err := packet.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 256)
	n, from, err := packet.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], want) {
		t.Fatalf("bind=%v read=%d source=%v error=%v payload=%q want=%q", packet.LocalAddr(), n, from, err, b[:n], want)
	}
	return from
}

func sendUDPPayload(t *testing.T, packet net.PacketConn, to net.Addr, payload []byte) {
	t.Helper()
	if err := packet.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := packet.WriteTo(payload, to)
	if err != nil || n != len(payload) {
		t.Fatalf("bind=%v to=%v written=%d error=%v", packet.LocalAddr(), to, n, err)
	}
}

// Exercise actual native packet sources and alternate destinations, independently
// of Measurement parsing and without changing the global dialer/controllers.
func TestSystemUDPAlternateIPv4Packets(t *testing.T) {
	peer := udpFixture(t, "udp4", "127.0.0.1:0")
	other := udpFixture(t, "udp4", "127.0.0.1:0")
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(peer.LocalAddr().(*net.UDPAddr).Port))
	conn, err := new(DefaultSystemDialer).Dial(context.Background(), nil, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	packet, ok := conn.(*xnet.PacketConnWrapper)
	if !ok {
		t.Fatalf("native packet type %T", conn)
	}
	for i, target := range []net.PacketConn{peer, other} {
		request := []byte{byte(i), 1, 2, 3}
		sendUDPPayload(t, packet, target.LocalAddr(), request)
		source := readUDPPayload(t, target, request)
		reply := []byte{byte(i), 9, 8, 7}
		sendUDPPayload(t, other, source, reply)
		actual := readUDPPayload(t, packet, reply)
		if actual.String() != other.LocalAddr().String() {
			t.Fatalf("actual source=%v want=%v", actual, other.LocalAddr())
		}
	}
}

// TestSystemUDPSamePortEchoDiagnostics preserves the plain Measurement fixture.
// Same-port bind refusal is inconclusive for the observed ephemeral allocation.
// It does not alter global controllers, dialers, sysctls, or runtime behavior.
func TestSystemUDPSamePortEchoDiagnostics(t *testing.T) {
	if os.Getenv("XRAY_NATIVE_UDP_DIAGNOSTICS") != "1" {
		t.Skip("requires XRAY_NATIVE_UDP_DIAGNOSTICS=1")
	}
	if len(Controllers) != 0 {
		t.Fatal("default-socket control requires no registered dialer controllers")
	}
	type observation struct {
		who  string
		data []byte
		from net.Addr
		err  error
		at   time.Time
	}
	read := func(who string, pc net.PacketConn) observation {
		r := observation{who: who}
		if r.err = pc.SetReadDeadline(time.Now().Add(time.Second)); r.err != nil {
			return r
		}
		b := make([]byte, 65536)
		var n int
		n, r.from, r.err = pc.ReadFrom(b)
		r.data, r.at = b[:n], time.Now()
		return r
	}
	for _, allocation := range []string{"forced-same-port", "default-distinct-port", "ephemeral-same-port", "wildcard-fixture"} {
		const size = 8191
		t.Run(allocation, func(t *testing.T) {
			ctx := context.Background()
			network, address := "udp4", "127.0.0.1:0"
			if allocation == "wildcard-fixture" {
				network, address = "udp", "0.0.0.0:0"
			}
			peer, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: peer.LocalAddr().(*net.UDPAddr).Port}
			t.Logf("FIXTURE actual=%v target=%v", peer.LocalAddr(), peerAddr)
			var sender net.PacketConn
			if allocation == "wildcard-fixture" {
				var lc net.ListenConfig
				same, bindErr := lc.ListenPacket(ctx, "udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(peerAddr.Port)))
				if bindErr == nil {
					same.Close()
					t.Fatal("WILDCARD_FIXTURE_STILL_ADMITS_SAME_PORT")
				}
				// Winsock WSAEADDRINUSE is distinct from Go's compatibility errno.
				if !errors.Is(bindErr, syscall.EADDRINUSE) && !(runtime.GOOS == "windows" && errors.Is(bindErr, syscall.Errno(10048))) {
					t.Fatalf("INCONCLUSIVE WILDCARD_BIND_ERROR: %v", bindErr)
				}
				t.Logf("SAME_PORT_REJECTED_EADDRINUSE error=%v", bindErr)
			}
			if allocation == "forced-same-port" {
				// DefaultSystemDialer's native input is network udp and
				// wildcard 0.0.0.0:0. Fix only its port for this control.
				var lc net.ListenConfig
				sender, err = lc.ListenPacket(ctx, "udp",
					net.JoinHostPort("0.0.0.0", strconv.Itoa(peerAddr.Port)))
				if err != nil {
					t.Logf("INCONCLUSIVE SAME_PORT_BIND_REFUSED fixture=%v error=%v; natural ephemeral collision remains untested", peerAddr, err)
					return
				}
			} else if allocation == "ephemeral-same-port" {
				// Exercise the unchanged native allocation leaf with port zero.
				// Explicit-port bind admission can differ from ephemeral allocation.
				searchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				var lc net.ListenConfig
				var seen [1 << 16]bool
				attempts, unique := 0, 0
				started := time.Now()
				for attempts < 65536 && searchCtx.Err() == nil {
					candidate, bindErr := lc.ListenPacket(searchCtx, "udp", "0.0.0.0:0")
					attempts++
					if bindErr != nil {
						if searchCtx.Err() != nil {
							break
						}
						t.Fatalf("EPHEMERAL_BIND_ERROR: %v", bindErr)
					}
					port := candidate.LocalAddr().(*net.UDPAddr).Port
					if !seen[port] {
						seen[port] = true
						unique++
					}
					if port == peerAddr.Port {
						sender = candidate
						break
					}
					if err := candidate.Close(); err != nil {
						t.Fatal(err)
					}
				}
				cancel()
				t.Logf("EPHEMERAL_SEARCH attempts=%d unique=%d elapsed=%v witnessed=%t", attempts, unique, time.Since(started), sender != nil)
				if sender == nil {
					t.Log("INCONCLUSIVE NO_EPHEMERAL_COLLISION_WITNESSED")
					return
				}
			} else {
				dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(peerAddr.Port))
				conn, dialErr := new(DefaultSystemDialer).Dial(ctx, nil, dest, nil)
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				sender = conn.(*xnet.PacketConnWrapper).PacketConn
			}
			t.Cleanup(func() { _ = sender.Close() })
			if allocation == "wildcard-fixture" && sender.LocalAddr().(*net.UDPAddr).Port == peerAddr.Port {
				t.Fatal("WILDCARD_DEFAULT_ALLOCATION_COLLIDED")
			}
			if allocation == "default-distinct-port" && sender.LocalAddr().(*net.UDPAddr).Port == peerAddr.Port {
				t.Logf("INCONCLUSIVE DISTINCT_CONTROL_COLLIDED fixture=%v sender=%v; no retry", peerAddr, sender.LocalAddr())
				return
			}
			payload := bytes.Repeat([]byte{0x5a}, size)
			if err := sender.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			n, writeErr := sender.WriteTo(payload, peerAddr)
			t.Logf("REQUEST fixture=%v sender=%v n=%d error=%v size=%d hash=%x", peerAddr, sender.LocalAddr(), n, writeErr, size, sha256.Sum256(payload))
			if writeErr != nil || n != size {
				t.Fatalf("REQUEST_WRITE_FAILED n=%d error=%v", n, writeErr)
			}
			request := read("fixture-request", peer)
			t.Logf("REQUEST_READ at=%s source=%v n=%d error=%v hash=%x", request.at.Format(time.RFC3339Nano), request.from, len(request.data), request.err, sha256.Sum256(request.data))
			if request.err != nil || !bytes.Equal(request.data, payload) {
				t.Fatal("REQUEST_NOT_RECEIVED_INTACT")
			}
			source := request.from.(*net.UDPAddr).AddrPort()
			local := peerAddr.AddrPort()
			echoTargetsFixture := source.Port() == local.Port() && source.Addr().Unmap() == local.Addr().Unmap()
			if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			results := make(chan observation, 2)
			go func() { results <- read("sender-return", sender) }()
			go func() { results <- read("fixture-again", peer) }()
			n, writeErr = peer.WriteTo(request.data, request.from)
			t.Logf("ONE_ECHO to=%v targetsFixture=%t n=%d error=%v", request.from, echoTargetsFixture, n, writeErr)
			var returned, again observation
			for range 2 {
				r := <-results
				t.Logf("READ who=%s at=%s source=%v n=%d error=%v hash=%x", r.who, r.at.Format(time.RFC3339Nano), r.from, len(r.data), r.err, sha256.Sum256(r.data))
				if r.who == "sender-return" {
					returned = r
				} else {
					again = r
				}
			}
			if writeErr != nil || n != size {
				t.Fatalf("ECHO_WRITE_FAILED n=%d error=%v", n, writeErr)
			}
			if again.err == nil && bytes.Equal(again.data, payload) {
				if timeout, ok := returned.err.(net.Error); !ok || !timeout.Timeout() || len(returned.data) != 0 {
					t.Fatal("FIXTURE_SELF_ECHO_WITH_OTHER_SENDER_OUTCOME")
				}
				t.Fatal("FIXTURE_SELF_ECHO_REPRODUCED")
			}
			if returned.err != nil || !bytes.Equal(returned.data, payload) {
				t.Fatal("NATIVE_RETURN_ABSENT_WITH_SUCCESSFUL_ECHO_WRITE")
			}
			if timeout, ok := again.err.(net.Error); !ok || !timeout.Timeout() || len(again.data) != 0 {
				t.Fatalf("unexpected fixture return: n=%d error=%v", len(again.data), again.err)
			}
			actual := returned.from.(*net.UDPAddr).AddrPort()
			if actual.Port() != local.Port() || actual.Addr().Unmap() != local.Addr().Unmap() {
				t.Fatalf("RETURN_SOURCE_CHANGED actual=%v expected=%v", actual, local)
			}
			t.Log("NATIVE_RETURN_INTACT")
		})
	}
}
