package measurement_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// TestNetworkDiagnostics records bounded observations, not endpoint health or
// an automatic retry of a failed operation. Normal test runs leave it disabled.
func TestNetworkDiagnostics(t *testing.T) {
	if os.Getenv("XRAY_NETWORK_DIAGNOSTICS") != "1" {
		t.Skip("explicit network diagnostics only")
	}
	t.Logf("platform=%s/%s go=%s utc=%s", runtime.GOOS, runtime.GOARCH, runtime.Version(), time.Now().UTC().Format(time.RFC3339))
	t.Run("nativeUDP", func(t *testing.T) {
		for _, family := range []string{"udp", "udp4"} {
			networkDiagnosticUDP(t, family, true, 0)
			failures, collisions := 0, 0
			for i := range 10000 {
				ok, collision := networkDiagnosticUDP(t, family, false, i)
				if !ok {
					failures++
				}
				if collision {
					collisions++
				}
			}
			networkDiagnosticLog(t, map[string]any{"family": family, "auto_attempts": 10000, "failures": failures, "collisions": collisions})
		}
	})
	t.Run("reusableInboundUDP", networkDiagnosticReusableUDP)
	t.Run("ECH", networkDiagnosticECH)
}

func networkDiagnosticLog(t *testing.T, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}

func networkDiagnosticUDP(t *testing.T, family string, forced bool, index int) (bool, bool) {
	t.Helper()
	started := time.Now()
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	port := peer.LocalAddr().(*net.UDPAddr).Port
	bind := ":0"
	if forced {
		bind = fmt.Sprintf(":%d", port)
	}
	client, err := net.ListenPacket(family, bind)
	if err != nil {
		networkDiagnosticLog(t, map[string]any{"family": family, "forced": forced, "index": index, "peer": peer.LocalAddr().String(), "bind_error": err.Error()})
		return false, false
	}
	defer client.Close()
	collision := client.LocalAddr().(*net.UDPAddr).Port == port
	type peerResult struct {
		RequestRead    int
		RequestSource  string
		ReadError      string
		ReadMillis     float64
		ReplyWrite     int
		WriteError     string
		WriteMillis    float64
		SelfReplyRead  int
		SelfReplyError string
	}
	done := make(chan peerResult, 1)
	payload, reply := []byte("request-must-reach-peer"), []byte("reply-must-reach-client")
	go func() {
		r := peerResult{}
		peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		peer.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		b := make([]byte, 256)
		n, a, e := peer.ReadFrom(b)
		r.RequestRead, r.ReadError = n, fmt.Sprint(e)
		r.ReadMillis = float64(time.Since(started).Microseconds()) / 1000
		if a != nil {
			r.RequestSource = a.String()
		}
		if e == nil && bytes.Equal(b[:n], payload) {
			r.ReplyWrite, e = peer.WriteTo(reply, a)
			r.WriteError = fmt.Sprint(e)
			r.WriteMillis = float64(time.Since(started).Microseconds()) / 1000
			if collision {
				peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				n, _, e = peer.ReadFrom(b)
				if e == nil && bytes.Equal(b[:n], reply) {
					r.SelfReplyRead = n
				}
				r.SelfReplyError = fmt.Sprint(e)
			}
		}
		done <- r
	}()
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	client.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	n, werr := client.WriteTo(payload, peer.LocalAddr())
	b := make([]byte, 256)
	received, source, rerr := client.ReadFrom(b)
	peerFacts := <-done
	ok := werr == nil && rerr == nil && bytes.Equal(b[:received], reply) && source != nil && source.String() == peer.LocalAddr().String()
	if forced || collision || !ok {
		networkDiagnosticLog(t, map[string]any{"family": family, "forced": forced, "index": index, "peer": peer.LocalAddr().String(), "client": client.LocalAddr().String(), "collision": collision, "client_written": n, "write_error": fmt.Sprint(werr), "client_received": received, "reply_source": fmt.Sprint(source), "read_error": fmt.Sprint(rerr), "peer_events": peerFacts, "ok": ok})
	}
	return ok, collision
}

type networkDiagnosticConn struct {
	net.Conn
	written atomic.Int64
	read    atomic.Int64
}

func (c *networkDiagnosticConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func (c *networkDiagnosticConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// Keep actual Xray inbound listeners alive while exercising the unchanged
// DefaultSystemDialer. A packet observed at an unrelated listener is retained
// separately from the client's receipt; absence alone is not attribution.
func networkDiagnosticReusableUDP(t *testing.T) {
	const attempts = 10000
	type delivery struct {
		Port    int
		Source  string
		Payload string
	}
	diverted := make(chan delivery, attempts+1)
	var divertedOverflow atomic.Int64
	ports := make(map[int]net.PacketConn)
	var listeners []net.PacketConn
	var listenerDone []chan struct{}
	defer func() {
		for _, pc := range listeners {
			pc.Close()
		}
		for _, done := range listenerDone {
			<-done
		}
	}()
	for range 8 {
		pc, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ports[port] = pc
		listeners = append(listeners, pc)
		done := make(chan struct{})
		listenerDone = append(listenerDone, done)
		networkDiagnosticLog(t, map[string]any{"phase": "reusable-inbound", "endpoint": pc.LocalAddr().String(), "flags": networkDiagnosticSocketFlags(pc)})
		go func() {
			defer close(done)
			b := make([]byte, 256)
			for {
				n, source, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				select {
				case diverted <- delivery{port, source.String(), string(b[:n])}:
				default:
					divertedOverflow.Add(1)
				}
			}
		}()
	}
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan struct{})
	selfControlSeen := make(chan struct{}, 1)
	selfControl := []byte("reply:diagnostic-request-00000000")
	var peerReads, peerRequests, peerIgnored, peerDuplicates, peerWrites, peerWriteErrors atomic.Int64
	go func() {
		defer close(peerDone)
		b := make([]byte, 256)
		seen := make([]bool, attempts)
		for {
			n, source, err := peer.ReadFrom(b)
			if err != nil {
				return
			}
			peerReads.Add(1)
			packet := string(b[:n])
			var index int
			_, parseErr := fmt.Sscanf(packet, "diagnostic-request-%d", &index)
			if parseErr != nil || index < 0 || index >= attempts || packet != fmt.Sprintf("diagnostic-request-%08d", index) {
				peerIgnored.Add(1)
				if bytes.Equal(b[:n], selfControl) && source.String() == peer.LocalAddr().String() {
					select {
					case selfControlSeen <- struct{}{}:
					default:
					}
				}
				continue
			}
			if seen[index] {
				peerDuplicates.Add(1)
				continue
			}
			seen[index] = true
			peerRequests.Add(1)
			peer.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			reply := append([]byte("reply:"), b[:n]...)
			written, err := peer.WriteTo(reply, source)
			if err != nil || written != len(reply) {
				peerWriteErrors.Add(1)
			} else {
				peerWrites.Add(1)
			}
		}
	}()
	defer func() { peer.Close(); <-peerDone }()
	// A deliberately self-delivered reply must not become another request.
	peer.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	controlWritten, controlErr := peer.WriteTo(selfControl, peer.LocalAddr())
	controlObserved := false
	select {
	case <-selfControlSeen:
		controlObserved = true
	case <-time.After(100 * time.Millisecond):
	}
	networkDiagnosticLog(t, map[string]any{"phase": "peer-self-reply-control", "written": controlWritten, "error": fmt.Sprint(controlErr), "observed": controlObserved})
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	dest := xnet.UDPDestination(xnet.IPAddress(peerAddr.IP), xnet.Port(peerAddr.Port))
	native := new(internet.DefaultSystemDialer)
	collisions, failures := 0, 0
	for i := range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := native.Dial(ctx, nil, dest, nil)
		if err != nil {
			cancel()
			failures++
			networkDiagnosticLog(t, map[string]any{"phase": "default-dialer", "index": i, "error": err.Error()})
			continue
		}
		local := c.LocalAddr().(*net.UDPAddr)
		_, collision := ports[local.Port]
		if collision {
			collisions++
		}
		packet := []byte(fmt.Sprintf("diagnostic-request-%08d", i))
		expected := append([]byte("reply:"), packet...)
		c.SetDeadline(time.Now().Add(100 * time.Millisecond))
		written, writeErr := c.Write(packet)
		b := make([]byte, 256)
		received, readErr := c.Read(b)
		ok := writeErr == nil && written == len(packet) && readErr == nil && bytes.Equal(b[:received], expected)
		if !ok {
			failures++
		}
		if i == 0 || collision || !ok {
			pc := c.(*xnet.PacketConnWrapper).PacketConn
			networkDiagnosticLog(t, map[string]any{"phase": "default-dialer-exchange", "index": i, "client": local.String(), "peer": peer.LocalAddr().String(), "inbound_collision": collision, "written": written, "write_error": fmt.Sprint(writeErr), "received": received, "read_error": fmt.Sprint(readErr), "expected_reply": string(expected), "ok": ok, "flags": networkDiagnosticSocketFlags(pc)})
		}
		c.Close()
		cancel()
	}
	// Stop both peer and inbound readers before reconciling the finite events.
	peer.Close()
	<-peerDone
	for _, pc := range listeners {
		pc.Close()
	}
	for _, done := range listenerDone {
		<-done
	}
	close(diverted)
	diversions := 0
	for event := range diverted {
		diversions++
		networkDiagnosticLog(t, map[string]any{"phase": "reply-at-inbound", "port": event.Port, "source": event.Source, "payload": event.Payload, "peer_source_matches": event.Source == peer.LocalAddr().String()})
	}
	networkDiagnosticLog(t, map[string]any{"phase": "default-dialer-summary", "attempts": attempts, "inbound_listeners": len(listeners), "collisions": collisions, "client_failures": failures, "inbound_packets": diversions, "inbound_event_overflow": divertedOverflow.Load(), "peer_reads": peerReads.Load(), "peer_requests": peerRequests.Load(), "peer_ignored": peerIgnored.Load(), "peer_duplicates": peerDuplicates.Load(), "peer_writes": peerWrites.Load(), "peer_write_errors": peerWriteErrors.Load(), "peer_control_reply_observed": controlObserved})
}

func networkDiagnosticECH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, "cloudflare.com")
	cancel()
	if err != nil {
		networkDiagnosticLog(t, map[string]any{"phase": "destination-dns", "error": err.Error()})
		return
	}
	echConfig, echErr := xraytls.QueryRecord("encryptedsni.com", "udp://1.1.1.1", nil)
	hash := sha256.Sum256(echConfig)
	networkDiagnosticLog(t, map[string]any{"phase": "ech-config", "bytes": len(echConfig), "sha256": hex.EncodeToString(hash[:]), "error": fmt.Sprint(echErr)})
	type cell struct {
		name, ip, sni string
		ech, compact  bool
	}
	var cells []cell
	ipCount := 0
	for _, a := range addresses {
		if a.IP.To4() != nil {
			ipCount++
			ip := a.IP.String()
			cells = append(cells, cell{"plain", ip, "cloudflare.com", false, false}, cell{"outer-SNI", ip, "cloudflare-ech.com", false, false})
			if echErr == nil && len(echConfig) > 0 {
				cells = append(cells, cell{"ECH", ip, "cloudflare.com", true, false}, cell{"compact-ECH", ip, "cloudflare.com", true, true})
			}
			// Two endpoint IPs suffice for the declared control.
			if ipCount == 2 {
				break
			}
		}
	}
	if len(cells) == 0 {
		networkDiagnosticLog(t, map[string]any{"phase": "destination-addresses", "ipv4_cells": 0, "reason": "resolver returned no IPv4 destination"})
		return
	}
	for _, c := range cells {
		started := time.Now()
		cfg := &tls.Config{ServerName: c.sni, NextProtos: []string{"http/1.1"}}
		if c.ech {
			cfg.EncryptedClientHelloConfigList = append([]byte(nil), echConfig...)
		}
		if c.compact {
			cfg.CurvePreferences = []tls.CurveID{tls.X25519}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(c.ip, "443"))
		if err != nil {
			networkDiagnosticLog(t, map[string]any{"mode": c.name, "ip": c.ip, "phase": "connect", "error": err.Error()})
			cancel()
			continue
		}
		connected := time.Since(started)
		cc := &networkDiagnosticConn{Conn: conn}
		tc := tls.Client(cc, cfg)
		err = tc.HandshakeContext(ctx)
		cancel()
		state := tc.ConnectionState()
		networkDiagnosticLog(t, map[string]any{"mode": c.name, "ip": c.ip, "sni": c.sni, "phase": "handshake", "error": fmt.Sprint(err), "error_type": fmt.Sprintf("%T", err), "written": cc.written.Load(), "read": cc.read.Load(), "handshake_complete": state.HandshakeComplete, "ech_accepted": state.ECHAccepted, "tls_version": state.Version, "connect_ms": float64(connected.Microseconds()) / 1000, "elapsed_ms": float64(time.Since(started).Microseconds()) / 1000})
		tc.Close()
	}
}
