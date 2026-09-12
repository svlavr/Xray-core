package realm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/realm/internal/nat"
)

func TestClientSetupCancellationClosesProvisionalSocket(t *testing.T) {
	stunSink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stunSink.Close()
	received := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		if _, _, err := stunSink.ReadFromUDP(buf); err == nil {
			close(received)
		}
	}()
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := NewConnClientContext(ctx, &Config{
			Scheme:      "http",
			Host:        "127.0.0.1",
			Port:        "1",
			ID:          "realm",
			StunServers: []string{stunSink.LocalAddr().String()},
			IPMode:      "v4",
		}, raw)
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("STUN setup did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled setup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock provisional socket")
	}
	if _, err := raw.WriteTo([]byte("closed"), stunSink.LocalAddr()); err == nil {
		t.Fatal("provisional socket remained open")
	}
}

func TestClientSetupFailureRollsBackOwnedMapping(t *testing.T) {
	gateway := &testGateway{grant: nat.Grant{Port: 4321, Lifetime: time.Minute}, ip: net.IPv4(203, 0, 113, 3)}
	mapper, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: time.Second}, gateway)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newConnClientContext(context.Background(), &Config{
		Scheme:      "http",
		Host:        "127.0.0.1",
		Port:        "1",
		ID:          "realm",
		IPMode:      "v4",
		PortMapping: &PortMapping{Enabled: true, Lifetime: 60},
	}, raw, func(context.Context, int, PortMapConfig) (*PortMapper, error) {
		return mapper, nil
	})
	if err == nil {
		t.Fatal("setup without STUN locals succeeded")
	}
	if gateway.deletes != 1 || mapper.Receipt() != PortMapRemoteDeleteConfirmed {
		t.Fatalf("deletes=%d receipt=%d", gateway.deletes, mapper.Receipt())
	}
}

func TestServerSessionJoinsPunchBeforeDeregister(t *testing.T) {
	registered := make(chan struct{})
	allowRegister := make(chan struct{})
	eventsStarted := make(chan struct{})
	connectStarted := make(chan struct{})
	deregistered := make(chan struct{})
	var deregisterBeforeJoin atomic.Bool
	var registerOnce, eventsOnce, connectOnce, deregisterOnce sync.Once
	var conn *realmConnServer
	nonce := strings.Repeat("01", PunchNonceSize)
	obfs := strings.Repeat("02", PunchObfsKeySize)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/realm":
			registerOnce.Do(func() { close(registered) })
			select {
			case <-allowRegister:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"session_id":"session-1","ttl":60}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/realm/events":
			eventsOnce.Do(func() { close(eventsStarted) })
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: punch\ndata: {\"addresses\":[\"127.0.0.1:9\"],\"nonce\":%q,\"obfs\":%q}\n\n", nonce, obfs)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/realm/connects/"):
			connectOnce.Do(func() { close(connectStarted) })
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/realm":
			conn.mu.Lock()
			activePunches := len(conn.events)
			conn.mu.Unlock()
			if activePunches != 0 {
				deregisterBeforeJoin.Store(true)
			}
			deregisterOnce.Do(func() { close(deregistered) })
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := NewConnServerContext(context.Background(), &Config{
		Scheme: "http",
		Host:   host,
		Port:   port,
		Token:  "token",
		ID:     "realm",
		IPMode: "v4",
	}, raw)
	if err != nil {
		t.Fatal(err)
	}
	conn = wrapper.(*realmConnServer)
	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("register did not start")
	}
	conn.localsMu.Lock()
	conn.locals = []netip.AddrPort{raw.LocalAddr().(*net.UDPAddr).AddrPort()}
	conn.localsLast = time.Now()
	conn.localsMu.Unlock()
	close(allowRegister)
	select {
	case <-eventsStarted:
	case <-time.After(time.Second):
		t.Fatal("events stream did not start")
	}
	select {
	case <-connectStarted:
	case <-time.After(time.Second):
		t.Fatal("punch child did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-deregistered:
	default:
		t.Fatal("session was not deregistered")
	}
	if deregisterBeforeJoin.Load() {
		t.Fatal("deregister ran before punch child completion")
	}
	conn.cleanupMu.Lock()
	cleanups := append([]sessionCleanupReceipt(nil), conn.cleanups...)
	conn.cleanupMu.Unlock()
	if len(cleanups) != 1 || cleanups[0].sessionID != "session-1" || !cleanups[0].confirmed || cleanups[0].err != nil {
		t.Fatalf("cleanup receipts=%+v", cleanups)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerCloseCancelsBlockedRegister(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	releaseHandler := make(chan struct{})
	var startOnce, finishOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(started) })
		<-releaseHandler
		finishOnce.Do(func() { close(finished) })
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := NewConnServerContext(context.Background(), &Config{Scheme: "http", Host: host, Port: port, ID: "realm", IPMode: "v4"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("register did not start")
	}
	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}
	close(releaseHandler)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel blocked register")
	}
}

func TestDeregisterFailureReceiptIsUnconfirmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	c := &realmConnServer{
		realmClient: NewClient("http", host, port, "", nil),
		realmID:     "realm",
		cleanupTTL:  time.Second,
	}
	if err := c.deregisterSession("session-1"); err == nil {
		t.Fatal("failed deregister reported success")
	}
	if len(c.cleanups) != 1 || c.cleanups[0].confirmed || c.cleanups[0].err == nil {
		t.Fatalf("cleanup receipts=%+v", c.cleanups)
	}
}
