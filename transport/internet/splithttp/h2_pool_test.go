package splithttp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

const nativeH2Budget = 8 * time.Second

type nativeH2Gate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newNativeH2Gate() *nativeH2Gate {
	return &nativeH2Gate{entered: make(chan struct{}, 32), release: make(chan struct{})}
}

func (g *nativeH2Gate) open() { g.once.Do(func() { close(g.release) }) }

func (g *nativeH2Gate) wait(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(nativeH2Budget):
		t.Fatal("native H2 handshake did not enter fixture")
	}
}

// Only server-side raw sockets are wrapped: the native client TLS connection
// must retain its concrete type and its lazy/eager handshake behavior.
type nativeH2Conn struct {
	net.Conn
	id        int64
	bytesRead atomic.Int64
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (c *nativeH2Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bytesRead.Add(int64(n))
	return n, err
}

func (c *nativeH2Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		close(c.closed)
	})
	return c.closeErr
}

type nativeH2Listener struct {
	net.Listener
	accepts  atomic.Int64
	mu       sync.Mutex
	conns    []*nativeH2Conn
	accepted chan struct{}
}

func (l *nativeH2Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	raw := &nativeH2Conn{Conn: c, id: l.accepts.Add(1), closed: make(chan struct{})}
	l.conns = append(l.conns, raw)
	l.mu.Unlock()
	select {
	case l.accepted <- struct{}{}:
	default:
	}
	return raw, nil
}

func (l *nativeH2Listener) connections() []*nativeH2Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*nativeH2Conn(nil), l.conns...)
}

func (l *nativeH2Listener) waitAccepts(t *testing.T, count int64) {
	t.Helper()
	timer := time.NewTimer(nativeH2Budget)
	defer timer.Stop()
	for l.accepts.Load() < count {
		select {
		case <-l.accepted:
		case <-timer.C:
			t.Fatalf("native H2 accepted %d connections, want at least %d", l.accepts.Load(), count)
		}
	}
}

type nativeH2Fixture struct {
	server    *httptest.Server
	listener  *nativeH2Listener
	gate      *nativeH2Gate
	hellos    atomic.Int64
	failFirst atomic.Bool
}

func newNativeH2Fixture(t *testing.T, handler http.Handler, maxStreams uint32) *nativeH2Fixture {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "native H2 response")
		})
	}
	f := &nativeH2Fixture{server: httptest.NewUnstartedServer(handler), gate: newNativeH2Gate()}
	f.listener = &nativeH2Listener{Listener: f.server.Listener, accepted: make(chan struct{}, 32)}
	f.server.Listener = f.listener
	f.server.EnableHTTP2 = true
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.TLS = &gotls.Config{GetConfigForClient: func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
		f.hellos.Add(1)
		select {
		case f.gate.entered <- struct{}{}:
		default:
		}
		if f.failFirst.CompareAndSwap(true, false) {
			return nil, errors.New("controlled native H2 handshake rejection")
		}
		select {
		case <-f.gate.release:
			return nil, nil
		case <-hello.Context().Done():
			return nil, hello.Context().Err()
		}
	}}
	if maxStreams > 0 {
		if err := http2.ConfigureServer(f.server.Config, &http2.Server{MaxConcurrentStreams: maxStreams}); err != nil {
			t.Fatal(err)
		}
	}
	f.server.StartTLS()
	t.Cleanup(func() {
		f.gate.open()
		f.server.CloseClientConnections()
		f.server.Close()
	})
	return f
}

// GotConn's client local address identifies the server raw peer without
// wrapping the native client connection or relying on its pre-handshake TLS snapshot.
// Call after verifying a successful H2 response from this pinned TLS server.
func (f *nativeH2Fixture) peer(t *testing.T, result nativeH2Result) *nativeH2Conn {
	t.Helper()
	for _, raw := range f.listener.connections() {
		if raw.RemoteAddr().String() != result.localAddr {
			continue
		}
		return raw
	}
	t.Fatalf("native H2 response has no observed server peer: local address %q", result.localAddr)
	return nil
}

func (f *nativeH2Fixture) unusedClosed(t *testing.T, used *nativeH2Conn) {
	t.Helper()
	for _, raw := range f.listener.connections() {
		if raw == used {
			continue
		}
		select {
		case <-raw.closed:
		case <-time.After(nativeH2Budget):
			t.Fatalf("unused native H2 raw peer %d did not close before fixture teardown", raw.id)
		}
		if n := raw.bytesRead.Load(); n != 0 {
			t.Fatalf("extra native H2 raw peer %d was used: bytes=%d", raw.id, n)
		}
	}
}

func (f *nativeH2Fixture) destination(t *testing.T) cnet.Destination {
	t.Helper()
	_, portText, err := net.SplitHostPort(f.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return cnet.TCPDestination(cnet.LocalHostIP, cnet.Port(port))
}

func (f *nativeH2Fixture) settings(fingerprint string) *internet.MemoryStreamConfig {
	pin := sha256.Sum256(f.server.Certificate().Raw)
	return &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{Path: "/", Xmux: &XmuxConfig{
			MaxConnections: &RangeConfig{From: 1, To: 1},
			MaxConcurrency: &RangeConfig{From: 0, To: 0},
		}},
		SecurityType: "tls",
		SecuritySettings: &xtls.Config{
			ServerName: "localhost", Fingerprint: fingerprint, NextProtocol: []string{"h2"},
			PinnedPeerCertSha256: [][]byte{pin[:]},
		},
	}
}

func nativeH2Client(t *testing.T, dest cnet.Destination, settings *internet.MemoryStreamConfig) (*DefaultDialerClient, *XmuxClient) {
	t.Helper()
	client, xmux := getHTTPClient(context.Background(), dest, settings)
	native := client.(*DefaultDialerClient)
	key := dialerConf{dest, settings}
	globalDialerAccess.Lock()
	manager := globalDialerMap[key]
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		if tr, ok := native.client.Transport.(interface{ CloseIdleConnections() }); ok {
			tr.CloseIdleConnections()
		}
		globalDialerAccess.Lock()
		if globalDialerMap[key] == manager {
			delete(globalDialerMap, key)
		}
		globalDialerAccess.Unlock()
	})
	return native, xmux
}

type nativeH2Result struct {
	body      string
	proto     int
	localAddr string
	err       error
}

func nativeH2Request(ctx context.Context, client *DefaultDialerClient, url string) nativeH2Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nativeH2Result{err: err}
	}
	var localAddr string
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		localAddr = info.Conn.LocalAddr().String()
	}}))
	resp, err := client.client.Do(req)
	if err != nil {
		return nativeH2Result{err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && err == nil {
		err = fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nativeH2Result{body: string(body), proto: resp.ProtoMajor, localAddr: localAddr, err: err}
}

func nativeH2Start(ctx context.Context, client *DefaultDialerClient, url string) <-chan nativeH2Result {
	result := make(chan nativeH2Result, 1)
	go func() { result <- nativeH2Request(ctx, client, url) }()
	return result
}

func nativeH2Await(t *testing.T, results <-chan nativeH2Result) nativeH2Result {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(nativeH2Budget):
		t.Fatal("native H2 fixture operation did not finish")
		return nativeH2Result{}
	}
}

func nativeH2Success(t *testing.T, result nativeH2Result, body string) {
	t.Helper()
	if result.err != nil || result.proto != 2 || result.body != body {
		t.Fatalf("native H2 response: proto=%d body=%q error=%v", result.proto, result.body, result.err)
	}
}

func nativeH2Wave(ctx context.Context, client *DefaultDialerClient, url string, count int) <-chan nativeH2Result {
	results := make(chan nativeH2Result, count)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(count)
	for range count {
		go func() {
			ready.Done()
			<-start
			results <- nativeH2Request(ctx, client, url)
		}()
	}
	ready.Wait()
	close(start)
	return results
}

func TestNativeH2ColdPoolCoalescesAndReuses(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "unsafe"} {
		t.Run(fingerprint, func(t *testing.T) {
			f := newNativeH2Fixture(t, nil, 0)
			settings := f.settings(fingerprint)
			client, xmux := nativeH2Client(t, f.destination(t), settings)
			for range 8 {
				sibling, siblingXmux := getHTTPClient(context.Background(), f.destination(t), settings)
				if sibling != client || siblingXmux != xmux {
					t.Fatal("one-connection XMUX did not select the same native client")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
			defer cancel()
			cold := nativeH2Wave(ctx, client, f.server.URL, 8)
			f.gate.wait(t)
			// Hold an actual cold handshake while the synchronized requests overlap.
			// The delay is fixture input, not an assertion about completion latency.
			select {
			case <-time.After(150 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal("cold native H2 overlap exceeded its budget")
			}
			f.gate.open()
			var peer *nativeH2Conn
			for range 8 {
				result := nativeH2Await(t, cold)
				nativeH2Success(t, result, "native H2 response")
				observed := f.peer(t, result)
				if peer != nil && peer != observed {
					t.Fatal("cold native H2 responses used different established peers")
				}
				peer = observed
			}
			if f.hellos.Load() != 1 || (fingerprint == "chrome" && f.listener.accepts.Load() != 1) {
				t.Fatalf("cold native H2: accepts=%d ClientHellos=%d", f.listener.accepts.Load(), f.hellos.Load())
			}
			// Standard TLS can return a lazy connection before the first AddConn
			// finishes. Any duplicate must be unused and closed by the native pool.
			f.unusedClosed(t, peer)
			accepts, hellos := f.listener.accepts.Load(), f.hellos.Load()
			warm := nativeH2Wave(ctx, client, f.server.URL, 8)
			for range 8 {
				result := nativeH2Await(t, warm)
				nativeH2Success(t, result, "native H2 response")
				if f.peer(t, result) != peer {
					t.Fatal("warm native H2 response used a different established peer")
				}
			}
			if f.listener.accepts.Load() != accepts || f.hellos.Load() != hellos {
				t.Fatal("warm native H2 requests opened another connection")
			}
			f.unusedClosed(t, peer)
		})
	}
}

func TestNativeH2UnsafeLazyHandshakeHandoff(t *testing.T) {
	f := newNativeH2Fixture(t, nil, 0)
	client, _ := nativeH2Client(t, f.destination(t), f.settings("unsafe"))
	ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
	defer cancel()
	first := nativeH2Start(ctx, client, f.server.URL)
	f.gate.wait(t)
	second := nativeH2Start(ctx, client, f.server.URL)
	// The first custom dial has returned its lazy TLS connection, but AddConn
	// is still handshaking. Observe the second accept before releasing it.
	f.listener.waitAccepts(t, 2)
	f.gate.open()
	a, b := nativeH2Await(t, first), nativeH2Await(t, second)
	nativeH2Success(t, a, "native H2 response")
	nativeH2Success(t, b, "native H2 response")
	peer := f.peer(t, a)
	if f.peer(t, b) != peer || f.hellos.Load() != 1 {
		t.Fatalf("lazy native H2 handoff: accepts=%d ClientHellos=%d", f.listener.accepts.Load(), f.hellos.Load())
	}
	f.unusedClosed(t, peer)
}

func TestNativeH2PendingCustomDialCoalesces(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "unsafe"} {
		t.Run(fingerprint, func(t *testing.T) {
			for _, uncoalesced := range []bool{false, true} {
				name := "shared-transport"
				if uncoalesced {
					name = "uncoalesced-control"
				}
				t.Run(name, func(t *testing.T) {
					f := newNativeH2Fixture(t, nil, 0)
					f.gate.open()
					dialGate := newNativeH2Gate()
					t.Cleanup(dialGate.open)
					var entries atomic.Int64
					install := func(client *DefaultDialerClient) {
						tr := client.client.Transport.(*http2.Transport)
						original := tr.DialTLSContext
						tr.DialTLSContext = func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
							entries.Add(1)
							dialGate.entered <- struct{}{}
							select {
							case <-dialGate.release:
								// Preserve the native returned connection's concrete type.
								return original(ctx, network, addr, cfg)
							case <-ctx.Done():
								return nil, ctx.Err()
							}
						}
					}
					var shared *DefaultDialerClient
					if !uncoalesced {
						shared, _ = nativeH2Client(t, f.destination(t), f.settings(fingerprint))
						install(shared)
					}
					clients := make([]*DefaultDialerClient, 8)
					for i := range clients {
						clients[i] = shared
						if uncoalesced {
							// Distinct native transports are a deliberately broken
							// coalescing control through the same observer and peer.
							clients[i], _ = nativeH2Client(t, f.destination(t), f.settings(fingerprint))
							install(clients[i])
						}
					}
					ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
					defer cancel()
					getConn := make(chan struct{}, len(clients))
					ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) { getConn <- struct{}{} }})
					results := make(chan nativeH2Result, len(clients))
					for _, client := range clients {
						go func() { results <- nativeH2Request(ctx, client, f.server.URL) }()
					}
					for range clients {
						select {
						case <-getConn:
						case <-ctx.Done():
							t.Fatal("requests did not all enter the native transport")
						}
					}
					dialGate.wait(t)
					if uncoalesced {
						for range len(clients) - 1 {
							dialGate.wait(t)
						}
					}
					// GetConn is caller entry, not private queue enrollment. This
					// bounded hold supplies overlap; the control checks sensitivity.
					select {
					case <-time.After(150 * time.Millisecond):
					case <-ctx.Done():
						t.Fatal("pending custom dial observation exceeded its budget")
					}
					pending := entries.Load()
					coalesced := pending == 1
					if coalesced == uncoalesced {
						t.Fatalf("custom dial observer: pending=%d uncoalesced-control=%v", pending, uncoalesced)
					}
					select {
					case result := <-results:
						t.Fatalf("request completed while native custom dial was gated: %v", result.err)
					default:
					}
					t.Logf("pending native custom dials=%d; coalescing predicate accepted=%v; uncoalesced-control=%v", pending, coalesced, uncoalesced)
					dialGate.open()
					for range clients {
						nativeH2Success(t, nativeH2Await(t, results), "native H2 response")
					}
				})
			}
		})
	}
}

func TestNativeH2CanceledWaiterPreservesSibling(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "unsafe"} {
		t.Run(fingerprint, func(t *testing.T) {
			f := newNativeH2Fixture(t, nil, 0)
			client, _ := nativeH2Client(t, f.destination(t), f.settings(fingerprint))
			ctx, stop := context.WithTimeout(context.Background(), nativeH2Budget)
			defer stop()
			leaderCtx, cancelLeader := context.WithCancel(ctx)
			defer cancelLeader()
			leader := nativeH2Start(leaderCtx, client, f.server.URL)
			f.gate.wait(t)
			entered := make(chan struct{})
			var enterOnce sync.Once
			siblingCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {
				enterOnce.Do(func() { close(entered) })
			}})
			sibling := nativeH2Start(siblingCtx, client, f.server.URL)
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("sibling did not enter the native transport")
			}
			select {
			case result := <-sibling:
				t.Fatalf("sibling completed before gated handshake: %v", result.err)
			default:
			}
			cancelLeader()
			if result := nativeH2Await(t, leader); !errors.Is(result.err, context.Canceled) {
				t.Fatalf("canceled waiter: %v", result.err)
			}
			f.gate.open()
			nativeH2Success(t, nativeH2Await(t, sibling), "native H2 response")
		})
	}
}

func TestNativeH2FailedHandshakeCanRecover(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "unsafe"} {
		t.Run(fingerprint, func(t *testing.T) {
			f := newNativeH2Fixture(t, nil, 0)
			f.failFirst.Store(true)
			f.gate.open()
			client, _ := nativeH2Client(t, f.destination(t), f.settings(fingerprint))
			ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
			defer cancel()
			if result := nativeH2Request(ctx, client, f.server.URL); result.err == nil {
				t.Fatal("controlled failed handshake returned success")
			}
			// This is a new caller request through the same transport, not a retry
			// which changes the recorded failure or a one-socket failure contract.
			nativeH2Success(t, nativeH2Request(ctx, client, f.server.URL), "native H2 response")
			nativeH2Success(t, nativeH2Request(ctx, client, f.server.URL), "native H2 response")
		})
	}
	t.Run("packet-xmux-replacement", func(t *testing.T) {
		f := newNativeH2Fixture(t, nil, 0)
		f.failFirst.Store(true)
		f.gate.open()
		settings := f.settings("chrome")
		client, xmux := nativeH2Client(t, f.destination(t), settings)
		packet := func(c *DefaultDialerClient) error {
			return c.PostPacket(context.Background(), f.server.URL, "f4", "0", buf.MultiBuffer{buf.FromBytes([]byte("packet"))})
		}
		if err := packet(client); err == nil || !client.IsClosed() {
			t.Fatalf("failed packet did not retire native client: closed=%v error=%v", client.IsClosed(), err)
		}
		replacement, replacementXmux := nativeH2Client(t, f.destination(t), settings)
		if replacement == client || replacementXmux == xmux {
			t.Fatal("XMUX reused the closed packet client")
		}
		if err := packet(replacement); err != nil {
			t.Fatalf("replacement packet failed: %v", err)
		}
	})
}

func TestNativeH2NativeMethodsRetainDetachedContext(t *testing.T) {
	for _, method := range []string{"stream", "packet"} {
		t.Run(method, func(t *testing.T) {
			observed := make(chan string, 1)
			f := newNativeH2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || r.ProtoMajor != 2 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				observed <- string(body)
				_, _ = io.WriteString(w, "native method response")
			}), 0)
			client, _ := nativeH2Client(t, f.destination(t), f.settings("chrome"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan nativeH2Result, 1)
			go func() {
				if method == "packet" {
					err := client.PostPacket(ctx, f.server.URL, "f4", "0", buf.MultiBuffer{buf.FromBytes([]byte("native packet"))})
					result <- nativeH2Result{err: err}
					return
				}
				reader, _, _, err := client.OpenStream(ctx, f.server.URL, "f4", nil, false)
				if err != nil {
					result <- nativeH2Result{err: err}
					return
				}
				defer reader.Close()
				body, err := io.ReadAll(reader)
				result <- nativeH2Result{body: string(body), err: err}
			}()
			f.gate.wait(t)
			cancel()
			f.gate.open()
			got := nativeH2Await(t, result)
			if got.err != nil || (method == "stream" && got.body != "native method response") {
				t.Fatalf("native detached method: body=%q error=%v", got.body, got.err)
			}
			select {
			case body := <-observed:
				if method == "packet" && body != "native packet" {
					t.Fatalf("native packet body: %q", body)
				}
			case <-time.After(nativeH2Budget):
				t.Fatal("native method did not reach H2 peer")
			}
		})
	}
}

func TestNativeH2SeparateTargetsProgressIndependently(t *testing.T) {
	a := newNativeH2Fixture(t, nil, 0)
	b := newNativeH2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "independent target B")
	}), 0)
	b.gate.open()
	settings := a.settings("chrome")
	clientA, _ := nativeH2Client(t, a.destination(t), settings)
	clientB, _ := nativeH2Client(t, b.destination(t), settings)
	if clientA == clientB {
		t.Fatal("different destinations shared a fixed-destination dialer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
	defer cancel()
	blocked := nativeH2Start(ctx, clientA, a.server.URL)
	a.gate.wait(t)
	nativeH2Success(t, nativeH2Request(ctx, clientB, b.server.URL), "independent target B")
	a.gate.open()
	nativeH2Success(t, nativeH2Await(t, blocked), "native H2 response")
}

func TestNativeH2StreamCapacityPermitsAnotherConnection(t *testing.T) {
	hold := newNativeH2Gate()
	t.Cleanup(hold.open)
	f := newNativeH2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			hold.entered <- struct{}{}
			select {
			case <-hold.release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, "capacity response")
	}), 1)
	f.gate.open()
	client, _ := nativeH2Client(t, f.destination(t), f.settings("chrome"))
	ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
	defer cancel()
	first := nativeH2Start(ctx, client, f.server.URL+"/hold")
	hold.wait(t)
	nativeH2Success(t, nativeH2Request(ctx, client, f.server.URL+"/free"), "capacity response")
	if f.listener.accepts.Load() < 2 {
		t.Fatal("native H2 wrongly imposed a lifetime one-socket limit")
	}
	hold.open()
	nativeH2Success(t, nativeH2Await(t, first), "capacity response")
}

func TestNativeH2RealityXHTTPExchange(t *testing.T) {
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "local REALITY cover")
	}))
	cover.EnableHTTP2 = true
	cover.TLS = &gotls.Config{
		MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
		CurvePreferences: []gotls.CurveID{gotls.X25519MLKEM768, gotls.X25519}, SessionTicketsDisabled: true,
	}
	cover.StartTLS()
	t.Cleanup(cover.Close)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp", ProtocolSettings: &Config{Path: "/f4", Mode: "stream-one"},
		SecurityType: "reality", SecuritySettings: &reality.Config{
			Type: "tcp", Dest: cover.Listener.Addr().String(),
			ServerNames: []string{"localhost"}, PrivateKey: key.Bytes(), ShortIds: [][]byte{shortID},
		},
	}
	payload := []byte("native XHTTP REALITY payload")
	serverResult := make(chan error, 1)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	// Native XHTTP reserves port zero for Unix listeners.
	listener, err := ListenXH(context.Background(), cnet.LocalHostIP, cnet.Port(listenPort), serverSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			got := make([]byte, len(payload))
			_, err := io.ReadFull(conn, got)
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("native REALITY inbound payload differs")
			}
			if err == nil {
				_, err = conn.Write(payload)
			}
			serverResult <- err
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	nativeListener := listener.(*Listener)
	t.Cleanup(func() {
		_ = nativeListener.server.Close()
		_ = listener.Close()
	})
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	destination := cnet.TCPDestination(cnet.LocalHostIP, cnet.Port(port))
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp", ProtocolSettings: &Config{Path: "/f4", Mode: "stream-one"},
		SecurityType: "reality", SecuritySettings: &reality.Config{
			Fingerprint: "chrome", ServerName: "localhost",
			PublicKey: key.PublicKey().Bytes(), ShortId: shortID, SpiderX: "/",
		},
	}
	// Capture and retire this fixture's manager only; native shared pool behavior
	// is exercised by Dial below, and fixture teardown is not a worker-join claim.
	_, _ = nativeH2Client(t, destination, clientSettings)
	ctx, cancel := context.WithTimeout(context.Background(), nativeH2Budget)
	defer cancel()
	clientResult := make(chan nativeH2Result, 1)
	go func() {
		conn, err := Dial(ctx, destination, clientSettings)
		if err != nil {
			clientResult <- nativeH2Result{err: err}
			return
		}
		defer conn.Close()
		_, err = conn.Write(payload)
		got := make([]byte, len(payload))
		if err == nil {
			_, err = io.ReadFull(conn, got)
		}
		clientResult <- nativeH2Result{body: string(got), err: err}
	}()
	got := nativeH2Await(t, clientResult)
	if got.err != nil || got.body != string(payload) {
		t.Fatalf("native XHTTP REALITY exchange: body=%q error=%v", got.body, got.err)
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatalf("native REALITY server: %v", err)
		}
	case <-time.After(nativeH2Budget):
		t.Fatal("native REALITY server fixture did not finish")
	}
}
