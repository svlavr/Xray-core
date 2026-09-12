package browser_dialer

import (
	"context"
	stderrors "errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const browserLifecycleTestTimeout = 5 * time.Second

func testActiveGeneration(t *testing.T) *serviceGeneration {
	t.Helper()
	serviceRegistry.mu.RLock()
	generation := serviceRegistry.active
	serviceRegistry.mu.RUnlock()
	if generation == nil {
		t.Fatal("Browser dialer generation is not active")
	}
	return generation
}

func startTestGeneration(t *testing.T, addr string) *serviceGeneration {
	t.Helper()
	if err := reloadAddress(""); err != nil {
		t.Fatalf("reset Browser dialer: %v", err)
	}
	if err := reloadAddress(addr); err != nil {
		t.Fatalf("start Browser dialer: %v", err)
	}
	t.Cleanup(func() {
		if err := reloadAddress(""); err != nil {
			t.Errorf("stop Browser dialer: %v", err)
		}
	})
	return testActiveGeneration(t)
}

func connectTestController(t *testing.T, generation *serviceGeneration) *websocket.Conn {
	return connectTestControllerWithHeader(t, generation, http.Header{})
}

func connectTestControllerWithHeader(t *testing.T, generation *serviceGeneration, header http.Header) *websocket.Conn {
	t.Helper()
	endpoint := url.URL{
		Scheme:   "ws",
		Host:     generation.authority,
		Path:     "/websocket",
		RawQuery: "token=" + url.QueryEscape(generation.token),
	}
	conn, response, err := websocket.DefaultDialer.Dial(endpoint.String(), header)
	if err != nil {
		if response != nil {
			t.Fatalf("connect Browser controller: %v (status %s)", err, response.Status)
		}
		t.Fatalf("connect Browser controller: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestBrowserServiceRejectsCrossOriginController(t *testing.T) {
	generation := startTestGeneration(t, "127.0.0.1:0")
	endpoint := url.URL{
		Scheme:   "ws",
		Host:     generation.listener.Addr().String(),
		Path:     "/websocket",
		RawQuery: "token=" + url.QueryEscape(generation.token),
	}
	header := http.Header{"Origin": []string{"https://attacker.invalid"}}
	conn, response, err := websocket.DefaultDialer.Dial(endpoint.String(), header)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("cross-origin Browser controller was accepted")
	}
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin response = %v, want 403", response)
	}

	requestURL := "http://" + generation.listener.Addr().String() + "/"
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatalf("create page request: %v", err)
	}
	request.Header.Set("Origin", "https://attacker.invalid")
	pageResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("read Browser page: %v", err)
	}
	defer pageResponse.Body.Close()
	if got := pageResponse.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("token-bearing page exposes cross-origin access: %q", got)
	}

	sameOrigin := http.Header{"Origin": []string{"http://" + generation.listener.Addr().String()}}
	_ = connectTestControllerWithHeader(t, generation, sameOrigin)
}

func TestBrowserServiceRejectsDNSRebindingHost(t *testing.T) {
	generation := startTestGeneration(t, "127.0.0.1:0")
	_, port, err := net.SplitHostPort(generation.listener.Addr().String())
	if err != nil {
		t.Fatalf("read listener port: %v", err)
	}
	attackerAuthority := net.JoinHostPort("attacker.invalid", port)
	endpoint := url.URL{
		Scheme:   "ws",
		Host:     attackerAuthority,
		Path:     "/websocket",
		RawQuery: "token=" + url.QueryEscape(generation.token),
	}
	networkDialer := &net.Dialer{}
	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return networkDialer.DialContext(ctx, network, generation.listener.Addr().String())
		},
	}
	header := http.Header{"Origin": []string{"http://" + attackerAuthority}}
	conn, response, err := dialer.Dial(endpoint.String(), header)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("DNS-rebound Browser controller was accepted")
	}
	if response == nil || response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("DNS-rebound response = %v, want 421", response)
	}

	requestURL := "http://" + generation.listener.Addr().String() + "/"
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatalf("create DNS-rebound page request: %v", err)
	}
	request.Host = attackerAuthority
	request.Header.Set("Origin", "http://"+attackerAuthority)
	pageResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request DNS-rebound Browser page: %v", err)
	}
	defer pageResponse.Body.Close()
	if pageResponse.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("DNS-rebound page status = %d, want 421", pageResponse.StatusCode)
	}
}

func TestBrowserServiceRejectsNonLoopbackBind(t *testing.T) {
	if _, err := newServiceGeneration("0.0.0.0:0"); err == nil {
		t.Fatal("Browser service accepted a non-loopback wildcard bind")
	}
}

func waitDialResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(browserLifecycleTestTimeout):
		t.Fatal("Browser dial did not finish")
		return nil
	}
}

func TestDialGetCancellationWhileWaitingForController(t *testing.T) {
	startTestGeneration(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := DialGetContext(ctx, "https://example.invalid/", nil, nil)
		result <- err
	}()
	cancel()
	if err := waitDialResult(t, result); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("DialGet error = %v, want context cancellation", err)
	}
}

func TestBorrowedDialCancellationClosesExactSocket(t *testing.T) {
	generation := startTestGeneration(t, "127.0.0.1:0")
	controller := connectTestController(t, generation)
	_ = controller.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := DialGetContext(ctx, "https://example.invalid/", nil, nil)
		result <- err
	}()
	if messageType, _, err := controller.ReadMessage(); err != nil {
		t.Fatalf("read Browser task: %v", err)
	} else if messageType != websocket.TextMessage {
		t.Fatalf("Browser task type = %d, want text", messageType)
	}

	cancel()
	if err := waitDialResult(t, result); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("DialGet error = %v, want context cancellation", err)
	}
	generation.mu.Lock()
	borrowed := len(generation.borrowed)
	generation.mu.Unlock()
	if borrowed != 0 {
		t.Fatalf("borrowed connection count = %d, want 0", borrowed)
	}
	if _, _, err := controller.ReadMessage(); err == nil {
		t.Fatal("controller socket remained open after request cancellation")
	}
}

func TestPostAckCancellationClosesBeforeGenerationReceipt(t *testing.T) {
	generation := startTestGeneration(t, "127.0.0.1:0")
	controller := connectTestController(t, generation)
	_ = controller.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))

	ctx, cancel := context.WithCancel(context.Background())
	type borrowedResult struct {
		conn        *websocket.Conn
		generation  *serviceGeneration
		stopRequest func() bool
		releaseTask func()
		err         error
	}
	result := make(chan borrowedResult, 1)
	go func() {
		conn, exactGeneration, stopRequest, releaseTask, err := borrowForTask(ctx, dialRequest{
			Method:         "GET",
			URL:            "https://example.invalid/",
			StreamResponse: true,
		})
		result <- borrowedResult{
			conn:        conn,
			generation:  exactGeneration,
			stopRequest: stopRequest,
			releaseTask: releaseTask,
			err:         err,
		}
	}()
	if _, _, err := controller.ReadMessage(); err != nil {
		t.Fatalf("read Browser task: %v", err)
	}
	if err := controller.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
		t.Fatalf("acknowledge Browser task: %v", err)
	}

	var borrowed borrowedResult
	select {
	case borrowed = <-result:
		if borrowed.err != nil {
			t.Fatalf("borrow Browser task: %v", borrowed.err)
		}
	case <-time.After(browserLifecycleTestTimeout):
		t.Fatal("Browser task did not reach post-ACK ownership")
	}
	if borrowed.generation != generation {
		t.Fatal("Browser task lost its exact service generation")
	}
	if !generation.transferBorrowed(borrowed.conn) {
		t.Fatal("failed to enter post-ACK transfer state")
	}
	cancel()
	if borrowed.stopRequest() {
		t.Fatal("request cancellation callback did not run")
	}
	_ = borrowed.conn.Close()

	closeResult := make(chan error, 1)
	go func() { closeResult <- generation.closeAndWait() }()
	select {
	case err := <-closeResult:
		t.Fatalf("generation joined before task receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, _, err := controller.ReadMessage(); err == nil {
		t.Fatal("post-ACK canceled socket remained open before task receipt")
	}
	borrowed.releaseTask()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("close Browser generation: %v", err)
		}
	case <-time.After(browserLifecycleTestTimeout):
		t.Fatal("generation did not join after task receipt")
	}
}

func TestReloadCancelsAndJoinsBorrowedOldGeneration(t *testing.T) {
	old := startTestGeneration(t, "127.0.0.1:0")
	controller := connectTestController(t, old)
	_ = controller.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))

	result := make(chan error, 1)
	go func() {
		_, err := DialGetContext(context.Background(), "https://example.invalid/", nil, nil)
		result <- err
	}()
	if _, _, err := controller.ReadMessage(); err != nil {
		t.Fatalf("read Browser task: %v", err)
	}

	if err := reloadAddress("localhost:0"); err != nil {
		t.Fatalf("reload Browser dialer: %v", err)
	}
	if err := waitDialResult(t, result); err == nil {
		t.Fatal("borrowed old-generation dial succeeded after reload")
	}
	select {
	case <-old.done:
	default:
		t.Fatal("reload returned before old generation joined")
	}
	serviceRegistry.mu.RLock()
	_, stillRetiring := serviceRegistry.retiring[old]
	replacement := serviceRegistry.active
	serviceRegistry.mu.RUnlock()
	if stillRetiring {
		t.Fatal("joined old generation remained in retiring inventory")
	}
	if replacement == nil || replacement == old {
		t.Fatal("reload did not publish an exact replacement generation")
	}
}

func TestReturnedConnectionTransfersAcrossReload(t *testing.T) {
	old := startTestGeneration(t, "127.0.0.1:0")
	controller := connectTestController(t, old)
	_ = controller.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))

	type dialResult struct {
		conn *websocket.Conn
		err  error
	}
	result := make(chan dialResult, 1)
	go func() {
		conn, err := DialGetContext(context.Background(), "https://example.invalid/", nil, nil)
		result <- dialResult{conn: conn, err: err}
	}()
	if _, _, err := controller.ReadMessage(); err != nil {
		t.Fatalf("read Browser task: %v", err)
	}
	if err := controller.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
		t.Fatalf("acknowledge Browser task: %v", err)
	}

	var returned *websocket.Conn
	select {
	case outcome := <-result:
		if outcome.err != nil {
			t.Fatalf("DialGet: %v", outcome.err)
		}
		returned = outcome.conn
	case <-time.After(browserLifecycleTestTimeout):
		t.Fatal("DialGet did not return transferred connection")
	}
	defer returned.Close()

	if err := reloadAddress("localhost:0"); err != nil {
		t.Fatalf("reload Browser dialer: %v", err)
	}
	payload := []byte("caller-owned")
	if err := controller.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("write after reload: %v", err)
	}
	_ = returned.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))
	messageType, received, err := returned.ReadMessage()
	if err != nil {
		t.Fatalf("read caller-owned connection after reload: %v", err)
	}
	if messageType != websocket.BinaryMessage || string(received) != string(payload) {
		t.Fatalf("message after reload = (%d, %q), want binary %q", messageType, received, payload)
	}
}

func TestStalePublisherCannotEnterReplacementGeneration(t *testing.T) {
	old := startTestGeneration(t, "127.0.0.1:0")
	if err := reloadAddress("localhost:0"); err != nil {
		t.Fatalf("reload Browser dialer: %v", err)
	}
	replacement := testActiveGeneration(t)
	controller := connectTestController(t, replacement)

	var exactConn *websocket.Conn
	select {
	case exactConn = <-replacement.conns:
	case <-time.After(browserLifecycleTestTimeout):
		t.Fatal("replacement publisher did not enqueue controller")
	}
	if old.enqueue(exactConn) {
		t.Fatal("sealed old generation accepted a stale publication")
	}
	_ = exactConn.Close()
	if len(replacement.conns) != 0 {
		t.Fatal("stale old publisher contaminated replacement queue")
	}
	_ = controller.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))
	if _, _, err := controller.ReadMessage(); err == nil {
		t.Fatal("rejected stale publisher socket remained open")
	}
}

func TestFullGenerationQueueRejectsAndClosesExcessPublisher(t *testing.T) {
	generation := startTestGeneration(t, "127.0.0.1:0")
	generation.mu.Lock()
	generation.conns = make(chan *websocket.Conn, 1)
	generation.mu.Unlock()
	_ = connectTestController(t, generation)
	deadline := time.Now().Add(browserLifecycleTestTimeout)
	for len(generation.conns) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("first controller was not queued")
		}
		time.Sleep(time.Millisecond)
	}

	second := connectTestController(t, generation)
	_ = second.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))
	if _, _, err := second.ReadMessage(); err == nil {
		t.Fatal("excess controller remained open behind a full generation queue")
	}
	if len(generation.conns) != 1 {
		t.Fatal("full-queue rejection changed the exact queued owner")
	}
}

func TestFailedReplacementLeavesActiveGenerationUnchanged(t *testing.T) {
	active := startTestGeneration(t, "127.0.0.1:0")
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve replacement address: %v", err)
	}
	defer occupied.Close()

	if err := reloadAddress(occupied.Addr().String()); err == nil {
		t.Fatal("replacement unexpectedly bound an occupied address")
	}
	if current := testActiveGeneration(t); current != active {
		t.Fatal("failed replacement mutated the active generation")
	}
	if !HasBrowserDialer() || !active.available() {
		t.Fatal("failed replacement sealed the active generation")
	}
}

func TestDialPacketOwnsConnectionThroughSecondAck(t *testing.T) {
	generation := startTestGeneration(t, "127.0.0.1:0")
	controller := connectTestController(t, generation)
	_ = controller.SetReadDeadline(time.Now().Add(browserLifecycleTestTimeout))
	payload := []byte("packet")

	result := make(chan error, 1)
	go func() {
		result <- DialPacketContext(context.Background(), http.MethodPost, "https://example.invalid/", nil, nil, payload)
	}()
	if messageType, _, err := controller.ReadMessage(); err != nil {
		t.Fatalf("read Browser packet task: %v", err)
	} else if messageType != websocket.TextMessage {
		t.Fatalf("Browser packet task type = %d, want text", messageType)
	}
	if err := controller.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
		t.Fatalf("acknowledge Browser packet task: %v", err)
	}
	messageType, received, err := controller.ReadMessage()
	if err != nil {
		t.Fatalf("read Browser packet body: %v", err)
	}
	if messageType != websocket.BinaryMessage || string(received) != string(payload) {
		t.Fatalf("packet body = (%d, %q), want binary %q", messageType, received, payload)
	}
	if err := controller.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
		t.Fatalf("acknowledge Browser packet body: %v", err)
	}
	if err := waitDialResult(t, result); err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	if _, _, err := controller.ReadMessage(); err == nil {
		t.Fatal("DialPacket did not close its borrowed socket")
	}
}

func TestRepeatedReloadUsesExactGenerationIdentity(t *testing.T) {
	firstA := startTestGeneration(t, "127.0.0.1:0")
	if err := reloadAddress("localhost:0"); err != nil {
		t.Fatalf("reload A to B: %v", err)
	}
	betweenB := testActiveGeneration(t)
	if err := reloadAddress("127.0.0.1:0"); err != nil {
		t.Fatalf("reload B to A: %v", err)
	}
	secondA := testActiveGeneration(t)
	if firstA == betweenB || firstA == secondA || betweenB == secondA {
		t.Fatal("A-B-A reload reused a service generation")
	}
	select {
	case <-firstA.done:
	default:
		t.Fatal("first A generation did not retire")
	}
	select {
	case <-betweenB.done:
	default:
		t.Fatal("B generation did not retire")
	}
	if !HasBrowserDialer() || !secondA.available() {
		t.Fatal("stale retirement affected the second A generation")
	}
	serviceRegistry.mu.RLock()
	retiring := len(serviceRegistry.retiring)
	serviceRegistry.mu.RUnlock()
	if retiring != 0 {
		t.Fatalf("retiring generation count = %d, want 0", retiring)
	}
}
