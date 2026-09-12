package splithttp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type blockedH1WriteConn struct {
	entered   chan struct{}
	closed    chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func (c *blockedH1WriteConn) Read([]byte) (int, error) { <-c.closed; return 0, io.ErrClosedPipe }
func (c *blockedH1WriteConn) Write([]byte) (int, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockedH1WriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*blockedH1WriteConn) LocalAddr() gonet.Addr            { return lifecycleTestAddr("local") }
func (*blockedH1WriteConn) RemoteAddr() gonet.Addr           { return lifecycleTestAddr("remote") }
func (*blockedH1WriteConn) SetDeadline(time.Time) error      { return nil }
func (*blockedH1WriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockedH1WriteConn) SetWriteDeadline(time.Time) error { return nil }

type lifecycleTestAddr string

func (a lifecycleTestAddr) Network() string { return string(a) }
func (a lifecycleTestAddr) String() string  { return string(a) }

type failedH1Conn struct{}

func (*failedH1Conn) Read([]byte) (int, error)         { return 0, io.ErrClosedPipe }
func (*failedH1Conn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*failedH1Conn) Close() error                     { return nil }
func (*failedH1Conn) LocalAddr() gonet.Addr            { return lifecycleTestAddr("local") }
func (*failedH1Conn) RemoteAddr() gonet.Addr           { return lifecycleTestAddr("remote") }
func (*failedH1Conn) SetDeadline(time.Time) error      { return nil }
func (*failedH1Conn) SetReadDeadline(time.Time) error  { return nil }
func (*failedH1Conn) SetWriteDeadline(time.Time) error { return nil }

type delayedHeadersTransport struct {
	conn     gonet.Conn
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

type closeTrackingConn struct {
	gonet.Conn
	closed chan struct{}
	once   sync.Once
}

type blockingLifecycleResource struct {
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *blockingLifecycleResource) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return nil
}

func (c *closeTrackingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (t *delayedHeadersTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: t.conn})
	}
	close(t.entered)
	<-req.Context().Done()
	close(t.canceled)
	<-t.release
	return nil, req.Context().Err()
}

func TestDefaultDialerClientCloseUnblocksAndJoinsH1Write(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	blocked := &blockedH1WriteConn{entered: make(chan struct{}), closed: make(chan struct{})}
	pool := &sync.Pool{}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: http.DefaultTransport},
		httpVersion:     "1.1",
		uploadRawPool:   pool,
		dialUploadConn:  func(context.Context) (gonet.Conn, error) { return blocked, nil },
		ctx:             ctx,
		cancel:          cancel,
		closeDone:       make(chan struct{}),
		rawConns:        make(map[*H1Conn]struct{}),
	}
	postDone := make(chan error, 1)
	go func() {
		postDone <- client.PostPacket(context.Background(), "http://example.test/", "session", "0", buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("H1 write did not block")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client Close did not unblock and join H1 write")
	}
	select {
	case <-postDone:
	case <-time.After(time.Second):
		t.Fatal("H1 PostPacket outlived Close receipt")
	}
}

func TestDefaultDialerClientRequestCancellationClosesBorrowedH1Write(t *testing.T) {
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	blocked := &blockedH1WriteConn{entered: make(chan struct{}), closed: make(chan struct{})}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: http.DefaultTransport},
		httpVersion:     "1.1",
		uploadRawPool:   &sync.Pool{},
		dialUploadConn:  func(context.Context) (gonet.Conn, error) { return blocked, nil },
		ctx:             ownerCtx,
		cancel:          ownerCancel,
		closeDone:       make(chan struct{}),
		rawConns:        make(map[*H1Conn]struct{}),
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	postDone := make(chan error, 1)
	go func() {
		postDone <- client.PostPacket(requestCtx, "http://example.test/", "session", "0", buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("H1 write did not block")
	}
	cancelRequest()
	select {
	case <-postDone:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not close borrowed H1 write")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultDialerClientCloseJoinsOpenStreamWorker(t *testing.T) {
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	fakeConn := &blockedH1WriteConn{entered: make(chan struct{}), closed: make(chan struct{})}
	transport := &delayedHeadersTransport{
		conn:     fakeConn,
		entered:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
		ctx:             ownerCtx,
		cancel:          ownerCancel,
		closeDone:       make(chan struct{}),
		rawConns:        make(map[*H1Conn]struct{}),
	}
	reader, _, _, err := client.OpenStream(context.Background(), "http://example.test/", "session", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	<-transport.entered
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case <-transport.canceled:
	case <-time.After(time.Second):
		t.Fatal("OpenStream worker did not observe generation cancellation")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before HTTP worker receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(transport.release)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join completed HTTP worker")
	}
}

func TestDefaultDialerClientClosePhysicallyClosesIdleH2Carrier(t *testing.T) {
	handlerDone := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte{0})
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
		close(handlerDone)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	carrierClosed := make(chan struct{})
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		ctx:             ownerCtx,
		cancel:          ownerCancel,
		closeDone:       make(chan struct{}),
		rawConns:        make(map[*H1Conn]struct{}),
		resources:       make(map[io.Closer]struct{}),
	}
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // synthetic local lifecycle peer
		DialTLSContext: func(ctx context.Context, network, address string, config *tls.Config) (gonet.Conn, error) {
			connection, err := (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return client.trackH2Carrier(&closeTrackingConn{Conn: connection, closed: carrierClosed})
		},
	}
	client.client = &http.Client{Transport: transport}

	reader, _, _, err := client.OpenStream(context.Background(), server.URL, "session", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(reader, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-carrierClosed:
	default:
		t.Fatal("H2 carrier remained physically open after generation close receipt")
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("H2 server request outlived generation close receipt")
	}
}

func TestCreateHTTPClientPublishesH2CarrierToGenerationOwner(t *testing.T) {
	handlerDone := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte{0})
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
		close(handlerDone)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	certificateHash := sha256.Sum256(server.Certificate().Raw)
	port := xnet.Port(server.Listener.Addr().(*gonet.TCPAddr).Port)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &xtls.Config{
			ServerName:           "localhost",
			NextProtocol:         []string{"h2"},
			PinnedPeerCertSha256: [][]byte{certificateHash[:]},
		},
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("localhost"), port)
	client := createHTTPClient(context.Background(), destination, settings).(*DefaultDialerClient)
	reader, _, _, err := client.OpenStream(context.Background(), fmt.Sprintf("https://localhost:%d/", port), "session", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(reader, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	client.resourceMu.Lock()
	ownedCarriers := len(client.resources)
	client.resourceMu.Unlock()
	if ownedCarriers != 1 {
		t.Fatalf("generation owns %d H2 carriers, want 1", ownedCarriers)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("production H2 request outlived generation close receipt")
	}
}

func TestDefaultDialerClientStopFansOutPhysicalResourceClose(t *testing.T) {
	release := make(chan struct{})
	resources := make([]*blockingLifecycleResource, 3)
	client := &DefaultDialerClient{resources: make(map[io.Closer]struct{})}
	for index := range resources {
		resources[index] = &blockingLifecycleResource{entered: make(chan struct{}), release: release}
		client.resources[resources[index]] = struct{}{}
	}
	stopped := make(chan struct{})
	go func() {
		client.closeResources()
		close(stopped)
	}()
	for _, resource := range resources {
		select {
		case <-resource.entered:
		case <-time.After(time.Second):
			t.Fatal("physical resource Close did not fan out before peer release")
		}
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("physical resource Close fan-out did not join")
	}
}

func TestDefaultDialerClientForgetsFailedH1Connection(t *testing.T) {
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	failed := new(failedH1Conn)
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: http.DefaultTransport},
		httpVersion:     "1.1",
		uploadRawPool:   &sync.Pool{},
		dialUploadConn:  func(context.Context) (gonet.Conn, error) { return failed, nil },
		ctx:             ownerCtx,
		cancel:          ownerCancel,
		closeDone:       make(chan struct{}),
		rawConns:        make(map[*H1Conn]struct{}),
	}
	if err := client.PostPacket(context.Background(), "http://example.test/", "session", "0", buf.MultiBuffer{buf.FromBytes([]byte("payload"))}); err == nil {
		t.Fatal("failed H1 write returned success")
	}
	client.rawMu.Lock()
	retained := len(client.rawConns)
	client.rawMu.Unlock()
	if retained != 0 {
		t.Fatalf("failed H1 inventory retained %d connections", retained)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
