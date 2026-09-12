package hysteria

import (
	"context"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type closeErrorConn struct {
	stdnet.Conn
	err error
}

func (c *closeErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

type blockingCloseConn struct {
	stdnet.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
		_ = c.Conn.Close()
	})
	return nil
}

func TestClientManagerBindsBeforePublicationAndStopsWithOwner(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	settings := &internet.MemoryStreamConfig{}
	key := dialerConf{MemoryStreamConfig: settings, owner: owner}
	manager, err := managerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.tickDone:
	default:
		t.Fatal("manager Close returned before cleanup ticker joined")
	}
	registry.mu.Lock()
	_, found := registry.managers[key]
	registry.mu.Unlock()
	if found {
		t.Fatal("closed manager remained published")
	}
}

func TestClientManagerDoesNotPublishIntoSealedOwner(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	owner.SignalStop()
	key := dialerConf{MemoryStreamConfig: &internet.MemoryStreamConfig{}, owner: owner}
	if _, err := managerFor(context.Background(), key); err == nil {
		t.Fatal("sealed owner admitted a manager")
	}
	registry.mu.Lock()
	_, found := registry.managers[key]
	registry.mu.Unlock()
	if found {
		t.Fatal("sealed-owner provisional manager was published")
	}
}

func TestClientManagerCloseBeforeStartSettlesTickerReceipt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &clientManager{ctx: ctx, cancel: cancel, clients: make(map[*client]struct{}), tickDone: make(chan struct{}), closeDone: make(chan struct{})}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.tickDone:
	default:
		t.Fatal("Close before start left the ticker receipt open")
	}
}

func TestLegacyManagerOutlivesFirstRequestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	settings := &internet.MemoryStreamConfig{}
	manager, err := managerFor(ctx, dialerConf{MemoryStreamConfig: settings})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-manager.ctx.Done():
		t.Fatal("legacy manager inherited request cancellation")
	case <-time.After(20 * time.Millisecond):
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientManagerExactABAReplacement(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	key := dialerConf{MemoryStreamConfig: settings}
	old, err := managerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	old.SignalStop()
	replacement, err := managerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == old {
		t.Fatal("sealed manager was reused")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	current := registry.managers[key]
	registry.mu.Unlock()
	if current != replacement {
		t.Fatal("old manager removed an exact-key replacement")
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientUseCloseIsIdempotentAndDrains(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	key := dialerConf{MemoryStreamConfig: settings}
	manager, err := managerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	client := &client{manager: manager, uses: make(map[*clientUse]struct{}), closeDone: make(chan struct{})}
	manager.mu.Lock()
	manager.clientWG.Add(1)
	manager.clients[client] = struct{}{}
	manager.current = client
	manager.mu.Unlock()
	local, remote := stdnet.Pipe()
	defer remote.Close()
	wrapped, err := client.acquireUse(local)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wrapped.(*clientUse).UnwrapConnection().(stdnet.Conn); !ok {
		t.Fatal("use wrapper did not expose its underlying connection")
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = wrapped.Close() }()
	}
	wg.Wait()
	client.mu.Lock()
	uses := len(client.uses)
	client.mu.Unlock()
	if uses != 0 {
		t.Fatalf("got %d retained uses after Close, want 0", uses)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.closeDone:
	case <-time.After(time.Second):
		t.Fatal("legacy empty manager did not self-release")
	}
}

func TestClientCloseWaitsForInflightDialBeforeRemoval(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	manager, err := managerFor(context.Background(), dialerConf{MemoryStreamConfig: settings})
	if err != nil {
		t.Fatal(err)
	}
	dialDone := make(chan struct{})
	client := &client{manager: manager, dialing: true, dialDone: dialDone, uses: make(map[*clientUse]struct{}), closeDone: make(chan struct{})}
	manager.mu.Lock()
	manager.clientWG.Add(1)
	manager.current = client
	manager.clients[client] = struct{}{}
	manager.mu.Unlock()
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before dial receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	manager.mu.Lock()
	_, stillRegistered := manager.clients[client]
	manager.mu.Unlock()
	if !stillRegistered {
		t.Fatal("client was removed before dial receipt")
	}
	close(dialDone)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not complete after dial receipt")
	}
}

func TestClientCloseReturnsOwnedUseCloseError(t *testing.T) {
	local, remote := stdnet.Pipe()
	defer remote.Close()
	client := &client{uses: make(map[*clientUse]struct{}), closeDone: make(chan struct{})}
	if _, err := client.acquireUse(&closeErrorConn{Conn: local, err: context.Canceled}); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err == nil {
		t.Fatal("Close discarded an owned use close error")
	}
}

func TestClientSignalStopDoesNotJoinBlockedUse(t *testing.T) {
	local, remote := stdnet.Pipe()
	defer remote.Close()
	blocked := &blockingCloseConn{Conn: local, entered: make(chan struct{}), release: make(chan struct{})}
	client := &client{uses: make(map[*clientUse]struct{}), closeDone: make(chan struct{})}
	if _, err := client.acquireUse(blocked); err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	go func() {
		client.SignalStop()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("SignalStop joined a blocked client use")
	}
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("SignalStop did not fan out the client-use unblock")
	}
	select {
	case <-client.closeDone:
		t.Fatal("client reported Close before the blocked use returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(blocked.release)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRollbackUnblocksBeforeJoiningAndReturnsError(t *testing.T) {
	blocked := make(chan struct{})
	firstStarted := make(chan struct{})
	err := closeConcurrently(
		func() error {
			close(firstStarted)
			<-blocked
			return nil
		},
		func() error {
			<-firstStarted
			close(blocked)
			return context.Canceled
		},
	)
	if err == nil {
		t.Fatal("parallel rollback discarded a cleanup error")
	}
}

func TestLegacyManagerSealsBeforeEmptyClientRemovalReturns(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	key := dialerConf{MemoryStreamConfig: settings}
	manager, err := managerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	client := &client{manager: manager, uses: make(map[*clientUse]struct{}), closeDone: make(chan struct{})}
	manager.mu.Lock()
	manager.clientWG.Add(1)
	manager.clients[client] = struct{}{}
	manager.current = client
	manager.mu.Unlock()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	sealed := manager.sealed
	manager.mu.Unlock()
	if !sealed {
		t.Fatal("empty legacy manager returned from removal before sealing admission")
	}
	if _, err := manager.client(context.Background(), settings, nil); err != errClientManagerClosed {
		t.Fatalf("got client admission error %v, want manager-closed sentinel", err)
	}
	replacement, err := managerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == manager {
		t.Fatal("sealed empty manager was reused")
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyDialSetupHonorsRequestCancellation(t *testing.T) {
	blackhole, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{},
	}
	destination := net.TCPDestination(net.DomainAddress("localhost"), net.Port(blackhole.LocalAddr().(*stdnet.UDPAddr).Port))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if conn, err := Dial(ctx, destination, settings); err == nil {
		_ = conn.Close()
		t.Fatal("blackhole Hysteria setup unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("legacy setup ignored request cancellation for %v", elapsed)
	}
	key := dialerConf{Destination: net.UDPDestination(destination.Address, destination.Port), MemoryStreamConfig: settings}
	deadline := time.Now().Add(time.Second)
	for {
		registry.mu.Lock()
		_, found := registry.managers[key]
		registry.mu.Unlock()
		if !found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed legacy setup retained its provisional manager")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInactiveClientIsReplacedInsteadOfRedialed(t *testing.T) {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{Certificate: []*tls.Certificate{serverCertificate}},
	}
	owner := internet.NewResourceLifecycle(context.Background())
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName:      protocolName,
		ProtocolSettings:  &Config{Auth: "test-auth"},
		SecurityType:      "tls",
		SecuritySettings:  &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}},
		ResourceLifecycle: owner,
	}
	listener, err := Listen(context.Background(), net.LocalHostIP, udp.PickPort(), serverSettings, func(conn stat.Connection) { _ = conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := net.UDPDestination(net.DomainAddress("localhost"), net.Port(listener.Addr().(*net.UDPAddr).Port))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, destination, clientSettings)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer conn.Close()
	key := dialerConf{Destination: destination, MemoryStreamConfig: clientSettings, owner: owner}
	registry.mu.Lock()
	manager := registry.managers[key]
	registry.mu.Unlock()
	if manager == nil {
		_ = listener.Close()
		t.Fatal("client manager was not published")
	}
	manager.mu.Lock()
	old := manager.current
	manager.mu.Unlock()
	if old == nil {
		t.Fatal("client generation was not published")
	}
	selected, err := manager.client(ctx, clientSettings, tls.ConfigFromStreamSettings(clientSettings))
	if err != nil || selected != old {
		t.Fatalf("active generation selection = (%p, %v), want (%p, nil)", selected, err, old)
	}
	old.mu.Lock()
	oldConn := old.conn
	old.mu.Unlock()
	if oldConn == nil {
		t.Fatal("selected generation has no QUIC connection")
	}
	if err := oldConn.CloseWithError(closeErrCodeOK, "test inactive generation"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for old.status() != StatusInactive {
		if time.Now().After(deadline) {
			t.Fatal("connection close did not make the client generation inactive")
		}
		time.Sleep(time.Millisecond)
	}
	if err := selected.ensureDial(ctx); err != errClientGenerationInactive {
		t.Fatalf("inactive generation returned %v, want inactive sentinel", err)
	}
	replacement, err := manager.client(ctx, clientSettings, tls.ConfigFromStreamSettings(clientSettings))
	if err != nil {
		t.Fatal(err)
	}
	if replacement == old {
		t.Fatal("inactive generation was reused for redial")
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestClientManagerRepeatedConcurrentStopAndClose(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	manager, err := managerFor(context.Background(), dialerConf{MemoryStreamConfig: settings})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.SignalStop()
			if err := manager.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestResourceLifecycleClosesRealHysteriaClientUse(t *testing.T) {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{Certificate: []*tls.Certificate{serverCertificate}},
	}
	owner := internet.NewResourceLifecycle(context.Background())
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName:      protocolName,
		ProtocolSettings:  &Config{Auth: "test-auth"},
		SecurityType:      "tls",
		SecuritySettings:  &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}},
		ResourceLifecycle: owner,
	}
	listener, err := Listen(context.Background(), net.LocalHostIP, udp.PickPort(), serverSettings, func(conn stat.Connection) { _ = conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), net.Port(listener.Addr().(*net.UDPAddr).Port)), clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("after-close")); err == nil {
		t.Fatal("resource lifecycle left returned client stream usable")
	}
}

func TestResourceLifecycleJoinsRealHysteriaUDPClient(t *testing.T) {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{Certificate: []*tls.Certificate{serverCertificate}},
	}
	owner := internet.NewResourceLifecycle(context.Background())
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName:      protocolName,
		ProtocolSettings:  &Config{Auth: "test-auth"},
		SecurityType:      "tls",
		SecuritySettings:  &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}},
		ResourceLifecycle: owner,
	}
	listener, err := Listen(context.Background(), net.LocalHostIP, udp.PickPort(), serverSettings, func(conn stat.Connection) { _ = conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	destination := net.UDPDestination(net.DomainAddress("localhost"), net.Port(listener.Addr().(*net.UDPAddr).Port))
	conn, err := Dial(ContextWithDatagram(ctx, true), destination, clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stat.TryUnwrapStatsConn(conn).(*InterConn); !ok {
		t.Fatalf("got %T, want a Hysteria UDP session", stat.TryUnwrapStatsConn(conn))
	}
	key := dialerConf{Destination: destination, MemoryStreamConfig: clientSettings, owner: owner}
	registry.mu.Lock()
	manager := registry.managers[key]
	registry.mu.Unlock()
	if manager == nil {
		t.Fatal("client manager was not published")
	}
	manager.mu.Lock()
	client := manager.current
	manager.mu.Unlock()
	if client == nil {
		t.Fatal("client generation was not published")
	}
	client.mu.Lock()
	udpSM := client.udpSM
	client.mu.Unlock()
	if udpSM == nil {
		t.Fatal("UDP session manager was not published")
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-udpSM.done:
	default:
		t.Fatal("resource lifecycle returned before udpSM.run joined")
	}
	select {
	case <-client.closeDone:
	default:
		t.Fatal("resource lifecycle returned before client generation joined")
	}
	if _, err := conn.Write(make([]byte, 4)); err == nil {
		t.Fatal("resource lifecycle left returned UDP session usable")
	}
}
