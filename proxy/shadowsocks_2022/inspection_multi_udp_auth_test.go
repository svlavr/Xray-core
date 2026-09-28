package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type authPacketConn struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func newAuthPacketConn() *authPacketConn {
	return &authPacketConn{in: make(chan []byte, 16), out: make(chan []byte, 16), done: make(chan struct{})}
}

func (c *authPacketConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case packet := <-c.in:
		return buf.MultiBuffer{buf.FromBytes(packet)}, nil
	case <-c.done:
		return nil, io.EOF
	}
}
func (*authPacketConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *authPacketConn) Write(packet []byte) (int, error) {
	select {
	case c.out <- append([]byte(nil), packet...):
		return len(packet), nil
	case <-c.done:
		return 0, io.ErrClosedPipe
	}
}
func (c *authPacketConn) Close() error { c.once.Do(func() { close(c.done) }); return nil }
func (*authPacketConn) LocalAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 8388}
}

func (*authPacketConn) RemoteAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 40000}
}
func (*authPacketConn) SetDeadline(time.Time) error      { return nil }
func (*authPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*authPacketConn) SetWriteDeadline(time.Time) error { return nil }

type authPacketReader struct {
	done chan struct{}
	once sync.Once
}

func newAuthPacketReader() *authPacketReader { return &authPacketReader{done: make(chan struct{})} }

func (r *authPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) { <-r.done; return nil, io.EOF }

func (r *authPacketReader) Interrupt()   { r.once.Do(func() { close(r.done) }) }
func (r *authPacketReader) Close() error { r.Interrupt(); return nil }

type authPayload struct {
	user, payload string
	destination   net.Destination
}
type authPacketWriter struct {
	received chan authPayload
	user     string
	closed   atomic.Bool
}

func (w *authPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if w.closed.Load() {
		return io.ErrClosedPipe
	}
	for _, b := range mb {
		var destination net.Destination
		if b.UDP != nil {
			destination = *b.UDP
		}
		w.received <- authPayload{user: w.user, payload: string(b.Bytes()), destination: destination}
	}
	return nil
}
func (w *authPacketWriter) Interrupt()   { w.closed.Store(true) }
func (w *authPacketWriter) Close() error { w.Interrupt(); return nil }

type authDispatcher struct {
	received chan authPayload
	calls    atomic.Int32
}

func (d *authDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.calls.Add(1)
	user := session.InboundFromContext(ctx).User.Email
	return &transport.Link{Reader: newAuthPacketReader(), Writer: &authPacketWriter{received: d.received, user: user}}, nil
}

func (*authDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (*authDispatcher) Start() error      { return nil }
func (*authDispatcher) Close() error      { return nil }
func (*authDispatcher) Type() interface{} { return routing.DispatcherType() }

func startAuthMulti(t *testing.T, master []byte, users map[string][]byte) (*MultiUserInbound, *authPacketConn, *authDispatcher, fs.FlowInspection) {
	t.Helper()
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: net.UDPDestination(net.LocalHostIP, 40000)})
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	config := &MultiUserServerConfig{Method: MethodAES128GCM, Key: base64.StdEncoding.EncodeToString(master)}
	for email, key := range users {
		config.Users = append(config.Users, &protocol.User{Email: email, Account: serial.ToTypedMessage(&Account{Key: base64.StdEncoding.EncodeToString(key)})})
	}
	inbound, err := NewMultiServer(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inbound.Close() })
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	inbound.statsManager = manager
	conn := newAuthPacketConn()
	t.Cleanup(func() { conn.Close() })
	dispatcher := &authDispatcher{received: make(chan authPayload, 16)}
	done := make(chan error, 1)
	go func() { done <- inbound.Process(ctx, net.Network_UDP, conn, dispatcher) }()
	t.Cleanup(func() {
		conn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("native UDP process did not exit")
		}
	})
	return inbound, conn, dispatcher, view
}

func fixedAuthCodec(t *testing.T, userKey []byte, sessionID uint64) *UDPCodec {
	t.Helper()
	method, _ := GetCipherMethod(MethodAES128GCM)
	codec, err := NewUDPPacketCodec(method, userKey, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	codec.clientSessionID = sessionID
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], sessionID)
	key := DeriveSessionSubKey(userKey, sid[:], method.KeySaltLength)
	codec.clientBodyCipher, err = method.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func sendAuthPacket(t *testing.T, conn *authPacketConn, codec *UDPCodec, payload string) {
	t.Helper()
	packet, err := codec.EncodeClientPacket(net.UDPDestination(net.LocalHostIP, 8080), []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	conn.in <- append([]byte(nil), packet.Bytes()...)
	packet.Release()
}

func receiveAuthPayload(t *testing.T, dispatcher *authDispatcher) authPayload {
	t.Helper()
	select {
	case packet := <-dispatcher.received:
		return packet
	case <-time.After(3 * time.Second):
		t.Fatal("authenticated packet was not dispatched")
		return authPayload{}
	}
}

func TestInspectionSS2022MultiUDPRemovedUser(t *testing.T) {
	userKey := []byte("fedcba9876543210")
	inbound, conn, dispatcher, view := startAuthMulti(t, []byte("0123456789abcdef"), map[string][]byte{"removed@example.invalid": userKey})
	codec := fixedAuthCodec(t, userKey, 0x1122334455667788)
	sendAuthPacket(t, conn, codec, "before removal")
	if got := receiveAuthPayload(t, dispatcher); got.user != "removed@example.invalid" || got.payload != "before removal" {
		t.Fatalf("first packet: %+v", got)
	}
	if err := inbound.RemoveUser(context.Background(), "removed@example.invalid"); err != nil {
		t.Fatal(err)
	}
	sendAuthPacket(t, conn, codec, "after removal")
	select {
	case got := <-dispatcher.received:
		t.Fatalf("removed user accepted: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("removed user reopened association: %d", dispatcher.calls.Load())
	}
	live, err := view.ReadLive()
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("removed user's live flow remains: %+v %v", live, err)
	}
}

func TestInspectionSS2022MultiUDPCollidingSessionIDs(t *testing.T) {
	firstKey, secondKey := []byte("fedcba9876543210"), []byte("ABCDEF0123456789")
	_, conn, dispatcher, _ := startAuthMulti(t, []byte("0123456789abcdef"), map[string][]byte{"first@example.invalid": firstKey, "second@example.invalid": secondKey})
	const sessionID uint64 = 0x1122334455667788
	first, second := fixedAuthCodec(t, firstKey, sessionID), fixedAuthCodec(t, secondKey, sessionID)
	sendAuthPacket(t, conn, first, "first")
	if got := receiveAuthPayload(t, dispatcher); got.user != "first@example.invalid" || got.payload != "first" {
		t.Fatalf("first: %+v", got)
	}
	sendAuthPacket(t, conn, second, "second")
	if got := receiveAuthPayload(t, dispatcher); got.user != "second@example.invalid" || got.payload != "second" {
		t.Fatalf("second: %+v", got)
	}
	if dispatcher.calls.Load() != 2 {
		t.Fatalf("colliding users shared association: %d", dispatcher.calls.Load())
	}
}

func TestInspectionSS2022RelayToMultiUDPChain(t *testing.T) {
	firstKey, relayKey, userKey := []byte("0123456789abcdef"), []byte("fedcba9876543210"), []byte("ABCDEF0123456789")
	_, multiConn, multiDispatcher, _ := startAuthMulti(t, relayKey, map[string][]byte{"chain@example.invalid": userKey})
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: net.UDPDestination(net.LocalHostIP, 40001)})
	relay, err := NewRelayServer(ctx, &RelayServerConfig{
		Method:       MethodAES128GCM,
		Key:          base64.StdEncoding.EncodeToString(firstKey),
		Destinations: []*RelayDestination{{Key: base64.StdEncoding.EncodeToString(relayKey), Address: net.NewIPOrDomain(net.LocalHostIP), Port: 8389}},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayConn := newAuthPacketConn()
	t.Cleanup(func() { relayConn.Close() })
	relayDispatcher := &authDispatcher{received: make(chan authPayload, 16)}
	done := make(chan error, 1)
	go func() { done <- relay.Process(ctx, net.Network_UDP, relayConn, relayDispatcher) }()
	t.Cleanup(func() {
		relayConn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("native relay did not exit")
		}
	})
	method, _ := GetCipherMethod(MethodAES128GCM)
	codec, err := NewUDPPacketCodec(method, userKey, firstKey, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	sendAuthPacket(t, relayConn, codec, "through relay and multi")
	forwarded := receiveAuthPayload(t, relayDispatcher)
	if relayDispatcher.calls.Load() != 1 {
		t.Fatalf("relay dispatch count: %d", relayDispatcher.calls.Load())
	}
	multiConn.in <- []byte(forwarded.payload)
	decoded := receiveAuthPayload(t, multiDispatcher)
	if decoded.user != "chain@example.invalid" || decoded.payload != "through relay and multi" || decoded.destination != net.UDPDestination(net.LocalHostIP, 8080) {
		t.Fatalf("relay to multi decoded packet: %+v", decoded)
	}
}
