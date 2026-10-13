package core_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	wiredns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
)

func borrowedDNSQuestion(name string, id uint16) *wiredns.Msg {
	q := new(wiredns.Msg)
	q.SetQuestion(name, wiredns.TypeTXT) // not the A/AAAA-only native hijack projection
	q.Id = id
	q.CheckingDisabled = true
	q.SetEdns0(1232, true)
	q.Extra = append(q.Extra, &wiredns.TXT{Hdr: wiredns.RR_Header{Name: name, Rrtype: wiredns.TypeTXT, Class: wiredns.ClassINET}, Txt: []string{"query-extra"}})
	return q
}

func borrowedDNSPack(t *testing.T, q *wiredns.Msg) []byte {
	t.Helper()
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func borrowedDNSAssertAnswer(t *testing.T, q *wiredns.Msg, wire []byte) {
	t.Helper()
	r := new(wiredns.Msg)
	if err := r.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Question, q.Question) || r.Id != q.Id || !bytes.Equal(wire, borrowedDNSPack(t, borrowedDNSAnswer(q))) {
		t.Fatalf("question/ID/answer/authority/additional sections changed: %v", r)
	}
}

func borrowedDNSRouteContext(ctx context.Context, tag string) context.Context {
	return session.SetForcedOutboundTagToContext(borrowedDNSBackendContext(ctx), tag)
}

func borrowedDNSPacket(t *testing.T, f *borrowedDNSFixture) net.PacketConn {
	t.Helper()
	c, err := core.DialUDP(borrowedDNSRouteContext(context.Background(), "borrowed-dns"), f.instance)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func borrowedDNSReadPacket(t *testing.T, c net.PacketConn) ([]byte, net.Addr, error) {
	t.Helper()
	type result struct {
		wire   []byte
		source net.Addr
		err    error
	}
	results := make(chan result, 1)
	go func() {
		wire := make([]byte, buf.Size)
		n, source, err := c.ReadFrom(wire)
		results <- result{wire[:n], source, err}
	}()
	select {
	case r := <-results:
		return r.wire, r.source, r.err
	case <-time.After(5 * time.Second):
		c.Close()
		t.Fatal("packet read timed out")
		return nil, nil, io.ErrNoProgress
	}
}

func borrowedDNSReadFrame(t *testing.T, c net.Conn) []byte {
	t.Helper()
	type result struct {
		wire []byte
		err  error
	}
	results := make(chan result, 1)
	go func() {
		var header [2]byte
		_, err := io.ReadFull(c, header[:])
		if err != nil {
			results <- result{err: err}
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(header[:])))
		_, err = io.ReadFull(c, wire)
		results <- result{wire, err}
	}()
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.wire
	case <-time.After(5 * time.Second):
		c.Close()
		t.Fatal("frame read timed out")
		return nil
	}
}

func TestBorrowedDNSConstructionAndFullMessageRoutes(t *testing.T) {
	f := newBorrowedDNSFixture(t, nil)
	if f.instance.GetFeature(featuredns.ClientType()) != f.client {
		t.Fatal("construction-bound client not selected")
	}
	h := f.instance.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("borrowed-dns")
	if h.(proxy.GetOutbound).GetOutbound() != f.gateway {
		t.Fatal("configured proxy was not selected")
	}

	observation := &session.LogicalObservation{}
	observation.ReturnedLink.Store(true)
	inbound := &session.Inbound{Tag: "user", User: &protocol.MemoryUser{Email: "user@invalid"}}
	out := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("lookup.invalid"), 443), Tag: "user-route"}
	content := &session.Content{Protocol: "user-protocol", Attributes: map[string]string{"caller": "unchanged"}}
	caller := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	caller = session.ContextWithLogicalObservation(caller, observation)
	caller = session.ContextWithInbound(caller, inbound)
	caller = session.ContextWithOutbounds(caller, []*session.Outbound{out})
	caller = session.ContextWithContent(caller, content)
	// Real router feature consumes the client bound by App construction.
	r := f.instance.GetFeature(routing.RouterType()).(routing.Router)
	for i := 0; i < 2; i++ {
		route, err := r.PickRoute(routingsession.AsRoutingContext(caller))
		if err != nil || route.GetOutboundTag() != "borrowed-dns" {
			t.Fatalf("router DNS consumer: %v / %v", route, err)
		}
	}
	// Native system-dialer lookup uses the same client, without preceding app/dns hosts/cache.
	ips, err := internet.LookupForIPContext(caller, "lookup.invalid", internet.DomainStrategy_USE_IP4, nil)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{203, 0, 113, 9}) {
		t.Fatalf("system DNS binding: %v / %v", ips, err)
	}

	udp := borrowedDNSPacket(t, f)
	endpoint := net.UDPDestination(f.gateway.endpoint, 53)
	qUDP := borrowedDNSQuestion("udp.invalid.", 0x1234)
	wire := borrowedDNSPack(t, qUDP)
	// Compare the decoded message with the actual sent wire: Unpack fills RR
	// lengths that are unset in the original in-memory query.
	decodedUDP := new(wiredns.Msg)
	if err := decodedUDP.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if n, err := udp.WriteTo(wire, endpoint.RawNetAddr()); err != nil || n != len(wire) {
		t.Fatalf("UDP write: %d / %v", n, err)
	}
	response, source, err := borrowedDNSReadPacket(t, udp)
	if err != nil || net.DestinationFromAddr(source) != endpoint {
		t.Fatalf("UDP endpoint: %v / %v", source, err)
	}
	borrowedDNSAssertAnswer(t, qUDP, response)

	tcpEndpoint := net.TCPDestination(f.gateway.endpoint, 53)
	tcp, err := core.Dial(borrowedDNSRouteContext(caller, "borrowed-dns"), f.instance, tcpEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	for i := 0; i < 2; i++ {
		q := borrowedDNSQuestion(fmt.Sprintf("tcp%d.invalid.", i), uint16(0x5678+i))
		wire := borrowedDNSPack(t, q)
		frame := make([]byte, len(wire)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(wire)))
		copy(frame[2:], wire)
		// Split inside the length header: Process must reconstruct stream framing.
		if _, err := tcp.Write(frame[:1]); err != nil {
			t.Fatal(err)
		}
		if _, err := tcp.Write(frame[1:]); err != nil {
			t.Fatal(err)
		}
		borrowedDNSAssertAnswer(t, q, borrowedDNSReadFrame(t, tcp))
	}
	records, closed := f.service.snapshot()
	if closed || len(records) != 6 {
		t.Fatalf("one callback paths: %d calls, closed=%v", len(records), closed)
	}
	if records[0].question.Question[0].Name != "lookup.invalid." || records[0].question.Question[0].Qtype != wiredns.TypeA {
		t.Fatal("lookup projection bypassed callback")
	}
	// CopyTo normalizes absent RR sections into empty backing slices. Compare
	// equivalent copied representations and require identical wire bytes too.
	if records[3].endpoint != endpoint || !reflect.DeepEqual(records[3].question, decodedUDP.Copy()) || !bytes.Equal(borrowedDNSPack(t, records[3].question), wire) {
		t.Fatal("raw UDP question/sections/endpoint changed before callback")
	}
	for _, record := range records[4:] {
		if record.endpoint != tcpEndpoint {
			t.Fatal("TCP endpoint association lost")
		}
	}
	for i := range records {
		for j := 0; j < i; j++ {
			if records[i].content == records[j].content {
				t.Fatal("backend content reused across calls")
			}
		}
	}
	if session.TrafficOriginFromContext(caller) != session.TrafficOriginUser || session.LogicalObservationFromContext(caller) != observation || !observation.ReturnedLink.Load() ||
		session.InboundFromContext(caller) != inbound || session.OutboundsFromContext(caller)[0] != out || out.Tag != "user-route" || out.Target.Address.Domain() != "lookup.invalid" ||
		session.ContentFromContext(caller) != content || content.Protocol != "user-protocol" || len(content.Attributes) != 1 || content.Attributes["caller"] != "unchanged" {
		t.Fatal("borrowed DNS mutated caller metadata/USER observation")
	}
}

func TestBorrowedDNSCancellationAndLocalCloseJoin(t *testing.T) {
	one := newBorrowedDNSBlock(t)
	two := newBorrowedDNSBlock(t)
	f := newBorrowedDNSFixture(t, map[string]*borrowedDNSBlock{"one.invalid.": one, "two.invalid.": two})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		_, _, err := f.client.LookupIPContext(ctx, "one.invalid", featuredns.IPOption{IPv4Enable: true})
		result <- err
	}()
	borrowedDNSWait(t, one.entered)
	cancel()
	borrowedDNSWait(t, one.canceled)
	// A canceled request leaves another wire request and the borrowed service alive.
	c := borrowedDNSPacket(t, f)
	endpoint := net.UDPDestination(f.gateway.endpoint, 53)
	q := borrowedDNSQuestion("sibling.invalid.", 17)
	if _, err := c.WriteTo(borrowedDNSPack(t, q), endpoint.RawNetAddr()); err != nil {
		t.Fatal(err)
	}
	wire, source, err := borrowedDNSReadPacket(t, c)
	if err != nil || net.DestinationFromAddr(source) != endpoint {
		t.Fatalf("sibling: %v / %v", source, err)
	}
	borrowedDNSAssertAnswer(t, q, wire)
	one.unblock()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("request cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not join")
	}

	// Close must also cancel a callback reached through native Process, not only lookups.
	blocked := borrowedDNSPacket(t, f)
	if _, err := blocked.WriteTo(borrowedDNSPack(t, borrowedDNSQuestion("two.invalid.", 18)), endpoint.RawNetAddr()); err != nil {
		t.Fatal(err)
	}
	borrowedDNSWait(t, two.entered)
	closed := make(chan struct{})
	go func() { f.client.Close(); close(closed) }()
	borrowedDNSWait(t, two.canceled)
	select {
	case <-closed:
		t.Fatal("Close returned before the local callback retired")
	case <-time.After(50 * time.Millisecond):
	}
	if _, _, err := f.client.LookupIP("sealed.invalid", featuredns.IPOption{IPv4Enable: true}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Close did not seal admissions: %v", err)
	}
	if _, serviceClosed := f.service.snapshot(); serviceClosed {
		t.Fatal("wrapper closed borrowed service")
	}
	two.unblock()
	borrowedDNSWait(t, closed)
	f.client.mu.Lock()
	active := len(f.client.active)
	f.client.mu.Unlock()
	if active != 0 {
		t.Fatalf("local admissions remain after Close: %d", active)
	}
	// Core feature close cannot own the borrowed service either.
	if err := f.instance.Close(); err != nil {
		t.Fatal(err)
	}
	if _, serviceClosed := f.service.snapshot(); serviceClosed {
		t.Fatal("core closed borrowed service")
	}
	if _, err := f.service.exchange(borrowedDNSBackendContext(context.Background()), borrowedDNSQuestion("composition.invalid.", 19), endpoint); err != nil {
		t.Fatalf("borrowed service did not survive: %v", err)
	}
	f.service.Close() // only explicit composition closes the borrowed service
	if _, serviceClosed := f.service.snapshot(); !serviceClosed {
		t.Fatal("composition close missing")
	}
}

func borrowedDNSValidatePacket(q *wiredns.Msg, expected net.Destination, wire []byte, source net.Addr) error {
	if source == nil || net.DestinationFromAddr(source) != expected {
		return errors.New("response endpoint mismatch")
	}
	r := new(wiredns.Msg)
	if err := r.Unpack(wire); err != nil {
		return err
	}
	if r.Id != q.Id || !reflect.DeepEqual(r.Question, q.Question) {
		return errors.New("response question/ID mismatch")
	}
	return nil
}

func TestBorrowedDNSPacketLimitsAndMissingRoute(t *testing.T) {
	f := newBorrowedDNSFixture(t, nil)
	endpoint := net.UDPDestination(f.gateway.endpoint, 53)
	for _, name := range []string{"wrong-source.invalid.", "wrong-id.invalid.", "no-source.invalid."} {
		c := borrowedDNSPacket(t, f)
		q := borrowedDNSQuestion(name, 31)
		if _, err := c.WriteTo(borrowedDNSPack(t, q), endpoint.RawNetAddr()); err != nil {
			t.Fatal(err)
		}
		wire, source, err := borrowedDNSReadPacket(t, c)
		if err != nil {
			t.Fatal(err)
		}
		associationErr := borrowedDNSValidatePacket(q, endpoint, wire, source)
		if name == "no-source.invalid." {
			if associationErr != nil {
				t.Fatal(associationErr)
			}
			// The gateway deliberately omitted Buffer.UDP. ReadFrom substitutes the
			// requested endpoint: source metadata is UNKNOWN, not authenticated proof.
			t.Log("metadata absent: ReadFrom reports requested endpoint; actual packet source remains unknown")
		} else if associationErr == nil {
			t.Fatalf("accepted mismatched packet: %s", name)
		}
		c.Close()
	}

	// Native DialUDP silently copies at most 8192 bytes; no-op deadlines cannot
	// qualify larger DNS datagrams. Use a valid oversized message and record the
	// actual ingress size instead of claiming universal full-message acceptance.
	large := borrowedDNSQuestion("large.invalid.", 32)
	for i := 0; i < 40; i++ {
		large.Extra = append(large.Extra, &wiredns.TXT{Hdr: wiredns.RR_Header{Name: "large.invalid.", Rrtype: wiredns.TypeTXT, Class: wiredns.ClassINET}, Txt: []string{strings.Repeat("x", 250)}})
	}
	largeWire := borrowedDNSPack(t, large)
	if len(largeWire) <= buf.Size {
		t.Fatal("oversized fixture was not oversized")
	}
	c := borrowedDNSPacket(t, f)
	// The initial three reads belong to the preceding packet cases.
	for i := 0; i < 3; i++ {
		<-f.gateway.reads
	}
	if err := c.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := c.WriteTo(largeWire, endpoint.RawNetAddr())
	if err != nil || n != buf.Size {
		t.Fatalf("native size limit: %d / %v", n, err)
	}
	select {
	case got := <-f.gateway.reads:
		if got != buf.Size {
			t.Fatalf("actual ingress size: %d", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("size witness did not reach Process")
	}
	if _, _, err := borrowedDNSReadPacket(t, c); err == nil {
		t.Fatal("truncated oversized DNS unexpectedly served")
	}

	before, _ := f.service.snapshot()
	missing, err := core.Dial(borrowedDNSRouteContext(context.Background(), "absent-route"), f.instance, net.TCPDestination(f.gateway.endpoint, 53))
	if err != nil {
		t.Fatal(err)
	} // native Dispatch reports route failure asynchronously
	t.Cleanup(func() { missing.Close() })
	missingRead := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(missing, make([]byte, 1))
		missingRead <- err
	}()
	select {
	case err := <-missingRead:
		if err == nil {
			t.Fatal("missing forced route did not return an I/O error")
		}
	case <-time.After(5 * time.Second):
		_ = missing.Close()
		select {
		case <-missingRead:
		case <-time.After(time.Second):
			t.Fatal("missing-route reader did not stop after Close")
		}
		t.Fatal("missing forced route did not return a bounded I/O error")
	}
	after, _ := f.service.snapshot()
	if len(after) != len(before) {
		t.Fatal("missing forced route fell back to default gateway")
	}
	// Invalid advertised address cannot be served by the custom Process.
	wrong := borrowedDNSPacket(t, f)
	if _, err := wrong.WriteTo(borrowedDNSPack(t, borrowedDNSQuestion("wrong-address.invalid.", 33)), net.UDPDestination(net.IPAddress(net.IP{192, 0, 2, 54}), 53).RawNetAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := borrowedDNSReadPacket(t, wrong); err == nil {
		t.Fatal("wrong advertised endpoint served")
	}
	after, _ = f.service.snapshot()
	if len(after) != len(before) {
		t.Fatal("wrong endpoint reached callback")
	}
}
