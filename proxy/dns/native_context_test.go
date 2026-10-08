package dns

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type nativeTagVerifier struct{ contexts chan context.Context }

func (v *nativeTagVerifier) IsOwnLink(ctx context.Context) bool {
	v.contexts <- ctx
	inbound := session.InboundFromContext(ctx)
	return inbound != nil && inbound.Tag == "resolver"
}

type nativeContextDialer struct {
	internet.Dialer
	conn stdnet.Conn
}

func (d nativeContextDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func TestInspectionDNSOwnLinkTimeoutOnlyKeepsInboundTag(t *testing.T) {
	incoming, client := stdnet.Pipe()
	upstream, server := stdnet.Pipe()
	defer incoming.Close()
	defer client.Close()
	defer upstream.Close()
	defer server.Close()

	query := new(mdns.Msg)
	query.SetQuestion("example.test.", mdns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	verifier := &nativeTagVerifier{contexts: make(chan context.Context, 1)}
	handler := &Handler{ownLinkVerifier: verifier, timeout: time.Second, rules: []*DNSRule{{action: RuleAction_Drop}}}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.UDPDestination(net.LocalHostIP, 53)}})
	original := &session.Inbound{Tag: "resolver", Source: net.UDPDestination(net.LocalHostIP, 12345), Conn: incoming}
	ctx = session.ContextWithInbound(ctx, original)
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	link := &transport.Link{Reader: buf.NewReader(incoming), Writer: buf.NewWriter(incoming)}
	done := make(chan error, 1)
	writeDone := make(chan struct{})
	go func() { done <- handler.Process(ctx, link, nativeContextDialer{conn: upstream}) }()
	go func() { _, _ = client.Write(wire); close(writeDone) }()
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(wire))
	if _, err := io.ReadFull(server, got); err != nil || string(got) != string(wire) {
		t.Fatalf("own DNS query was not forwarded: bytes=%d err=%v", len(got), err)
	}
	select {
	case seen := <-verifier.contexts:
		inbound := session.InboundFromContext(seen)
		if inbound == nil || inbound == original || inbound.Tag != "resolver" || inbound.Conn != nil || inbound.Source.IsValid() {
			t.Fatalf("detached DNS inbound retained more than tag: %+v", inbound)
		}
	case <-time.After(time.Second):
		t.Fatal("own-link verifier was not called")
	}
	_ = client.Close()
	_ = server.Close()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("DNS query writer did not stop")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS outbound did not stop after its pipes closed")
	}
}
