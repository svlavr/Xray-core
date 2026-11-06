package freedom_test

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type policyLoopbackDialer struct {
	targets  []net.Destination
	up, down appstats.Counter
}

func (d *policyLoopbackDialer) Dial(ctx context.Context, target net.Destination) (stat.Connection, error) {
	d.targets = append(d.targets, target)
	conn, err := (&stdnet.Dialer{}).DialContext(ctx, target.Network.SystemString(), target.NetAddr())
	if err != nil {
		return nil, err
	}
	return &stat.CounterConnection{Connection: conn, WriteCounter: &d.up, ReadCounter: &d.down}, nil
}
func (*policyLoopbackDialer) DestIpAddress() net.IP                                 { return nil }
func (*policyLoopbackDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestFreedomProcessMasqueLoopbackPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, inbound  string
		allow, blocked bool
	}{
		{"masque_default", "masque", false, true},
		{"masque_explicit_allow", "masque", true, false},
		{"ordinary_socks", "socks", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			payload, response := []byte("native-policy-request"), []byte("native-policy-response")
			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				got := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, got); err == nil && !bytes.Equal(got, payload) {
					err = io.ErrUnexpectedEOF
				}
				if err == nil {
					_, err = conn.Write(response)
				}
				peerDone <- err
			}()
			defer func() {
				_ = listener.Close()
				select {
				case err := <-peerDone:
					if !tc.blocked && err != nil {
						t.Errorf("owned peer: %v", err)
					}
				case <-time.After(4 * time.Second):
					t.Error("owned peer did not stop")
				}
			}()
			config := &freedom.Config{}
			if tc.allow {
				config.FinalRules = []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}
			}
			h := new(freedom.Handler)
			if err := h.Init(config, policy.DefaultManager{}); err != nil {
				t.Fatal(err)
			}
			target := net.DestinationFromAddr(listener.Addr())
			ob := &session.Outbound{Target: target}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: tc.inbound})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
			dialer := new(policyLoopbackDialer)
			var received bytes.Buffer
			if err := h.Process(ctx, &transport.Link{Reader: buf.NewReader(bytes.NewReader(payload)), Writer: buf.NewWriter(&received)}, dialer); err != nil {
				t.Fatal(err)
			}
			if ob.Target != target || ob.Name != "freedom" {
				t.Fatalf("outbound metadata: %+v", ob)
			}
			if tc.blocked {
				if len(dialer.targets) != 0 || received.Len() != 0 || dialer.up.Value() != 0 || dialer.down.Value() != 0 {
					t.Fatalf("blocked target reached dialer or counters: %v %q %d/%d", dialer.targets, received.Bytes(), dialer.up.Value(), dialer.down.Value())
				}
				return
			}
			if len(dialer.targets) != 1 || dialer.targets[0] != target {
				t.Fatalf("dial destinations: %v, want %v", dialer.targets, target)
			}
			if !bytes.Equal(received.Bytes(), response) || dialer.up.Value() != int64(len(payload)) || dialer.down.Value() != int64(len(response)) {
				t.Fatalf("native payload/counters: %q %d/%d", received.Bytes(), dialer.up.Value(), dialer.down.Value())
			}
		})
	}
}

func TestFreedomProcessInvalidTargetPreservesError(t *testing.T) {
	h := new(freedom.Handler)
	if err := h.Init(&freedom.Config{}, policy.DefaultManager{}); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	dialer := new(policyLoopbackDialer)
	err := h.Process(ctx, &transport.Link{Reader: buf.NewReader(bytes.NewReader(nil)), Writer: buf.Discard}, dialer)
	if err == nil || !strings.Contains(err.Error(), "target not specified") {
		t.Fatalf("invalid target error: %v", err)
	}
	if len(dialer.targets) != 0 {
		t.Fatalf("invalid target dialed: %v", dialer.targets)
	}
}

// This fixture deliberately ignores Interrupt, as a DispatchLink reader may do.
// Its release belongs to the test; bounded Process return does not claim a join.
type heldPolicyReader struct {
	entered, release, exited chan struct{}
	once                     sync.Once
}

func (r *heldPolicyReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	close(r.exited)
	return nil, io.EOF
}
func (*heldPolicyReader) Interrupt() {}

func TestFreedomProcessBlockDelayBoundsReturnWithoutReaderJoin(t *testing.T) {
	h := new(freedom.Handler)
	if err := h.Init(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Block, Delay: &freedom.Range{}}}}, policy.DefaultManager{}); err != nil {
		t.Fatal(err)
	}
	reader := &heldPolicyReader{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	defer func() {
		close(reader.release)
		select {
		case <-reader.exited:
		case <-time.After(2 * time.Second):
			t.Error("owned reader did not stop after fixture release")
		}
	}()
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 443)}})
	dialer := new(policyLoopbackDialer)
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, &transport.Link{Reader: reader, Writer: buf.Discard}, dialer) }()
	select {
	case <-reader.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("blackhole copy not entered")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("zero-delay Process waited for an uninterruptible reader")
	}
	select {
	case <-reader.exited:
		t.Fatal("fixture reader exited before release")
	default:
	}
	if len(dialer.targets) != 0 {
		t.Fatalf("blocked destination dialed: %v", dialer.targets)
	}
}
