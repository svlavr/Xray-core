package masque

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	clog "github.com/xtls/xray-core/common/log"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type pr7121RefusingDialer struct {
	err   error
	calls int
}

type pr7121DiscardLogger struct{}

func (pr7121DiscardLogger) Handle(clog.Message) {}

func (d *pr7121RefusingDialer) Dial(context.Context, cnet.Destination) (stat.Connection, error) {
	d.calls++
	return nil, d.err
}
func (*pr7121RefusingDialer) DestIpAddress() cnet.IP                                { return nil }
func (*pr7121RefusingDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// Exercise actual admission and establishment failure. Only the existing
// healthy tunnel and the lower dial refusal are fixtures, not a live WARP peer.
func TestPR7121GetTunnelHealthyPoolExpansionFailure(t *testing.T) {
	// The process-global async console logger uses channels created outside
	// synctest; use a synchronous sink so it cannot prevent virtual-time advance.
	clog.RegisterHandler(pr7121DiscardLogger{})
	t.Cleanup(func() { clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter())) })
	for _, connections := range []int32{3, 1} {
		name := "configured3"
		if connections == 1 {
			name = "configured1_control"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				healthy := &tunnel{done: make(chan struct{})}
				c := &Client{ctx: ctx, cancel: cancel,
					server:  protocol.NewServerSpec(cnet.TCPDestination(cnet.LocalHostIP, 443), nil),
					tunnels: map[*tunnel]struct{}{healthy: {}},
				}
				defer c.Close()
				refusal := errors.New("additional tunnel refused")
				dialer := &pr7121RefusingDialer{err: refusal}
				constructions := 0
				c.xmux = splithttp.NewXmuxManager(splithttp.XmuxConfig{
					MaxConnections: &splithttp.RangeConfig{From: connections, To: connections},
				}, func() splithttp.XmuxConn {
					constructions++
					if constructions == 1 {
						return healthy
					}
					return c.newXmuxConn()
				})
				first, selected, err := c.getTunnel(ctx, dialer)
				if err != nil || selected != healthy {
					t.Fatalf("initial admission: %v", err)
				}
				first.DoneRunning()
				for i := 0; i < 5; i++ {
					x, selected, err := c.getTunnel(ctx, dialer)
					if err != nil || x != first || selected != healthy {
						t.Fatalf("attempt %d: did not reuse healthy tunnel: tunnel=%p error=%v", i, selected, err)
					}
					if first.Running.Load() != 1 {
						t.Fatal("reused tunnel was not reserved")
					}
					x.DoneRunning()
					if connections == 3 {
						if dialer.calls != i+1 || constructions != i+2 || c.lastErr != refusal {
							t.Fatalf("attempt %d: expected repeated expansion, dials=%d constructions=%d", i, dialer.calls, constructions)
						}
						// A second immediate request reuses the same wrapper during cooldown.
						x, selected, cached := c.getTunnel(ctx, dialer)
						if cached != nil || x != first || selected != healthy || dialer.calls != i+1 {
							t.Fatalf("cooldown: tunnel=%p err=%v calls=%d", selected, cached, dialer.calls)
						}
						if constructions != i+2 {
							t.Fatal("cooldown constructed another sentinel")
						}
						x.DoneRunning()
					} else {
						if dialer.calls != 0 || constructions != 1 {
							t.Fatal("control attempted expansion")
						}
					}
					if healthy.IsClosed() || first.NotUsed.Load() || first.Running.Load() != 0 {
						t.Fatal("healthy tunnel was closed, retired or still busy")
					}
					time.Sleep(retryInterval + time.Millisecond)
				}
				t.Logf("maxConnections=%d: five admissions; lower dials=%d; healthy tunnel remained open", connections, dialer.calls)
			})
		})
	}
}

func TestPR7121GetTunnelFallbackUnavailable(t *testing.T) {
	clog.RegisterHandler(pr7121DiscardLogger{})
	t.Cleanup(func() { clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter())) })
	for _, control := range []string{"no_existing", "concurrency", "reuse_exhausted", "requests_exhausted", "expired", "closed", "retired"} {
		t.Run(control, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				healthy := &tunnel{done: make(chan struct{})}
				c := &Client{ctx: ctx, cancel: cancel,
					server:  protocol.NewServerSpec(cnet.TCPDestination(cnet.LocalHostIP, 443), nil),
					tunnels: map[*tunnel]struct{}{healthy: {}},
				}
				defer c.Close()
				refusal := errors.New("additional tunnel refused")
				dialer := &pr7121RefusingDialer{err: refusal}
				config := splithttp.XmuxConfig{MaxConnections: &splithttp.RangeConfig{From: 3, To: 3}}
				switch control {
				case "concurrency":
					config.MaxConcurrency = &splithttp.RangeConfig{From: 1, To: 1}
				case "reuse_exhausted":
					config.CMaxReuseTimes = &splithttp.RangeConfig{From: 1, To: 1}
				case "expired":
					config.HMaxReusableSecs = &splithttp.RangeConfig{From: 1, To: 1}
				}
				constructions := 0
				c.xmux = splithttp.NewXmuxManager(config, func() splithttp.XmuxConn {
					constructions++
					if constructions == 1 && control != "no_existing" {
						return healthy
					}
					return c.newXmuxConn()
				})
				if control != "no_existing" {
					first, _, err := c.getTunnel(ctx, dialer)
					if err != nil {
						t.Fatal(err)
					}
					if control == "concurrency" {
						defer first.DoneRunning()
					} else {
						first.DoneRunning()
					}
					switch control {
					case "requests_exhausted":
						first.LeftRequests.Store(0)
					case "expired":
						time.Sleep(2 * time.Second)
					case "closed":
						healthy.close()
					case "retired":
						first.NotUsed.Store(true)
					}
				}
				for i := 0; i < 2; i++ {
					x, selected, err := c.getTunnel(ctx, dialer)
					if err != refusal || x != nil || selected != nil {
						t.Fatalf("attempt %d: inadmissible fallback returned tunnel=%p err=%v", i, selected, err)
					}
					if dialer.calls != 1 {
						t.Fatalf("attempt %d: expected one real refusal followed by cooldown, calls=%d", i, dialer.calls)
					}
				}
				wantConstructions := 2
				if control == "no_existing" {
					wantConstructions = 1
				}
				if constructions != wantConstructions {
					t.Fatalf("cooldown created a sentinel: constructions=%d", constructions)
				}
			})
		})
	}
}

func TestPR7121GetTunnelFallbackReuseAccounting(t *testing.T) {
	clog.RegisterHandler(pr7121DiscardLogger{})
	t.Cleanup(func() { clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		healthy := &tunnel{done: make(chan struct{})}
		c := &Client{ctx: ctx, cancel: cancel,
			server:  protocol.NewServerSpec(cnet.TCPDestination(cnet.LocalHostIP, 443), nil),
			tunnels: map[*tunnel]struct{}{healthy: {}},
		}
		defer c.Close()
		refusal := errors.New("additional tunnel refused")
		dialer := &pr7121RefusingDialer{err: refusal}
		constructions := 0
		c.xmux = splithttp.NewXmuxManager(splithttp.XmuxConfig{
			MaxConnections: &splithttp.RangeConfig{From: 3, To: 3},
			CMaxReuseTimes: &splithttp.RangeConfig{From: 3, To: 3},
		}, func() splithttp.XmuxConn {
			constructions++
			if constructions == 1 {
				return healthy
			}
			return c.newXmuxConn()
		})
		first, _, err := c.getTunnel(ctx, dialer)
		if err != nil {
			t.Fatal(err)
		}
		first.DoneRunning()
		// Creation admits the first use; failed expansion and cooldown each
		// consume exactly one of the two remaining uses of this same wrapper.
		for i := 0; i < 2; i++ {
			x, selected, err := c.getTunnel(ctx, dialer)
			if err != nil || x != first || selected != healthy {
				t.Fatalf("reuse %d: %v", i, err)
			}
			x.DoneRunning()
		}
		x, selected, err := c.getTunnel(ctx, dialer)
		if err != refusal || x != nil || selected != nil || !first.NotUsed.Load() || !healthy.IsClosed() {
			t.Fatalf("exhausted reuse: tunnel=%p err=%v", selected, err)
		}
		if dialer.calls != 1 || constructions != 2 {
			t.Fatal("cooldown expanded the pool")
		}
	})
}
