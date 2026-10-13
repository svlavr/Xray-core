package masque

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func newTestClient(newConn func(c *Client) splithttp.XmuxConn) *Client {
	c := &Client{ctx: context.Background()}
	c.xmux = splithttp.NewXmuxManager(&splithttp.XmuxConfig{
		MaxConnections: &splithttp.RangeConfig{From: 3, To: 3},
	}, func() splithttp.XmuxConn {
		return newConn(c)
	})
	return c
}

func TestGetTunnelFallsBack(t *testing.T) {
	refused := errors.New("refused")
	healthy := &tunnel{done: make(chan struct{})}
	dials := 0
	c := newTestClient(func(c *Client) splithttp.XmuxConn {
		if dials++; dials == 1 {
			return healthy
		}
		c.lastErr, c.lastErrAt = refused, time.Now()
		return failedTunnel(refused)
	})
	for i := 0; i < 5; i++ {
		xmuxClient, got, err := c.getTunnel(context.Background(), nil)
		if err != nil || got != healthy {
			t.Fatalf("flow %d: got %p, %v instead of the healthy tunnel", i, got, err)
		}
		xmuxClient.DoneRunning()
	}
	if healthyCount := c.xmux.GetExistingXmuxClient(context.Background()).Running.Load(); healthyCount != 0 {
		t.Fatalf("running flows after completion: %d", healthyCount)
	}
	if dials != 2 {
		t.Errorf("dialed %d times, a failed tunnel should not be retried within %v", dials, retryInterval)
	}
}

func TestGetTunnelFailsWithoutTunnels(t *testing.T) {
	refused := errors.New("refused")
	c := newTestClient(func(c *Client) splithttp.XmuxConn {
		c.lastErr, c.lastErrAt = refused, time.Now()
		return failedTunnel(refused)
	})
	for i := 0; i < 2; i++ {
		if _, _, err := c.getTunnel(context.Background(), nil); err != refused {
			t.Fatalf("flow %d: got %v instead of %v", i, err, refused)
		}
	}
}

func TestClientCloseOwnsRetiredTunnels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{ctx: ctx, cancel: cancel, tunnels: make(map[*tunnel]struct{})}
	c.xmux = splithttp.NewXmuxManager(&splithttp.XmuxConfig{
		CMaxReuseTimes: &splithttp.RangeConfig{From: 1, To: 1},
	}, func() splithttp.XmuxConn {
		t := &tunnel{done: make(chan struct{}), onClose: c.removeTunnel}
		c.tunnels[t] = struct{}{}
		return t
	})
	t.Cleanup(func() { c.Close() })
	first, firstTunnel, err := c.getTunnel(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.DoneRunning()
	second, secondTunnel, err := c.getTunnel(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.DoneRunning()
	if firstTunnel == secondTunnel || firstTunnel.IsClosed() || !first.NotUsed.Load() {
		t.Fatal("retired tunnel was reused or closed while its flow was running")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !firstTunnel.IsClosed() || !secondTunnel.IsClosed() || len(c.tunnels) != 0 {
		t.Fatal("client close missed a retired or selected tunnel")
	}
	if _, _, err := c.getTunnel(context.Background(), nil); err == nil {
		t.Fatal("closed client admitted a flow")
	}
}
