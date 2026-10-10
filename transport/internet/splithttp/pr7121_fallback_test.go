package splithttp

import (
	"context"
	"testing"
	"time"
)

type pr7121XmuxConn struct {
	closed bool
}

func (c *pr7121XmuxConn) IsClosed() bool { return c.closed }
func (c *pr7121XmuxConn) Close() error {
	c.closed = true
	return nil
}

func TestPR7121ExistingXmuxClientLimits(t *testing.T) {
	for _, control := range []string{"empty", "closed", "retired", "reuse_exhausted", "requests_exhausted", "expired", "concurrency"} {
		t.Run(control, func(t *testing.T) {
			created := 0
			m := NewXmuxManager(XmuxConfig{}, func() XmuxConn {
				created++
				return &pr7121XmuxConn{}
			})
			var first *XmuxClient
			if control != "empty" {
				first = m.GetXmuxClient(context.Background())
				switch control {
				case "closed":
					first.XmuxConn.(*pr7121XmuxConn).closed = true
				case "retired":
					first.NotUsed.Store(true)
				case "reuse_exhausted":
					first.leftUsage = 0
				case "requests_exhausted":
					first.LeftRequests.Store(0)
				case "expired":
					first.UnreusableAt = time.Now().Add(-time.Second)
				case "concurrency":
					m.concurrency = 1
					first.AddRunning()
					defer first.DoneRunning()
				}
			}
			before := created
			if got := m.GetExistingXmuxClient(context.Background()); got != nil {
				t.Fatalf("returned inadmissible client: %p", got)
			}
			if created != before {
				t.Fatal("existing-only selection created a connection")
			}
			if first != nil && control != "concurrency" {
				if !first.NotUsed.Load() || !first.XmuxConn.IsClosed() || len(m.xmuxClients) != 0 {
					t.Fatal("ineligible client was not retired and closed")
				}
			}
			if control == "concurrency" && (first.NotUsed.Load() || first.XmuxConn.IsClosed() || len(m.xmuxClients) != 1) {
				t.Fatal("busy healthy client was retired")
			}
			// The normal entrypoint must still create when no client is eligible.
			if m.GetXmuxClient(context.Background()) == first || created != before+1 {
				t.Fatal("ordinary selection did not create a new client")
			}
		})
	}
}

func TestPR7121ExistingXmuxClientReuseAccounting(t *testing.T) {
	created := 0
	m := NewXmuxManager(XmuxConfig{
		MaxConnections: &RangeConfig{From: 3, To: 3},
		CMaxReuseTimes: &RangeConfig{From: 2, To: 2},
	}, func() XmuxConn {
		created++
		return &pr7121XmuxConn{}
	})
	ctx := context.Background()
	first := m.GetXmuxClient(ctx)
	if got := m.GetExistingXmuxClient(ctx); got != first || created != 1 || len(m.xmuxClients) != 1 {
		t.Fatal("existing selection expanded the pool or duplicated its wrapper")
	}
	if first.leftUsage != 0 {
		t.Fatal("existing selection did not consume the final reuse")
	}
	if m.GetExistingXmuxClient(ctx) != nil || created != 1 || !first.NotUsed.Load() {
		t.Fatal("existing selection admitted an exhausted client")
	}
	second := m.GetXmuxClient(ctx)
	third := m.GetXmuxClient(ctx)
	if second == third || created != 3 {
		t.Fatal("ordinary selection no longer fills maxConnections before reuse")
	}
}
