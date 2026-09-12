package burst

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

func TestHealthPingStopCancelsAndJoinsInitialProbe(t *testing.T) {
	originalDialer := tagged.Dialer
	t.Cleanup(func() { tagged.Dialer = originalDialer })
	dialEntered := make(chan struct{})
	dialCancelled := make(chan struct{})
	allowDialReturn := make(chan struct{})
	tagged.Dialer = func(ctx context.Context, _ routing.Dispatcher, _ net.Destination, _ string) (net.Conn, error) {
		close(dialEntered)
		<-ctx.Done()
		close(dialCancelled)
		<-allowDialReturn
		return nil, ctx.Err()
	}

	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Destination:   "http://example.test/",
		Interval:      int64(10 * time.Second),
		SamplingCount: 1,
		Timeout:       int64(time.Minute),
	})
	h.StartScheduler(func() ([]string, error) { return []string{"blocked"}, nil })
	select {
	case <-dialEntered:
	case <-time.After(time.Second):
		t.Fatal("initial probe did not reach the tagged dialer")
	}

	stopped := make(chan struct{})
	go func() {
		h.StopScheduler()
		close(stopped)
	}()
	select {
	case <-dialCancelled:
	case <-time.After(time.Second):
		t.Fatal("StopScheduler did not cancel the active request context")
	}
	select {
	case <-stopped:
		t.Fatal("StopScheduler returned before the tagged dial receipt")
	case <-time.After(20 * time.Millisecond):
	}
	close(allowDialReturn)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("StopScheduler did not join the active initial probe")
	}
	if err := h.Check([]string{"late"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-close Check error = %v, want context cancellation", err)
	}
	h.StopScheduler()
}
