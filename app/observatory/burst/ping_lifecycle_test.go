package burst

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/task"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestDirectPingDialIsJoinedAfterRequestCancellation(t *testing.T) {
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	var lifecycle task.Lifecycle
	dialStarted := make(chan struct{})
	dialCancelled := make(chan struct{})
	allowDialReturn := make(chan struct{})
	client := &pingClient{
		ctx:         ownerCtx,
		destination: "http://example.test/",
		timeout:     time.Minute,
		httpClient: newDirectHTTPClientWithDialer(ownerCtx, &lifecycle, time.Minute, func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			close(dialCancelled)
			<-allowDialReturn
			return nil, ctx.Err()
		}),
	}
	probeDone := make(chan error, 1)
	go func() {
		_, err := client.MeasureDelay(http.MethodHead)
		probeDone <- err
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("direct dial did not start")
	}
	lifecycle.Seal()
	cancelOwner()
	select {
	case <-dialCancelled:
	case <-time.After(time.Second):
		t.Fatal("direct dial did not observe owner cancellation")
	}
	waitDone := make(chan struct{})
	go func() {
		lifecycle.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("lifecycle returned before the direct dial receipt")
	case <-time.After(20 * time.Millisecond):
	}
	close(allowDialReturn)
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not join the direct dial receipt")
	}
	select {
	case err := <-probeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("MeasureDelay error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("MeasureDelay did not return after direct dial cleanup")
	}
}

func TestPingClientMeasureDelayUsesOwnerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	requestStarted := make(chan struct{})
	client := &pingClient{
		ctx:         ctx,
		destination: "http://example.test/",
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			close(requestStarted)
			<-request.Context().Done()
			return nil, request.Context().Err()
		})},
	}
	result := make(chan error, 1)
	go func() {
		_, err := client.MeasureDelay(http.MethodHead)
		result <- err
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("MeasureDelay error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("MeasureDelay did not observe owner cancellation")
	}
}
