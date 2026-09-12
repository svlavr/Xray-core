package burst

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

type pingClient struct {
	destination string
	httpClient  *http.Client
	ctx         context.Context
	timeout     time.Duration
}

func newPingClient(ctx context.Context, lifecycle *task.Lifecycle, dispatcher routing.Dispatcher, destination string, timeout time.Duration, handler string) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  newHTTPClient(ctx, lifecycle, dispatcher, handler, timeout),
		ctx:         ctx,
		timeout:     timeout,
	}
}

func newDirectPingClient(ctx context.Context, lifecycle *task.Lifecycle, destination string, timeout time.Duration) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  newDirectHTTPClient(ctx, lifecycle, timeout),
		ctx:         ctx,
		timeout:     timeout,
	}
}

func newDirectHTTPClient(ownerCtx context.Context, lifecycle *task.Lifecycle, timeout time.Duration) *http.Client {
	dialer := &stdnet.Dialer{Timeout: timeout}
	return newDirectHTTPClientWithDialer(ownerCtx, lifecycle, timeout, dialer.DialContext)
}

func newDirectHTTPClientWithDialer(ownerCtx context.Context, lifecycle *task.Lifecycle, timeout time.Duration, dialContext func(context.Context, string, string) (stdnet.Conn, error)) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		DialContext: func(requestCtx context.Context, network, address string) (stdnet.Conn, error) {
			if lifecycle == nil || !lifecycle.Acquire() {
				return nil, context.Canceled
			}
			defer lifecycle.Release()
			dialCtx, cancelDial := context.WithCancel(ownerCtx)
			stopRequestCancel := context.AfterFunc(requestCtx, cancelDial)
			defer func() {
				stopRequestCancel()
				cancelDial()
			}()
			return dialContext(dialCtx, network, address)
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func newHTTPClient(ownerCtx context.Context, lifecycle *task.Lifecycle, dispatcher routing.Dispatcher, handler string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(requestCtx context.Context, network, addr string) (net.Conn, error) {
			if lifecycle == nil || !lifecycle.Acquire() {
				return nil, context.Canceled
			}
			defer lifecycle.Release()
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			dialCtx, cancelDial := context.WithCancel(ownerCtx)
			stopRequestCancel := context.AfterFunc(requestCtx, cancelDial)
			defer func() {
				stopRequestCancel()
				cancelDial()
			}()
			return tagged.Dialer(dialCtx, dispatcher, dest, handler)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// don't follow redirect
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MeasureDelay returns the delay time of the request to dest
func (s *pingClient) MeasureDelay(httpMethod string) (time.Duration, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}

	requestCtx := s.ctx
	cancel := func() {}
	if s.timeout > 0 {
		requestCtx, cancel = context.WithTimeout(s.ctx, s.timeout)
	}
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, httpMethod, s.destination, nil)
	if err != nil {
		return rttFailed, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return rttFailed, err
	}
	defer resp.Body.Close()
	if httpMethod == http.MethodGet {
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return rttFailed, err
		}
	}
	return time.Since(start), nil
}
