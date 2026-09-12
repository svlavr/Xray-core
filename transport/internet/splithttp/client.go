package splithttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/net/http2"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, buf.MultiBuffer) error
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          atomic.Bool
	httpVersion     string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
	ctx            context.Context
	cancel         context.CancelFunc
	tasks          task.Lifecycle
	workers        task.Lifecycle
	stopOnce       sync.Once
	closeOnce      sync.Once
	closeDone      chan struct{}
	closeErr       error
	rawMu          sync.Mutex
	rawConns       map[*H1Conn]struct{}
	resourceMu     sync.Mutex
	resources      map[io.Closer]struct{}
}

type ownedH2Carrier struct {
	net.Conn
	owner *DefaultDialerClient
	once  sync.Once
	err   error
}

func (c *ownedH2Carrier) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.forgetResource(c)
	})
	return c.err
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) operationContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(c.ctx))
	stop := context.AfterFunc(c.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	if !c.tasks.Acquire() {
		return nil, nil, nil, errors.New("SplitHTTP transport generation is closed")
	}
	requestCtx, releaseContext := c.operationContext()
	var releaseOnce sync.Once
	releaseTask := func() { releaseOnce.Do(func() { releaseContext(); c.tasks.Release() }) }
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			gotConn.Close()
		},
	})

	method := "GET" // stream-down
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, err := http.NewRequestWithContext(requestCtx, method, url, body)
	if err != nil {
		releaseTask()
		errors.LogInfoInner(ctx, err, "failed to create HTTP request for "+url)
		return nil, nil, nil, err
	}
	c.transportConfig.FillStreamRequest(req, sessionId, "")

	wrc = &WaitReadCloser{wait: done.New(), cleanup: releaseTask}
	if !c.workers.Acquire() {
		_ = wrc.Close()
		return nil, nil, nil, errors.New("SplitHTTP transport generation is closed")
	}
	go func() {
		defer c.workers.Release()
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed.Store(true)
				errors.LogInfoInner(ctx, err, "failed to "+method+" "+url)
			}
			gotConn.Close()
			common.Close(body)
			wrc.Close()
			return
		}
		if resp.StatusCode != 200 && !uploadOnly {
			errors.LogInfo(ctx, "unexpected status ", resp.StatusCode)
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			common.Close(body)
			wrc.Close()
			return
		}
		wrc.(*WaitReadCloser).Set(resp.Body)
	}()

	select {
	case <-gotConn.Wait():
	case <-c.ctx.Done():
		_ = wrc.Close()
		return nil, nil, nil, c.ctx.Err()
	}
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	if !c.tasks.Acquire() {
		buf.ReleaseMulti(payload)
		return errors.New("SplitHTTP transport generation is closed")
	}
	defer c.tasks.Release()
	return c.postPacket(ctx, url, sessionId, seqStr, payload)
}

func (c *DefaultDialerClient) postPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	requestCtx, releaseContext := c.operationContext()
	requestCtx, cancelRequest := context.WithCancel(requestCtx)
	stopRequest := context.AfterFunc(ctx, cancelRequest)
	defer func() { stopRequest(); cancelRequest(); releaseContext() }()
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(requestCtx, method, url, nil)
	if err != nil {
		buf.ReleaseMulti(payload)
		return err
	}
	if err := c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload); err != nil {
		return err
	}

	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed.Store(true)
			return err
		}

		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBuff := new(bytes.Buffer)
		requestBuff.Grow(512 + int(req.ContentLength))
		common.Must(req.Write(requestBuff))

		var uploadConn any
		var h1UploadConn *H1Conn

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(requestCtx)
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				c.rawMu.Lock()
				if c.rawConns == nil || c.ctx.Err() != nil {
					c.rawMu.Unlock()
					_ = h1UploadConn.Close()
					return errors.New("SplitHTTP transport generation closed during H1 publication")
				}
				c.rawConns[h1UploadConn] = struct{}{}
				c.rawMu.Unlock()
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)
			}

			borrowed := h1UploadConn
			stopBorrow := context.AfterFunc(requestCtx, func() { c.closeH1(borrowed) })

			if !newConnection {
				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						stopBorrow()
						c.closeH1(h1UploadConn)
						c.closed.Store(true)
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					io.Copy(io.Discard, resp.Body)
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						stopBorrow()
						c.closeH1(h1UploadConn)
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}

			_, err := h1UploadConn.Write(requestBuff.Bytes())
			if !stopBorrow() && err == nil {
				err = requestCtx.Err()
			}
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			} else if newConnection {
				c.closeH1(h1UploadConn)
				return err
			}
			c.closeH1(h1UploadConn)
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}

func (c *DefaultDialerClient) closeH1(conn *H1Conn) {
	if conn == nil {
		return
	}
	c.rawMu.Lock()
	if c.rawConns != nil {
		delete(c.rawConns, conn)
	}
	c.rawMu.Unlock()
	_ = conn.Close()
}

func (c *DefaultDialerClient) SignalStop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.closed.Store(true)
		c.tasks.Seal()
		c.workers.Seal()
		c.cancel()
		c.closeResources()
	})
}

func (c *DefaultDialerClient) trackResource(resource io.Closer) bool {
	c.resourceMu.Lock()
	if c.resources == nil || c.ctx.Err() != nil {
		c.resourceMu.Unlock()
		_ = resource.Close()
		return false
	}
	c.resources[resource] = struct{}{}
	c.resourceMu.Unlock()
	return true
}

func (c *DefaultDialerClient) trackH2Carrier(connection net.Conn) (net.Conn, error) {
	carrier := &ownedH2Carrier{Conn: connection, owner: c}
	if !c.trackResource(carrier) {
		return nil, errors.New("SplitHTTP transport generation closed during H2 publication")
	}
	return carrier, nil
}

func (c *DefaultDialerClient) forgetResource(resource io.Closer) {
	c.resourceMu.Lock()
	if c.resources != nil {
		delete(c.resources, resource)
	}
	c.resourceMu.Unlock()
}

func (c *DefaultDialerClient) trackH3Resources(ctx context.Context, resources ...io.Closer) bool {
	tracked := make([]io.Closer, 0, len(resources))
	for _, resource := range resources {
		if !c.trackResource(resource) {
			for _, trackedResource := range tracked {
				c.releaseResource(trackedResource)
			}
			return false
		}
		tracked = append(tracked, resource)
	}
	if !c.workers.Acquire() {
		for _, resource := range tracked {
			c.releaseResource(resource)
		}
		return false
	}
	context.AfterFunc(ctx, func() {
		defer c.workers.Release()
		for _, resource := range tracked {
			c.releaseResource(resource)
		}
	})
	return true
}

func (c *DefaultDialerClient) releaseResource(resource io.Closer) {
	c.resourceMu.Lock()
	if c.resources != nil {
		delete(c.resources, resource)
	}
	c.resourceMu.Unlock()
	_ = resource.Close()
}

func (c *DefaultDialerClient) closeResources() {
	c.resourceMu.Lock()
	resources := c.resources
	c.resources = nil
	c.resourceMu.Unlock()
	var closeWG sync.WaitGroup
	for resource := range resources {
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			_ = resource.Close()
		}()
	}
	closeWG.Wait()
}

func (c *DefaultDialerClient) Close() error {
	c.SignalStop()
	c.closeOnce.Do(func() {
		c.rawMu.Lock()
		rawConns := c.rawConns
		c.rawConns = nil
		c.rawMu.Unlock()
		for rawConn := range rawConns {
			_ = rawConn.Close()
		}
		c.workers.Wait()
		c.tasks.Wait()
		transport := c.client.Transport
		switch typed := transport.(type) {
		case *http3.Transport:
			c.closeErr = typed.Close()
		case *http2.Transport:
			typed.CloseIdleConnections()
		case *http.Transport:
			typed.CloseIdleConnections()
		}
		close(c.closeDone)
	})
	<-c.closeDone
	return c.closeErr
}

type WaitReadCloser struct {
	wait        *done.Instance
	reader      atomic.Pointer[io.ReadCloser]
	cleanup     func()
	cleanupOnce sync.Once
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.reader.Store(&rc)
	if w.wait.Done() {
		if p := w.reader.Swap(nil); p != nil {
			(*p).Close()
		}
	}
	w.wait.Close()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	rc := w.reader.Load()
	if rc == nil {
		<-w.wait.Wait()
		if rc = w.reader.Load(); rc == nil {
			w.release()
			return 0, io.ErrClosedPipe
		}
	}
	n, err := (*rc).Read(b)
	if err != nil {
		w.release()
	}
	return n, err
}

func (w *WaitReadCloser) release() {
	w.cleanupOnce.Do(func() {
		if w.cleanup != nil {
			w.cleanup()
		}
	})
}

func (w *WaitReadCloser) Close() error {
	w.release()
	w.wait.Close()
	if p := w.reader.Swap(nil); p != nil {
		return (*p).Close()
	}
	return nil
}
