package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sync"
	"text/template"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	header        []*Header
	h2Mu          sync.Mutex
	h2Conns       map[net.Destination]*h2Conn
	h2Retired     []*h2Conn
	closed        bool
}

type h2Conn struct {
	rawConn net.Conn
	h2Conn  *http2.ClientConn
}

type h2PayloadWrite struct {
	done sync.WaitGroup
	err  error
}

func startH2PayloadWrite(ctx context.Context, trackTCP bool, writer *io.PipeWriter, payload []byte) *h2PayloadWrite {
	write := new(h2PayloadWrite)
	write.done.Add(1)
	ownedPayload := bytes.Clone(payload)
	var participant task.ParticipantLease
	if trackTCP {
		participant = task.AcquireParticipant(ctx)
	}
	go func() {
		defer write.done.Done()
		if participant != nil {
			defer func() { participant.Release(write.err) }()
		}
		_, write.err = writer.Write(ownedPayload)
	}()
	return write
}

func (w *h2PayloadWrite) Wait() error {
	w.done.Wait()
	return w.err
}

// NewClient create a new http client based on the given config.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New(`no target server found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	v := core.MustFromContext(ctx)
	return &Client{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		header:        config.Header,
		h2Conns:       make(map[net.Destination]*h2Conn),
	}, nil
}

func (c *Client) Close() error {
	c.h2Mu.Lock()
	if c.closed {
		c.h2Mu.Unlock()
		return nil
	}
	c.closed = true
	connections := c.h2Conns
	retired := c.h2Retired
	c.h2Conns = nil
	c.h2Retired = nil
	c.h2Mu.Unlock()
	var closeErrors []error
	for _, connection := range connections {
		if connection.h2Conn != nil {
			closeErrors = append(closeErrors, connection.h2Conn.Close())
		}
		if connection.rawConn != nil {
			closeErrors = append(closeErrors, connection.rawConn.Close())
		}
	}
	for _, connection := range retired {
		if connection.h2Conn != nil {
			closeErrors = append(closeErrors, connection.h2Conn.Close())
		}
		if connection.rawConn != nil {
			closeErrors = append(closeErrors, connection.rawConn.Close())
		}
	}
	return errors.Combine(closeErrors...)
}

// Process implements proxy.Outbound.Process. We first create a socket tunnel via HTTP CONNECT method, then redirect all inbound traffic to that tunnel.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "http"
	ob.CanSpliceCopy = 2
	target := ob.Target
	targetAddr := target.NetAddr()

	if target.Network == net.Network_UDP {
		return errors.New("UDP is not supported by HTTP outbound")
	}

	server := c.server
	dest := server.Destination
	user := server.User
	var conn stat.Connection

	mbuf, _ := link.Reader.ReadMultiBuffer()
	len := mbuf.Len()
	firstPayload := bytespool.Alloc(len)
	mbuf, _ = buf.SplitBytes(mbuf, firstPayload)
	firstPayload = firstPayload[:len]

	buf.ReleaseMulti(mbuf)
	defer bytespool.Free(firstPayload)

	header, err := fillRequestHeader(ctx, c.header)
	if err != nil {
		return errors.New("failed to fill out header").Base(err)
	}

	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		netConn, err := c.setUpHTTPTunnel(ctx, dest, targetAddr, user, dialer, header, firstPayload)
		if netConn != nil {
			if _, ok := netConn.(*http2Conn); !ok {
				if _, err := netConn.Write(firstPayload); err != nil {
					netConn.Close()
					return err
				}
			}
			conn = stat.Connection(netConn)
		}
		return err
	}); err != nil {
		return errors.New("failed to find an available destination").Base(err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			errors.LogInfoInner(ctx, err, "failed to closed connection")
		}
	}()

	p := c.policyManager.ForLevel(0)
	if user != nil {
		p = c.policyManager.ForLevel(user.Level)
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = core.ContextWithoutRequestCancellation(ctx)
		defer newCancel()
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)

	requestFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}
	responseFunc := func() error {
		ob.CanSpliceCopy = 1
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if newCtx == nil {
		err = task.Run(ctx, requestFunc, responseDonePost)
	} else {
		var copies task.Lifecycle
		trackCopy := func(copyTask func() error) func() error {
			copies.Acquire()
			return func() error {
				defer copies.Release()
				return copyTask()
			}
		}
		err = task.Run(ctx, trackCopy(requestFunc), trackCopy(responseDonePost))
		cancel()
		newCancel()
		_ = conn.Close()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		copies.Seal()
		copies.Wait()
		_ = timer.CloseAndWait()
	}
	if err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

// fillRequestHeader will fill out the template of the headers
func fillRequestHeader(ctx context.Context, header []*Header) ([]*Header, error) {
	if len(header) == 0 {
		return header, nil
	}

	inbound := session.InboundFromContext(ctx)
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]

	var src net.Destination
	if inbound != nil {
		src = inbound.Source
	} else {
		src = net.TCPDestination(net.AnyIP, 0)
	}

	data := struct {
		Source net.Destination
		Target net.Destination
	}{
		Source: src,
		Target: ob.Target,
	}

	filled := make([]*Header, len(header))
	for i, h := range header {
		tmpl, err := template.New(h.Key).Parse(h.Value)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer

		if err = tmpl.Execute(&buf, data); err != nil {
			return nil, err
		}
		filled[i] = &Header{Key: h.Key, Value: buf.String()}
	}

	return filled, nil
}

// setUpHTTPTunnel will create a socket tunnel via HTTP CONNECT method
func (c *Client) setUpHTTPTunnel(ctx context.Context, dest net.Destination, target string, user *protocol.MemoryUser, dialer internet.Dialer, header []*Header, firstPayload []byte) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Header: make(http.Header),
		Host:   target,
	}

	if user != nil && user.Account != nil {
		account := user.Account.(*Account)
		auth := account.GetUsername() + ":" + account.GetPassword()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	for _, h := range header {
		req.Header.Set(h.Key, h.Value)
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	connectHTTP1 := func(rawConn net.Conn) (net.Conn, error) {
		req.Header.Set("Proxy-Connection", "Keep-Alive")

		err := req.Write(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			rawConn.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
		}
		return rawConn, nil
	}

	connectHTTP2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
		pr, pw := io.Pipe()
		req.Body = pr

		payloadWrite := startH2PayloadWrite(ctx, !session.TimeoutOnlyFromContext(ctx), pw, firstPayload)

		resp, err := h2clientConn.RoundTrip(req)
		if err != nil {
			_ = pr.CloseWithError(err)
			_ = pw.CloseWithError(err)
			_ = rawConn.Close()
			_ = payloadWrite.Wait()
			return nil, err
		}

		if err := payloadWrite.Wait(); err != nil {
			_ = pr.CloseWithError(err)
			_ = pw.CloseWithError(err)
			_ = resp.Body.Close()
			_ = rawConn.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = pr.Close()
			_ = pw.Close()
			_ = resp.Body.Close()
			_ = rawConn.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
		}
		return newHTTP2Conn(rawConn, pw, resp.Body), nil
	}

	c.h2Mu.Lock()
	var idleRetired []*h2Conn
	retained := c.h2Retired[:0]
	for _, connection := range c.h2Retired {
		state := connection.h2Conn.State()
		if state.StreamsActive == 0 && state.StreamsReserved == 0 && state.StreamsPending == 0 {
			idleRetired = append(idleRetired, connection)
		} else {
			retained = append(retained, connection)
		}
	}
	c.h2Retired = retained
	cachedConn, cachedConnFound := c.h2Conns[dest]
	closed := c.closed
	c.h2Mu.Unlock()
	for _, connection := range idleRetired {
		_ = connection.h2Conn.Close()
		_ = connection.rawConn.Close()
	}
	if closed {
		return nil, errors.New("HTTP outbound is closed")
	}

	if cachedConnFound {
		rc, cc := cachedConn.rawConn, cachedConn.h2Conn
		if cc.CanTakeNewRequest() {
			proxyConn, err := connectHTTP2(rc, cc)
			if err != nil {
				c.h2Mu.Lock()
				if c.h2Conns[dest] == cachedConn {
					delete(c.h2Conns, dest)
					c.h2Retired = append(c.h2Retired, cachedConn)
				}
				c.h2Mu.Unlock()
				return nil, err
			}
			c.h2Mu.Lock()
			current := !c.closed && c.h2Conns[dest] == cachedConn
			c.h2Mu.Unlock()
			if !current {
				_ = proxyConn.Close()
				return nil, errors.New("HTTP outbound closed or replaced during HTTP/2 reuse")
			}

			return proxyConn, nil
		}
	}

	rawConn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}

	iConn := stat.TryUnwrapStatsConn(rawConn)

	nextProto := ""
	if tlsConn, ok := iConn.(*tls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	} else if tlsConn, ok := iConn.(*tls.UConn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	switch nextProto {
	case "", "http/1.1":
		return connectHTTP1(rawConn)
	case "h2":
		t := http2.Transport{}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		proxyConn, err := connectHTTP2(rawConn, h2clientConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		candidate := &h2Conn{
			rawConn: rawConn,
			h2Conn:  h2clientConn,
		}
		c.h2Mu.Lock()
		if c.closed {
			c.h2Mu.Unlock()
			_ = h2clientConn.Close()
			_ = rawConn.Close()
			return nil, errors.New("HTTP outbound closed during HTTP/2 publication")
		}
		previous := c.h2Conns[dest]
		c.h2Conns[dest] = candidate
		if previous != nil {
			c.h2Retired = append(c.h2Retired, previous)
		}
		c.h2Mu.Unlock()

		return proxyConn, err
	default:
		_ = rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " + nextProto)
	}
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	h.in.Close()
	return h.out.Close()
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
