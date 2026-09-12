package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

const connectionQueueCapacity = 256

type dialRequest struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	Extra          any    `json:"extra,omitempty"`
	StreamResponse bool   `json:"streamResponse"`
}

// serviceGeneration is the exact owner of one Browser listener, its upgrade
// publishers, queued controller sockets and sockets borrowed by an in-flight
// dial request. A successful streaming dial transfers its socket to the
// caller; reload deliberately does not close sockets after that transfer.
type serviceGeneration struct {
	addr      string
	authority string
	token     string
	page      []byte
	listener  net.Listener
	server    *http.Server
	ctx       context.Context
	cancel    context.CancelFunc
	tasks     task.Lifecycle
	conns     chan *websocket.Conn
	mu        sync.Mutex
	sealed    bool
	borrowed  map[*websocket.Conn]struct{}
	serveErr  error
	stopErr   error
	stopOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}
	closeErr  error
}

var serviceRegistry = struct {
	reloadMu sync.Mutex
	mu       sync.RWMutex
	active   *serviceGeneration
	retiring map[*serviceGeneration]struct{}
}{retiring: make(map[*serviceGeneration]struct{})}

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		parsed, err := url.Parse(origin)
		expectedScheme := "http"
		defaultPort := "80"
		if r.TLS != nil {
			expectedScheme = "https"
			defaultPort = "443"
		}
		return err == nil && parsed.Scheme == expectedScheme && sameAuthority(parsed.Host, r.Host, defaultPort)
	},
}

func newServiceGeneration(addr string) (*serviceGeneration, error) {
	configuredHost, _, err := net.SplitHostPort(addr)
	if err != nil || configuredHost == "" {
		return nil, errors.New("Browser dialer address must contain an explicit host and port").Base(err)
	}
	if ip := net.ParseIP(configuredHost); !strings.EqualFold(configuredHost, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("Browser dialer address must use localhost or an explicit loopback IP")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errors.New("failed to listen for Browser dialer service").Base(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, actualPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		cancel()
		return nil, errors.New("failed to determine Browser dialer listener port").Base(err)
	}
	uuidToken := uuid.New()
	token := uuidToken.String()
	generation := &serviceGeneration{
		addr:      addr,
		authority: net.JoinHostPort(configuredHost, actualPort),
		token:     token,
		page:      bytes.ReplaceAll(webpage, []byte("csrfToken"), []byte(token)),
		listener:  listener,
		ctx:       ctx,
		cancel:    cancel,
		conns:     make(chan *websocket.Conn, connectionQueueCapacity),
		borrowed:  make(map[*websocket.Conn]struct{}),
		done:      make(chan struct{}),
	}
	generation.server = &http.Server{Addr: addr, Handler: http.HandlerFunc(generation.handle)}
	if !generation.tasks.Acquire() {
		_ = listener.Close()
		cancel()
		return nil, errors.New("Browser dialer service generation is sealed")
	}
	go generation.serve()
	return generation, nil
}

func (g *serviceGeneration) serve() {
	err := g.server.Serve(g.listener)
	if err != nil && !stderrors.Is(err, http.ErrServerClosed) {
		g.mu.Lock()
		g.serveErr = err
		g.mu.Unlock()
		g.signalStop()
	}
	g.tasks.Release()
}

func (g *serviceGeneration) handle(w http.ResponseWriter, r *http.Request) {
	if !g.tasks.Acquire() {
		http.Error(w, "Browser dialer service generation is closed", http.StatusServiceUnavailable)
		return
	}
	defer g.tasks.Release()
	if !sameAuthority(r.Host, g.authority, "80") {
		http.Error(w, "invalid Browser dialer host", http.StatusMisdirectedRequest)
		return
	}

	if r.URL.Path != "/websocket" {
		_, _ = w.Write(g.page)
		return
	}
	if r.URL.Query().Get("token") != g.token {
		http.Error(w, "invalid Browser dialer token", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		errors.LogErrorInner(g.ctx, err, "Browser dialer http upgrade unexpected error")
		return
	}
	if !g.enqueue(conn) {
		_ = conn.Close()
	}
}

func sameAuthority(left, right, defaultPort string) bool {
	leftHost, leftPort, leftOK := splitAuthority(left, defaultPort)
	rightHost, rightPort, rightOK := splitAuthority(right, defaultPort)
	return leftOK && rightOK && strings.EqualFold(leftHost, rightHost) && leftPort == rightPort
}

func splitAuthority(authority, defaultPort string) (string, string, bool) {
	host, port, err := net.SplitHostPort(authority)
	if err == nil {
		return host, port, host != "" && port != ""
	}
	if authority == "" || strings.Contains(authority, ":") {
		return "", "", false
	}
	return authority, defaultPort, true
}

// enqueue publishes only into this exact generation. It never blocks an HTTP
// handler behind a full queue, and seal is serialized against publication.
func (g *serviceGeneration) enqueue(conn *websocket.Conn) bool {
	if conn == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return false
	}
	select {
	case g.conns <- conn:
		return true
	default:
		return false
	}
}

func (g *serviceGeneration) borrow(ctx context.Context) (*websocket.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, errors.New("Browser dialer service generation is closed")
	case conn := <-g.conns:
		if conn == nil {
			return nil, errors.New("Browser dialer service returned a nil connection")
		}
		g.mu.Lock()
		if g.sealed {
			g.mu.Unlock()
			_ = conn.Close()
			return nil, errors.New("Browser dialer service generation is closed")
		}
		g.borrowed[conn] = struct{}{}
		g.mu.Unlock()
		return conn, nil
	}
}

func (g *serviceGeneration) releaseBorrowed(conn *websocket.Conn) {
	g.mu.Lock()
	delete(g.borrowed, conn)
	g.mu.Unlock()
}

// transferBorrowed linearizes returned ownership before reload seal. If seal
// won, the socket remains old-generation cleanup and must not be published.
func (g *serviceGeneration) transferBorrowed(conn *websocket.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		delete(g.borrowed, conn)
		return false
	}
	if _, found := g.borrowed[conn]; !found {
		return false
	}
	delete(g.borrowed, conn)
	return true
}

func (g *serviceGeneration) available() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.sealed
}

func (g *serviceGeneration) signalStop() {
	g.stopOnce.Do(func() {
		g.tasks.Seal()
		g.mu.Lock()
		g.sealed = true
		queued := make([]*websocket.Conn, 0, len(g.conns))
		for {
			select {
			case conn := <-g.conns:
				if conn != nil {
					queued = append(queued, conn)
				}
			default:
				goto queueDrained
			}
		}
	queueDrained:
		borrowed := make([]*websocket.Conn, 0, len(g.borrowed))
		for conn := range g.borrowed {
			borrowed = append(borrowed, conn)
		}
		g.borrowed = make(map[*websocket.Conn]struct{})
		g.mu.Unlock()

		g.cancel()
		for _, conn := range append(queued, borrowed...) {
			_ = conn.Close()
		}
		if err := g.server.Close(); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
			g.mu.Lock()
			g.stopErr = err
			g.mu.Unlock()
		}
	})
}

func (g *serviceGeneration) closeAndWait() error {
	g.signalStop()
	g.closeOnce.Do(func() {
		g.tasks.Wait()
		g.mu.Lock()
		g.closeErr = errors.Combine(g.serveErr, g.stopErr)
		g.mu.Unlock()
		close(g.done)
	})
	<-g.done
	g.mu.Lock()
	err := g.closeErr
	g.mu.Unlock()
	return err
}

func detachAndRetire(old, replacement *serviceGeneration) {
	serviceRegistry.mu.Lock()
	serviceRegistry.active = replacement
	if old != nil {
		serviceRegistry.retiring[old] = struct{}{}
	}
	serviceRegistry.mu.Unlock()
}

func finishRetirement(generation *serviceGeneration) {
	if generation == nil {
		return
	}
	serviceRegistry.mu.Lock()
	delete(serviceRegistry.retiring, generation)
	serviceRegistry.mu.Unlock()
}

func reloadAddress(addr string) error {
	serviceRegistry.reloadMu.Lock()
	defer serviceRegistry.reloadMu.Unlock()
	return reloadAddressLocked(addr)
}

func reloadAddressLocked(addr string) error {
	serviceRegistry.mu.RLock()
	old := serviceRegistry.active
	serviceRegistry.mu.RUnlock()
	if old == nil && addr == "" {
		return nil
	}
	if old != nil && old.addr == addr && old.available() {
		return nil
	}

	// A stopped generation at the same address must release its listener before
	// replacement can bind. Exact registry identity prevents stale cleanup from
	// touching a later generation at the same address.
	var priorCloseErr error
	if old != nil && old.addr == addr {
		detachAndRetire(old, nil)
		priorCloseErr = old.closeAndWait()
		finishRetirement(old)
		old = nil
	}

	var replacement *serviceGeneration
	var err error
	if addr != "" {
		replacement, err = newServiceGeneration(addr)
		if err != nil {
			return errors.Combine(priorCloseErr, err)
		}
	}

	detachAndRetire(old, replacement)
	if old == nil {
		return priorCloseErr
	}
	closeErr := old.closeAndWait()
	finishRetirement(old)
	return errors.Combine(priorCloseErr, closeErr)
}

func reloadEnvironment() error {
	serviceRegistry.reloadMu.Lock()
	defer serviceRegistry.reloadMu.Unlock()
	addr := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	return reloadAddressLocked(addr)
}

// Reload is retained for external Go-module users. Instance initialization
// uses reloadEnvironment directly so listener setup failures remain typed.
func Reload() {
	if err := reloadEnvironment(); err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to reload Browser dialer service")
	}
}

func acquireActiveGeneration() (*serviceGeneration, error) {
	serviceRegistry.mu.RLock()
	generation := serviceRegistry.active
	if generation == nil || !generation.tasks.Acquire() {
		serviceRegistry.mu.RUnlock()
		return nil, errors.New("Browser dialer service is unavailable")
	}
	serviceRegistry.mu.RUnlock()
	return generation, nil
}

func HasBrowserDialer() bool {
	serviceRegistry.mu.RLock()
	generation := serviceRegistry.active
	serviceRegistry.mu.RUnlock()
	return generation != nil && generation.available()
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
}

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	return DialWSContext(context.Background(), uri, ed)
}

func DialWSContext(ctx context.Context, uri string, ed []byte) (*websocket.Conn, error) {
	request := dialRequest{
		Method:         "WS",
		URL:            uri,
		StreamResponse: true,
	}
	request.Extra = webSocketExtra{Protocol: base64.RawURLEncoding.EncodeToString(ed)}
	return dialTask(ctx, request)
}

type httpExtra struct {
	Referrer string            `json:"referrer,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Cookies  map[string]string `json:"cookies,omitempty"`
}

func httpExtraFromHeadersAndCookies(headers http.Header, cookies []*http.Cookie) *httpExtra {
	if len(headers) == 0 {
		return nil
	}

	extra := httpExtra{}
	if referrer := headers.Get("Referer"); referrer != "" {
		extra.Referrer = referrer
		headers.Del("Referer")
	}

	if len(headers) > 0 {
		extra.Headers = make(map[string]string)
		for header := range headers {
			extra.Headers[header] = headers.Get(header)
		}
	}

	if len(cookies) > 0 {
		extra.Cookies = make(map[string]string)
		for _, cookie := range cookies {
			extra.Cookies[cookie.Name] = cookie.Value
		}
	}

	return &extra
}

func DialGet(uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	return DialGetContext(context.Background(), uri, headers, cookies)
}

func DialGetContext(ctx context.Context, uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	request := dialRequest{
		Method:         "GET",
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: true,
	}
	return dialTask(ctx, request)
}

func DialPacket(method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	return DialPacketContext(context.Background(), method, uri, headers, cookies, payload)
}

func DialPacketContext(ctx context.Context, method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	request := dialRequest{
		Method:         method,
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: false,
	}

	conn, generation, stopRequest, releaseTask, err := borrowForTask(ctx, request)
	if err != nil {
		return err
	}
	defer func() {
		stopRequest()
		generation.releaseBorrowed(conn)
		_ = conn.Close()
		releaseTask()
	}()

	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		return taskError(ctx, generation, err)
	}
	if err := CheckOK(conn); err != nil {
		return taskError(ctx, generation, err)
	}
	return nil
}

func borrowForTask(ctx context.Context, request dialRequest) (*websocket.Conn, *serviceGeneration, func() bool, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	generation, err := acquireActiveGeneration()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	committed := false
	defer func() {
		if !committed {
			generation.tasks.Release()
		}
	}()

	for {
		conn, err := generation.borrow(ctx)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		requestCloseDone := make(chan struct{})
		stopRequestCallback := context.AfterFunc(ctx, func() {
			defer close(requestCloseDone)
			_ = conn.Close()
		})
		stopRequest := func() bool {
			stopped := stopRequestCallback()
			if !stopped {
				<-requestCloseDone
			}
			return stopped
		}
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			stopRequest()
			generation.releaseBorrowed(conn)
			_ = conn.Close()
			if ctx.Err() != nil || generation.ctx.Err() != nil {
				return nil, nil, nil, nil, taskError(ctx, generation, err)
			}
			continue
		}
		if err := CheckOK(conn); err != nil {
			stopRequest()
			generation.releaseBorrowed(conn)
			_ = conn.Close()
			return nil, nil, nil, nil, taskError(ctx, generation, err)
		}
		committed = true
		var releaseOnce sync.Once
		return conn, generation, stopRequest, func() {
			releaseOnce.Do(func() {
				generation.tasks.Release()
			})
		}, nil
	}
}

func dialTask(ctx context.Context, request dialRequest) (*websocket.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, generation, stopRequest, releaseTask, err := borrowForTask(ctx, request)
	if err != nil {
		return nil, err
	}
	if !generation.transferBorrowed(conn) {
		stopRequest()
		_ = conn.Close()
		releaseTask()
		return nil, errors.New("Browser dialer service generation closed before result publication")
	}
	if !stopRequest() {
		_ = conn.Close()
		releaseTask()
		return nil, taskError(ctx, generation, context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		releaseTask()
		return nil, err
	}
	releaseTask()
	return conn, nil
}

func taskError(ctx context.Context, generation *serviceGeneration, fallback error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if generation != nil && generation.ctx.Err() != nil {
		return errors.New("Browser dialer service generation is closed").Base(fallback)
	}
	return fallback
}

func CheckOK(conn *websocket.Conn) error {
	if _, payload, err := conn.ReadMessage(); err != nil {
		_ = conn.Close()
		return err
	} else if message := string(payload); message != "ok" {
		_ = conn.Close()
		return errors.New(message)
	}
	return nil
}

func init() {
	platform.RegisterEnvReload(reloadEnvironment)
}
