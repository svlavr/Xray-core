package reverse

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

// Bridge is a component in reverse proxy, that relays connections from Portal to local address.
type Bridge struct {
	access      sync.Mutex
	startMu     sync.Mutex
	dispatcher  routing.Dispatcher
	tag         string
	domain      string
	workers     []*BridgeWorker
	monitorTask *task.Periodic
	ctx         context.Context
	cancel      context.CancelFunc
	sealed      bool
	stopOnce    sync.Once
	closeOnce   sync.Once
	closeDone   chan struct{}
	closeErr    error
}

// NewBridge creates a new Bridge instance.
func NewBridge(config *BridgeConfig, dispatcher routing.Dispatcher) (*Bridge, error) {
	return newBridge(context.Background(), config, dispatcher)
}

func newBridge(parent context.Context, config *BridgeConfig, dispatcher routing.Dispatcher) (*Bridge, error) {
	if config.Tag == "" {
		return nil, errors.New("bridge tag is empty")
	}
	if config.Domain == "" {
		return nil, errors.New("bridge domain is empty")
	}

	ctx, cancel := context.WithCancel(parent)
	b := &Bridge{
		dispatcher: dispatcher,
		tag:        config.Tag,
		domain:     config.Domain,
		closeDone:  make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
	b.monitorTask = &task.Periodic{
		Execute:  b.monitor,
		Interval: time.Second * 2,
	}
	return b, nil
}

func (b *Bridge) cleanup() {
	b.access.Lock()
	if b.sealed {
		b.access.Unlock()
		return
	}
	var activeWorkers []*BridgeWorker
	var retiredWorkers []*BridgeWorker

	for _, w := range b.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		} else {
			retiredWorkers = append(retiredWorkers, w)
		}
	}

	if len(activeWorkers) != len(b.workers) {
		b.workers = activeWorkers
	}
	b.access.Unlock()
	for _, worker := range retiredWorkers {
		worker.SignalStop()
	}
	for _, worker := range retiredWorkers {
		_ = worker.Close()
	}
}

func (b *Bridge) monitor() error {
	b.cleanup()
	b.access.Lock()
	if b.sealed {
		b.access.Unlock()
		return nil
	}
	workers := append([]*BridgeWorker(nil), b.workers...)
	b.access.Unlock()

	var numConnections uint32
	var numWorker uint32

	for _, w := range workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}

	if numWorker == 0 || numConnections/numWorker > 16 {
		worker, err := newBridgeWorker(b.ctx, b.domain, b.tag, b.dispatcher)
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "failed to create bridge worker")
			return nil
		}
		b.access.Lock()
		if b.sealed {
			b.access.Unlock()
			_ = worker.Close()
			return nil
		}
		b.workers = append(b.workers, worker)
		b.access.Unlock()
	}

	return nil
}

func (b *Bridge) Start() error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	b.access.Lock()
	closed := b.sealed
	b.access.Unlock()
	if closed {
		return errors.New("bridge is closed")
	}
	return b.monitorTask.Start()
}

func (b *Bridge) SignalStop() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() {
		b.startMu.Lock()
		defer b.startMu.Unlock()
		b.access.Lock()
		b.sealed = true
		workers := append([]*BridgeWorker(nil), b.workers...)
		b.access.Unlock()
		b.cancel()
		_ = b.monitorTask.Close()
		for _, worker := range workers {
			worker.SignalStop()
		}
	})
}

func (b *Bridge) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		b.SignalStop()
		b.access.Lock()
		workers := append([]*BridgeWorker(nil), b.workers...)
		b.access.Unlock()
		var errs []error
		errs = append(errs, b.monitorTask.CloseAndWait())
		for _, worker := range workers {
			errs = append(errs, worker.Close())
		}
		b.access.Lock()
		b.closeErr = errors.Combine(errs...)
		close(b.closeDone)
		b.access.Unlock()
	})
	b.access.Lock()
	done := b.closeDone
	b.access.Unlock()
	<-done
	b.access.Lock()
	defer b.access.Unlock()
	return b.closeErr
}

type BridgeWorker struct {
	access     sync.Mutex
	Tag        string
	Worker     *mux.ServerWorker
	Dispatcher routing.Dispatcher
	State      Control_State
	Timer      *signal.ActivityTimer
	control    task.Lifecycle
	stopOnce   sync.Once
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
	controls   map[*transport.Link]struct{}
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewBridgeWorker(domain string, tag string, d routing.Dispatcher) (*BridgeWorker, error) {
	return newBridgeWorker(context.Background(), domain, tag, d)
}

func newBridgeWorker(ctx context.Context, domain string, tag string, d routing.Dispatcher) (*BridgeWorker, error) {
	workerCtx, cancel := context.WithCancel(ctx)
	workerCtx = session.ContextWithInbound(workerCtx, &session.Inbound{
		Tag: tag,
	})
	link, err := d.Dispatch(workerCtx, net.Destination{
		Network: net.Network_TCP,
		Address: net.DomainAddress(domain),
		Port:    0,
	})
	if err != nil {
		cancel()
		return nil, err
	}

	w := &BridgeWorker{
		Dispatcher: d,
		Tag:        tag,
		closeDone:  make(chan struct{}),
		ctx:        workerCtx,
		cancel:     cancel,
	}

	worker, err := mux.NewServerWorker(workerCtx, w, link)
	if err != nil {
		cancel()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return nil, err
	}
	w.Worker = worker

	terminate := func() {
		worker.Close()
	}
	w.Timer = signal.CancelAfterInactivity(workerCtx, terminate, 60*time.Second)
	return w, nil
}

func (w *BridgeWorker) Type() interface{} {
	return routing.DispatcherType()
}

func (w *BridgeWorker) Start() error {
	return nil
}

func (w *BridgeWorker) Close() error {
	if w == nil {
		return nil
	}
	w.access.Lock()
	if w.closeDone == nil {
		w.closeDone = make(chan struct{})
	}
	w.access.Unlock()
	w.closeOnce.Do(func() {
		w.SignalStop()
		var errs []error
		if w.Timer != nil {
			errs = append(errs, w.Timer.CloseAndWait())
		}
		if w.Worker != nil {
			errs = append(errs, w.Worker.CloseAndWait())
		}
		w.control.Wait()
		w.access.Lock()
		w.closeErr = errors.Combine(errs...)
		close(w.closeDone)
		w.access.Unlock()
	})
	w.access.Lock()
	done := w.closeDone
	w.access.Unlock()
	<-done
	w.access.Lock()
	defer w.access.Unlock()
	return w.closeErr
}

func (w *BridgeWorker) SignalStop() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() {
		w.control.Seal()
		if w.cancel != nil {
			w.cancel()
		}
		w.access.Lock()
		controls := make([]*transport.Link, 0, len(w.controls))
		for link := range w.controls {
			controls = append(controls, link)
		}
		w.access.Unlock()
		for _, link := range controls {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
		if w.Worker != nil {
			_ = w.Worker.Close()
		}
	})
}

func (w *BridgeWorker) IsActive() bool {
	w.access.Lock()
	state := w.State
	w.access.Unlock()
	return state == Control_ACTIVE && !w.Worker.Closed()
}

func (w *BridgeWorker) Closed() bool {
	return w.Worker.Closed()
}

func (w *BridgeWorker) Connections() uint32 {
	return w.Worker.ActiveConnections()
}

func (w *BridgeWorker) handleInternalConn(link *transport.Link) {
	reader := link.Reader
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			if w.Timer != nil {
				if w.Closed() {
					w.Timer.SetTimeout(0)
				} else {
					w.Timer.SetTimeout(24 * time.Hour)
				}
			}
			return
		}
		if w.Timer != nil {
			w.Timer.Update()
		}
		valid := true
		for _, b := range mb {
			var ctl Control
			if err := proto.Unmarshal(b.Bytes(), &ctl); err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to parse proto message")
				valid = false
				break
			}
			w.access.Lock()
			w.State = ctl.State
			w.access.Unlock()
		}
		buf.ReleaseMulti(mb)
		if !valid {
			if w.Timer != nil {
				w.Timer.SetTimeout(0)
			}
			return
		}
	}
}

func (w *BridgeWorker) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if !w.control.Acquire() {
		return nil, errors.New("bridge worker is closed")
	}
	if !isInternalDomain(dest) {
		defer w.control.Release()
		if session.InboundFromContext(ctx) == nil {
			ctx = session.ContextWithInbound(ctx, &session.Inbound{
				Tag: w.Tag,
			})
		}
		return w.Dispatcher.Dispatch(ctx, dest)
	}

	opt := []pipe.Option{pipe.WithSizeLimit(16 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	controlLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}
	w.access.Lock()
	if w.control.Sealed() {
		w.access.Unlock()
		w.control.Release()
		common.Interrupt(uplinkReader)
		common.Interrupt(uplinkWriter)
		common.Interrupt(downlinkReader)
		common.Interrupt(downlinkWriter)
		return nil, errors.New("bridge worker is closed")
	}
	if w.controls == nil {
		w.controls = make(map[*transport.Link]struct{})
	}
	w.controls[controlLink] = struct{}{}
	w.access.Unlock()
	go func() {
		defer w.control.Release()
		defer func() {
			w.access.Lock()
			delete(w.controls, controlLink)
			w.access.Unlock()
		}()
		w.handleInternalConn(controlLink)
	}()

	return &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}, nil
}

func (w *BridgeWorker) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if !w.control.Acquire() {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("bridge worker is closed")
	}
	w.access.Lock()
	if w.control.Sealed() {
		w.access.Unlock()
		w.control.Release()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("bridge worker is closed")
	}
	if w.controls == nil {
		w.controls = make(map[*transport.Link]struct{})
	}
	w.controls[link] = struct{}{}
	w.access.Unlock()
	defer w.control.Release()
	defer func() {
		w.access.Lock()
		delete(w.controls, link)
		w.access.Unlock()
	}()
	if !isInternalDomain(dest) {
		if session.InboundFromContext(ctx) == nil {
			ctx = session.ContextWithInbound(ctx, &session.Inbound{
				Tag: w.Tag,
			})
		}
		return w.Dispatcher.DispatchLink(ctx, dest, link)
	}
	w.handleInternalConn(link)

	return nil
}
