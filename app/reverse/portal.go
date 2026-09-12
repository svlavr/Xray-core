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
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

type Portal struct {
	access    sync.Mutex
	startMu   sync.Mutex
	ohm       outbound.Manager
	tag       string
	domain    string
	picker    *StaticMuxPicker
	client    *mux.ClientManager
	handler   *Outbound
	lifecycle task.Lifecycle
	stopOnce  sync.Once
	removeMu  sync.Mutex
	removed   bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func NewPortal(config *PortalConfig, ohm outbound.Manager) (*Portal, error) {
	if config.Tag == "" {
		return nil, errors.New("portal tag is empty")
	}

	if config.Domain == "" {
		return nil, errors.New("portal domain is empty")
	}

	picker, err := NewStaticMuxPicker()
	if err != nil {
		return nil, err
	}

	return &Portal{
		ohm:       ohm,
		tag:       config.Tag,
		domain:    config.Domain,
		picker:    picker,
		closeDone: make(chan struct{}),
		client: &mux.ClientManager{
			Picker: picker,
		},
	}, nil
}

func (p *Portal) Start() error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	if !p.lifecycle.Acquire() {
		return errors.New("portal is closed")
	}
	defer p.lifecycle.Release()
	handler := &Outbound{
		portal: p,
		tag:    p.tag,
	}
	p.access.Lock()
	if p.handler != nil {
		p.access.Unlock()
		return errors.New("portal is already started")
	}
	p.handler = handler
	p.access.Unlock()
	if err := p.ohm.AddHandler(context.Background(), handler); err != nil {
		p.access.Lock()
		if p.handler == handler {
			p.handler = nil
		}
		p.access.Unlock()
		return err
	}
	if p.lifecycle.Sealed() {
		if exact, ok := p.ohm.(outbound.ExactHandlerRemover); ok {
			_ = exact.RemoveHandlerInstance(context.Background(), handler)
		} else {
			_ = p.ohm.RemoveHandler(context.Background(), p.tag)
		}
		return errors.New("portal closed during Start")
	}
	return nil
}

func (p *Portal) Close() error {
	if p == nil {
		return nil
	}
	p.startMu.Lock()
	err := p.removeHandlerLocked()
	if err == nil {
		p.SignalStop()
	}
	p.startMu.Unlock()
	if err != nil {
		return err
	}
	return p.closeOwned()
}

func (p *Portal) removeHandler() error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	return p.removeHandlerLocked()
}

func (p *Portal) removeHandlerLocked() error {
	p.removeMu.Lock()
	defer p.removeMu.Unlock()
	if p.removed {
		return nil
	}
	p.access.Lock()
	handler := p.handler
	p.access.Unlock()
	if handler != nil {
		var err error
		if exact, ok := p.ohm.(outbound.ExactHandlerRemover); ok {
			err = exact.RemoveHandlerInstance(context.Background(), handler)
		} else {
			// Preserve the stable Manager behavior for legacy implementations.
			err = p.ohm.RemoveHandler(context.Background(), p.tag)
		}
		if err != nil {
			return err
		}
	}
	p.removed = true
	return nil
}

func (p *Portal) closeOwned() error {
	p.closeOnce.Do(func() {
		p.SignalStop()
		err := p.picker.Close()
		p.lifecycle.Wait()
		p.access.Lock()
		p.closeErr = err
		close(p.closeDone)
		p.access.Unlock()
	})
	p.access.Lock()
	done := p.closeDone
	p.access.Unlock()
	<-done
	p.access.Lock()
	err := p.closeErr
	p.access.Unlock()
	return err
}

func (p *Portal) closeFromHandler(handler *Outbound) error {
	if p == nil {
		return nil
	}
	p.access.Lock()
	current := p.handler
	p.access.Unlock()
	if current != handler {
		return nil
	}
	return p.closeOwned()
}

func (p *Portal) SignalStop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		p.lifecycle.Seal()
		p.picker.SignalStop()
	})
}

func (p *Portal) HandleConnection(ctx context.Context, link *transport.Link) error {
	if !p.lifecycle.Acquire() {
		return errors.New("portal is closed")
	}
	defer p.lifecycle.Release()
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return errors.New("outbound metadata not found").AtError()
	}

	if isDomain(ob.Target, p.domain) {
		muxClient, err := mux.NewClientWorker(*link, mux.ClientStrategy{})
		if err != nil {
			return errors.New("failed to create mux client worker").Base(err).AtWarning()
		}

		worker, err := NewPortalWorker(muxClient)
		if err != nil {
			return errors.New("failed to create portal worker").Base(err)
		}

		if !p.picker.AddWorker(worker) {
			_ = worker.Close()
			return errors.New("portal is closed")
		}

		if _, ok := link.Reader.(*pipe.Reader); !ok {
			select {
			case <-ctx.Done():
			case <-muxClient.WaitClosed():
			}
		}
		return nil
	}

	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}

	return p.client.Dispatch(ctx, link)
}

type Outbound struct {
	portal *Portal
	tag    string
}

func (o *Outbound) Tag() string {
	return o.tag
}

func (o *Outbound) Dispatch(ctx context.Context, link *transport.Link) {
	if err := o.portal.HandleConnection(ctx, link); err != nil {
		errors.LogInfoInner(ctx, err, "failed to process reverse connection")
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	}
}

func (o *Outbound) Start() error {
	return nil
}

func (o *Outbound) Close() error {
	if o == nil || o.portal == nil {
		return nil
	}
	return o.portal.closeFromHandler(o)
}

// SenderSettings implements outbound.Handler.
func (o *Outbound) SenderSettings() *serial.TypedMessage {
	return nil
}

// ProxySettings implements outbound.Handler.
func (o *Outbound) ProxySettings() *serial.TypedMessage {
	return nil
}

type StaticMuxPicker struct {
	access    sync.Mutex
	workers   []*PortalWorker
	cTask     *task.Periodic
	sealed    bool
	stopOnce  sync.Once
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func NewStaticMuxPicker() (*StaticMuxPicker, error) {
	p := &StaticMuxPicker{closeDone: make(chan struct{})}
	p.cTask = &task.Periodic{
		Execute:  p.cleanup,
		Interval: time.Second * 30,
	}
	p.cTask.Start()
	return p, nil
}

func (p *StaticMuxPicker) cleanup() error {
	p.access.Lock()
	if p.sealed {
		p.access.Unlock()
		return nil
	}

	var activeWorkers []*PortalWorker
	var closedWorkers []*PortalWorker
	for _, w := range p.workers {
		if !w.Closed() {
			activeWorkers = append(activeWorkers, w)
		} else {
			closedWorkers = append(closedWorkers, w)
		}
	}

	if len(activeWorkers) != len(p.workers) {
		p.workers = activeWorkers
	}
	p.access.Unlock()
	for _, worker := range closedWorkers {
		worker.SignalStop()
	}
	for _, worker := range closedWorkers {
		_ = worker.Close()
	}

	return nil
}

func (p *StaticMuxPicker) PickAvailable() (*mux.ClientWorker, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if p.sealed {
		return nil, errors.New("mux picker is closed")
	}

	if len(p.workers) == 0 {
		return nil, errors.New("empty worker list")
	}

	var minIdx int = -1
	var minConn uint32 = 9999
	for i, w := range p.workers {
		if w.Draining() {
			continue
		}
		if w.IsFull() {
			continue
		}
		if w.client.ActiveConnections() < minConn {
			minConn = w.client.ActiveConnections()
			minIdx = i
		}
	}

	if minIdx == -1 {
		for i, w := range p.workers {
			if w.IsFull() {
				continue
			}
			if w.client.ActiveConnections() < minConn {
				minConn = w.client.ActiveConnections()
				minIdx = i
			}
		}
	}

	if minIdx != -1 {
		return p.workers[minIdx].client, nil
	}

	return nil, errors.New("no mux client worker available")
}

func (p *StaticMuxPicker) AddWorker(worker *PortalWorker) bool {
	p.access.Lock()
	defer p.access.Unlock()
	if p.sealed {
		return false
	}
	p.workers = append(p.workers, worker)
	return true
}

func (p *StaticMuxPicker) SignalStop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		p.access.Lock()
		p.sealed = true
		workers := append([]*PortalWorker(nil), p.workers...)
		p.access.Unlock()
		_ = p.cTask.Close()
		for _, worker := range workers {
			worker.SignalStop()
		}
	})
}

func (p *StaticMuxPicker) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.SignalStop()
		p.access.Lock()
		workers := append([]*PortalWorker(nil), p.workers...)
		p.access.Unlock()
		var errs []error
		errs = append(errs, p.cTask.CloseAndWait())
		for _, worker := range workers {
			errs = append(errs, worker.Close())
		}
		p.access.Lock()
		p.workers = nil
		p.closeErr = errors.Combine(errs...)
		close(p.closeDone)
		p.access.Unlock()
	})
	p.access.Lock()
	done := p.closeDone
	p.access.Unlock()
	<-done
	p.access.Lock()
	defer p.access.Unlock()
	return p.closeErr
}

type PortalWorker struct {
	access    sync.Mutex
	client    *mux.ClientWorker
	control   *task.Periodic
	writer    buf.Writer
	reader    buf.Reader
	cancel    context.CancelFunc
	draining  bool
	counter   uint32
	timer     *signal.ActivityTimer
	stopOnce  sync.Once
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func NewPortalWorker(client *mux.ClientWorker) (*PortalWorker, error) {
	opt := []pipe.Option{pipe.WithSizeLimit(16 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	ctx, cancel := context.WithCancel(context.Background())
	outbounds := []*session.Outbound{{
		Target: net.UDPDestination(net.DomainAddress(internalDomain), 0),
	}}
	ctx = session.ContextWithOutbounds(ctx, outbounds)
	f := client.Dispatch(ctx, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if !f {
		cancel()
		common.Interrupt(uplinkReader)
		common.Interrupt(uplinkWriter)
		common.Interrupt(downlinkReader)
		common.Interrupt(downlinkWriter)
		_ = client.Close()
		client.Wait()
		return nil, errors.New("unable to dispatch control connection")
	}
	terminate := func() {
		client.Close()
	}
	w := &PortalWorker{
		client:    client,
		reader:    downlinkReader,
		writer:    uplinkWriter,
		timer:     signal.CancelAfterInactivity(ctx, terminate, 24*time.Hour), // // prevent leak
		closeDone: make(chan struct{}),
		cancel:    cancel,
	}
	w.control = &task.Periodic{
		Execute:  w.heartbeat,
		Interval: time.Second * 2,
	}
	if err := w.control.Start(); err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

func (w *PortalWorker) heartbeat() error {
	w.access.Lock()
	if w.Closed() {
		w.access.Unlock()
		return errors.New("client worker stopped")
	}

	if w.draining || w.writer == nil {
		w.access.Unlock()
		return errors.New("already disposed")
	}

	msg := &Control{}
	msg.FillInRandom()

	if w.client.TotalConnections() > 256 {
		w.draining = true
		msg.State = Control_DRAIN
	}

	w.counter = (w.counter + 1) % 5
	if w.draining || w.counter == 1 {
		b, err := proto.Marshal(msg)
		common.Must(err)
		mb := buf.MergeBytes(nil, b)
		w.timer.Update()
		writer := w.writer
		reader := w.reader
		draining := w.draining
		if draining {
			w.writer = nil
		}
		w.access.Unlock()
		if draining {
			defer common.Close(writer)
			defer common.Interrupt(reader)
		}
		return writer.WriteMultiBuffer(mb)
	}
	w.access.Unlock()
	return nil
}

func (w *PortalWorker) SignalStop() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() {
		if w.control != nil {
			_ = w.control.Close()
		}
		if w.cancel != nil {
			w.cancel()
		}
		w.access.Lock()
		writer := w.writer
		reader := w.reader
		w.writer = nil
		w.draining = true
		w.access.Unlock()
		common.Close(writer)
		common.Interrupt(reader)
		_ = w.client.Close()
	})
}

func (w *PortalWorker) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		w.SignalStop()
		var errs []error
		if w.timer != nil {
			errs = append(errs, w.timer.CloseAndWait())
		}
		if w.control != nil {
			errs = append(errs, w.control.CloseAndWait())
		}
		w.client.Wait()
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

func (w *PortalWorker) IsFull() bool {
	return w.client.IsFull()
}

func (w *PortalWorker) Draining() bool {
	w.access.Lock()
	defer w.access.Unlock()
	return w.draining
}

func (w *PortalWorker) Closed() bool {
	return w.client.Closed()
}
