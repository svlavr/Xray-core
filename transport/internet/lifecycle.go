package internet

import (
	"context"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
)

var nextResourceLifecycleID atomic.Uint64

// LifecycleResource is one cached/config-generation transport resource. Its
// stop phase must not wait; Close returns only after its own receipts finish.
type LifecycleResource interface {
	SignalStop()
	Close() error
}

type ResourceLifecycle struct {
	mu        sync.Mutex
	id        uint64
	ctx       context.Context
	cancel    context.CancelFunc
	sealed    bool
	next      uint64
	resources map[uint64]LifecycleResource
	stopOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}
	closeErr  error
}

type resourceLifecycleKey struct{}

func NewResourceLifecycle(ctx context.Context) *ResourceLifecycle {
	base := context.WithoutCancel(ctx)
	resourceCtx, cancel := context.WithCancel(base)
	lifecycle := &ResourceLifecycle{
		id:        nextResourceLifecycleID.Add(1),
		ctx:       resourceCtx,
		cancel:    cancel,
		resources: make(map[uint64]LifecycleResource),
		done:      make(chan struct{}),
	}
	lifecycle.ctx = context.WithValue(lifecycle.ctx, resourceLifecycleKey{}, lifecycle)
	return lifecycle
}

func ResourceLifecycleFromContext(ctx context.Context) *ResourceLifecycle {
	lifecycle, _ := ctx.Value(resourceLifecycleKey{}).(*ResourceLifecycle)
	return lifecycle
}

func ContextWithResourceLifecycle(ctx context.Context, lifecycle *ResourceLifecycle) context.Context {
	if lifecycle == nil {
		return ctx
	}
	return context.WithValue(ctx, resourceLifecycleKey{}, lifecycle)
}

func (l *ResourceLifecycle) Context() context.Context {
	if l == nil {
		return context.Background()
	}
	return l.ctx
}

func (l *ResourceLifecycle) ID() uint64 {
	if l == nil {
		return 0
	}
	return l.id
}

func (l *ResourceLifecycle) Register(resource LifecycleResource) (func(), error) {
	return l.register(resource, nil)
}

// RegisterBound publishes the exact unregister token to the resource before
// the owner can observe it. The binder must only store the token and return.
func (l *ResourceLifecycle) RegisterBound(resource LifecycleResource, bind func(func())) error {
	if bind == nil {
		return errors.New("transport resource unregister binder is unavailable")
	}
	_, err := l.register(resource, bind)
	return err
}

func (l *ResourceLifecycle) register(resource LifecycleResource, bind func(func())) (func(), error) {
	if l == nil || resource == nil {
		return nil, errors.New("transport resource lifecycle is unavailable")
	}
	l.mu.Lock()
	if l.sealed {
		l.mu.Unlock()
		return nil, errors.New("transport resource lifecycle is sealed")
	}
	id := l.next
	l.next++
	l.mu.Unlock()
	var once sync.Once
	unregister := func() {
		once.Do(func() {
			l.mu.Lock()
			if l.resources[id] == resource {
				delete(l.resources, id)
			}
			l.mu.Unlock()
		})
	}
	if bind != nil {
		bind(unregister)
	}
	l.mu.Lock()
	if l.sealed {
		l.mu.Unlock()
		return nil, errors.New("transport resource lifecycle sealed during registration")
	}
	l.resources[id] = resource
	l.mu.Unlock()
	return unregister, nil
}

func signalLifecycleResource(resource LifecycleResource) {
	defer func() { _ = recover() }()
	resource.SignalStop()
}

func closeLifecycleResource(resource LifecycleResource) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("transport resource close panic: ", recovered)
		}
	}()
	return resource.Close()
}

func (l *ResourceLifecycle) SignalStop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.sealed = true
		resources := make([]LifecycleResource, 0, len(l.resources))
		for _, resource := range l.resources {
			resources = append(resources, resource)
		}
		l.mu.Unlock()
		l.cancel()
		for _, resource := range resources {
			signalLifecycleResource(resource)
		}
	})
}

func (l *ResourceLifecycle) CloseAndWait() error {
	if l == nil {
		return nil
	}
	l.SignalStop()
	l.closeOnce.Do(func() {
		l.mu.Lock()
		resources := make([]LifecycleResource, 0, len(l.resources))
		for _, resource := range l.resources {
			resources = append(resources, resource)
		}
		l.mu.Unlock()
		results := make(chan error, len(resources))
		for _, resource := range resources {
			go func() { results <- closeLifecycleResource(resource) }()
		}
		var closeErrors []error
		for range resources {
			closeErrors = append(closeErrors, <-results)
		}
		l.mu.Lock()
		l.resources = make(map[uint64]LifecycleResource)
		l.closeErr = errors.Combine(closeErrors...)
		l.mu.Unlock()
		close(l.done)
	})
	<-l.done
	l.mu.Lock()
	err := l.closeErr
	l.mu.Unlock()
	return err
}

// DialLifecycle is owned by one core.Instance. Transport never imports core.
type DialLifecycle struct {
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	sealed, configured bool
	dns                dns.Client
	outbound           outbound.Manager
	dialer             SystemDialer
	controllers        map[uint64]*controllerRegistration
	legacyControllers  []func(string, string, syscall.RawConn) error
	controllerOrder    []uint64
	nextID, nextOpID   uint64
	operations         map[uint64]*dialOperation
	wg                 sync.WaitGroup
}

type dialOperation struct {
	lifecycle     *DialLifecycle
	id            uint64
	ctx           context.Context
	cancel        context.CancelFunc
	dns           dns.Client
	outbound      outbound.Manager
	dialer        SystemDialer
	controllers   []func(string, string, syscall.RawConn) error
	registrations []*controllerRegistration
	resources     map[uint64]io.Closer
	nextResource  uint64
	releaseOnce   sync.Once
}

type controllerRegistration struct {
	id       uint64
	callback func(string, string, syscall.RawConn) error
	uses     int
	retired  bool
	done     chan struct{}
}

type (
	dialLifecycleKey struct{}
	dialOperationKey struct{}
)

func NewDialLifecycle() *DialLifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return &DialLifecycle{ctx: ctx, cancel: cancel, controllers: make(map[uint64]*controllerRegistration), operations: make(map[uint64]*dialOperation)}
}

// Configure is the construction publication point. The Release-1 host leaves
// the selection at DefaultSystemDialer; the stable legacy alternative remains
// snapshot-compatible and is fenced against late result publication.
func (l *DialLifecycle) Configure(client dns.Client, manager outbound.Manager) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed || l.configured {
		return errors.New("dial lifecycle cannot be configured")
	}
	l.dns, l.outbound, l.dialer = client, manager, currentSystemDialer()
	ControllersLock.Lock()
	l.legacyControllers = append([]func(string, string, syscall.RawConn) error(nil), Controllers...)
	ControllersLock.Unlock()
	l.configured = true
	return nil
}

func ContextWithDialLifecycle(ctx context.Context, lifecycle *DialLifecycle) context.Context {
	if lifecycle == nil {
		return ctx
	}
	return context.WithValue(ctx, dialLifecycleKey{}, lifecycle)
}

func DialLifecycleFromContext(ctx context.Context) *DialLifecycle {
	lifecycle, _ := ctx.Value(dialLifecycleKey{}).(*DialLifecycle)
	return lifecycle
}

func snapshotForContext(ctx context.Context) *dialOperation {
	op, _ := ctx.Value(dialOperationKey{}).(*dialOperation)
	return op
}

// WithDialOperation captures exactly one immutable operation snapshot. Nested
// transport calls reuse it and must not re-admit or re-read mutable state.
func WithDialOperation(ctx context.Context) (context.Context, func(), error) {
	if op := snapshotForContext(ctx); op != nil {
		if err := op.ctx.Err(); err != nil {
			return nil, nil, err
		}
		nestedCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(op.ctx, cancel)
		return nestedCtx, func() { stop(); cancel() }, nil
	}
	l := DialLifecycleFromContext(ctx)
	if l == nil {
		return ctx, func() {}, nil
	}
	l.mu.Lock()
	if l.sealed || !l.configured {
		l.mu.Unlock()
		return nil, nil, errors.New("dial lifecycle is not admitting operations")
	}
	controllers := append([]func(string, string, syscall.RawConn) error(nil), l.legacyControllers...)
	registrations := make([]*controllerRegistration, 0, len(l.controllers))
	for _, controllerID := range l.controllerOrder {
		if registration := l.controllers[controllerID]; registration != nil {
			registration.uses++
			registrations = append(registrations, registration)
			controllers = append(controllers, registration.callback)
		}
	}
	id := l.nextOpID
	l.nextOpID++
	operationCtx, cancel := context.WithCancel(ctx)
	op := &dialOperation{lifecycle: l, id: id, ctx: operationCtx, cancel: cancel, dns: l.dns, outbound: l.outbound, dialer: l.dialer, controllers: controllers, registrations: registrations, resources: make(map[uint64]io.Closer)}
	l.operations[id] = op
	l.wg.Add(1)
	l.mu.Unlock()
	stop := context.AfterFunc(l.ctx, cancel)
	release := func() {
		op.releaseOnce.Do(func() {
			stop()
			cancel()
			l.mu.Lock()
			delete(l.operations, id)
			resources := make([]io.Closer, 0, len(op.resources))
			for _, resource := range op.resources {
				resources = append(resources, resource)
			}
			op.resources = nil
			l.mu.Unlock()
			var closeWG sync.WaitGroup
			for _, resource := range resources {
				closeWG.Add(1)
				go func() {
					defer closeWG.Done()
					if deadline, ok := resource.(interface{ SetDeadline(time.Time) error }); ok {
						_ = deadline.SetDeadline(time.Now())
					}
					_ = resource.Close()
				}()
			}
			closeWG.Wait()
			l.mu.Lock()
			for _, registration := range registrations {
				registration.uses--
				if registration.retired && registration.uses == 0 {
					close(registration.done)
				}
			}
			l.mu.Unlock()
			l.wg.Done()
		})
	}
	return context.WithValue(operationCtx, dialOperationKey{}, op), release, nil
}

func sameDialResource(left, right io.Closer) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftType := reflect.TypeOf(left)
	return leftType == reflect.TypeOf(right) && leftType.Comparable() && left == right
}

// AdoptDialResource makes the operation own a returned connection before it
// becomes visible to its caller. Operation cancellation closes all exact
// resources before releasing controller holds and the operation receipt.
func AdoptDialResource(ctx context.Context, resource io.Closer) (func(), func() error, error) {
	if resource == nil {
		return nil, nil, errors.New("nil dial resource")
	}
	op := snapshotForContext(ctx)
	if op == nil {
		return func() {}, func() error { return nil }, nil
	}
	l := op.lifecycle
	l.mu.Lock()
	if l.operations[op.id] != op || op.ctx.Err() != nil {
		l.mu.Unlock()
		return nil, nil, errors.New("dial operation no longer owns returned resource")
	}
	for _, existing := range op.resources {
		if sameDialResource(existing, resource) {
			l.mu.Unlock()
			return func() {}, func() error { return nil }, nil
		}
	}
	resourceID := op.nextResource
	op.nextResource++
	op.resources[resourceID] = resource
	l.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			l.mu.Lock()
			if sameDialResource(op.resources[resourceID], resource) {
				delete(op.resources, resourceID)
			}
			l.mu.Unlock()
		})
	}
	commit := func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.operations[op.id] != op || !sameDialResource(op.resources[resourceID], resource) || op.ctx.Err() != nil {
			return errors.New("dial operation sealed before resource publication")
		}
		return nil
	}
	return release, commit, nil
}

func DialOperationContext(ctx context.Context) context.Context {
	if operation := snapshotForContext(ctx); operation != nil {
		return operation.ctx
	}
	if lifecycle := DialLifecycleFromContext(ctx); lifecycle != nil {
		return lifecycle.ctx
	}
	return nil
}

func (l *DialLifecycle) Seal() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if !l.sealed {
		l.sealed = true
		l.cancel()
		for _, operation := range l.operations {
			operation.cancel()
		}
	}
	l.mu.Unlock()
}

func (l *DialLifecycle) Wait() {
	if l != nil {
		l.wg.Wait()
	}
}
func (l *DialLifecycle) IsSealed() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.sealed }

// RegisterDialerControllerContext returns an exact unregister token. It only
// affects future snapshots; already admitted operations retain their copy.
func RegisterDialerControllerContext(ctx context.Context, ctl func(string, string, syscall.RawConn) error) (func(), error) {
	if ctl == nil {
		return nil, errors.New("nil listener controller")
	}
	l := DialLifecycleFromContext(ctx)
	if l == nil {
		return nil, errors.New("dial lifecycle is unavailable")
	}
	l.mu.Lock()
	if l.sealed || !l.configured {
		l.mu.Unlock()
		return nil, errors.New("dial lifecycle is not admitting controller registrations")
	}
	id := l.nextID
	l.nextID++
	registration := &controllerRegistration{id: id, callback: ctl, done: make(chan struct{})}
	l.controllers[id] = registration
	l.controllerOrder = append(l.controllerOrder, id)
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.controllers, id)
			for index, controllerID := range l.controllerOrder {
				if controllerID == id {
					l.controllerOrder = append(l.controllerOrder[:index], l.controllerOrder[index+1:]...)
					break
				}
			}
			registration.retired = true
			if registration.uses == 0 {
				close(registration.done)
			}
			l.mu.Unlock()
			<-registration.done
		})
	}, nil
}

func lifecycleForContext(ctx context.Context) *DialLifecycle { return DialLifecycleFromContext(ctx) }
