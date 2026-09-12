package internet

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type blockingAdapter struct {
	release <-chan struct{}
	conn    net.Conn
}

type boundLifecycleResource struct {
	mu         sync.Mutex
	unregister func()
	closed     chan struct{}
	closeOnce  sync.Once
}

func (*boundLifecycleResource) SignalStop() {}
func (r *boundLifecycleResource) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		unregister := r.unregister
		r.mu.Unlock()
		if unregister == nil {
			panic("resource closed before unregister token binding")
		}
		unregister()
		close(r.closed)
	})
	<-r.closed
	return nil
}

func TestResourceLifecycleBindsUnregisterBeforeOwnerPublication(t *testing.T) {
	owner := NewResourceLifecycle(context.Background())
	resource := &boundLifecycleResource{closed: make(chan struct{})}
	binderEntered := make(chan struct{})
	releaseBinder := make(chan struct{})
	registered := make(chan error, 1)
	go func() {
		registered <- owner.RegisterBound(resource, func(unregister func()) {
			close(binderEntered)
			<-releaseBinder
			resource.mu.Lock()
			resource.unregister = unregister
			resource.mu.Unlock()
		})
	}()
	<-binderEntered
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.CloseAndWait() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner close waited for an unpublished resource binder")
	}
	close(releaseBinder)
	if err := <-registered; err == nil {
		t.Fatal("registration published after owner seal")
	}
	select {
	case <-resource.closed:
		t.Fatal("owner observed resource before token binding")
	default:
	}
}

func (a blockingAdapter) Dial(string, string) (net.Conn, error) { <-a.release; return a.conn, nil }

func TestSimpleSystemDialerRemainsSynchronous(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	release := make(chan struct{})
	dialer := WithAdapter(blockingAdapter{release: release, conn: client})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := dialer.Dial(ctx, nil, xnet.TCPDestination(xnet.LocalHostIP, 1), nil)
		result <- err
	}()
	cancel()
	select {
	case <-result:
		t.Fatal("adapter returned before synchronous call completed")
	default:
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("late adapter result error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adapter did not complete")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late adapter connection remained open after lifecycle cancellation")
	}
}

func TestRegisterDialerControllerRejectsCustomDialerWithoutMutation(t *testing.T) {
	dialerLock.RLock()
	oldDialer := effectiveSystemDialer
	dialerLock.RUnlock()
	ControllersLock.Lock()
	oldControllers := append([]func(string, string, syscall.RawConn) error(nil), Controllers...)
	ControllersLock.Unlock()
	t.Cleanup(func() {
		UseAlternativeSystemDialer(oldDialer)
		ControllersLock.Lock()
		Controllers = oldControllers
		ControllersLock.Unlock()
	})
	UseAlternativeSystemDialer(WithAdapter(blockingAdapter{release: make(chan struct{})}))
	if err := RegisterDialerController(func(string, string, syscall.RawConn) error { return nil }); err == nil {
		t.Fatal("RegisterDialerController accepted custom dialer")
	}
	ControllersLock.Lock()
	got := len(Controllers)
	ControllersLock.Unlock()
	if got != len(oldControllers) {
		t.Fatalf("controller list mutated: got %d, want %d", got, len(oldControllers))
	}
}

func TestInstanceDialLifecycleSnapshotsLegacyDialerAndControllersOnce(t *testing.T) {
	dialerLock.RLock()
	oldDialer := effectiveSystemDialer
	dialerLock.RUnlock()
	ControllersLock.Lock()
	oldControllers := append([]func(string, string, syscall.RawConn) error(nil), Controllers...)
	ControllersLock.Unlock()
	t.Cleanup(func() {
		UseAlternativeSystemDialer(oldDialer)
		ControllersLock.Lock()
		Controllers = oldControllers
		ControllersLock.Unlock()
	})
	UseAlternativeSystemDialer(WithAdapter(blockingAdapter{release: make(chan struct{})}))
	ControllersLock.Lock()
	Controllers = append(Controllers, func(string, string, syscall.RawConn) error { return nil })
	ControllersLock.Unlock()

	lifecycle := NewDialLifecycle()
	if err := lifecycle.Configure(nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithDialLifecycle(context.Background(), lifecycle)
	operationCtx, release, err := WithDialOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	snapshot := snapshotForContext(operationCtx)
	if _, ok := snapshot.dialer.(*SimpleSystemDialer); !ok {
		t.Fatalf("Instance dialer = %T, want exact configured legacy dialer snapshot", snapshot.dialer)
	}
	if want := len(oldControllers) + 1; len(snapshot.controllers) != want {
		t.Fatalf("Instance snapshot controllers = %d, want %d construction-time legacy controllers", len(snapshot.controllers), want)
	}
}

func TestLifecycleControllerTokenKeepsAdmittedSnapshot(t *testing.T) {
	lifecycle := NewDialLifecycle()
	if err := lifecycle.Configure(nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithDialLifecycle(context.Background(), lifecycle)
	first := func(string, string, syscall.RawConn) error { return nil }
	second := func(string, string, syscall.RawConn) error { return nil }
	unregisterFirst, err := RegisterDialerControllerContext(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, releaseFirst, err := WithDialOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unregistered := make(chan struct{})
	go func() {
		unregisterFirst()
		close(unregistered)
	}()
	for {
		lifecycle.mu.Lock()
		remaining := len(lifecycle.controllers)
		lifecycle.mu.Unlock()
		if remaining == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := RegisterDialerControllerContext(ctx, second); err != nil {
		t.Fatal(err)
	}
	secondCtx, releaseSecond, err := WithDialOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()
	if got := snapshotForContext(firstCtx).controllers; len(got) != 1 || reflect.ValueOf(got[0]).Pointer() != reflect.ValueOf(first).Pointer() {
		t.Fatal("admitted snapshot lost its exact controller")
	}
	if got := snapshotForContext(secondCtx).controllers; len(got) != 1 || reflect.ValueOf(got[0]).Pointer() != reflect.ValueOf(second).Pointer() {
		t.Fatal("replacement snapshot does not contain exact controller")
	}
	releaseFirst()
	select {
	case <-unregistered:
	case <-time.After(time.Second):
		t.Fatal("controller unregister did not receive the admitted snapshot receipt")
	}
}

func TestDetachedContextCannotDialAfterLifecycleSeal(t *testing.T) {
	lifecycle := NewDialLifecycle()
	if err := lifecycle.Configure(nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithDialLifecycle(context.Background(), lifecycle)
	operationCtx, release, err := WithDialOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	detached := context.WithoutCancel(operationCtx)
	lifecycle.Seal()
	if _, nestedRelease, err := WithDialOperation(detached); err == nil {
		nestedRelease()
		t.Fatal("detached operation admitted work after lifecycle seal")
	}
}

func TestLifecycleConnectionCloseWaitsForPublicationMetadata(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	released := make(chan struct{})
	connection := ownStatConnection(client, func() {})
	closed := make(chan error, 1)
	go func() { closed <- connection.Close() }()
	select {
	case <-closed:
		t.Fatal("Close completed before lifecycle metadata commit")
	case <-time.After(20 * time.Millisecond):
	}
	connection.resourceRelease = func() { close(released) }
	connection.commit(func() bool { return false })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after lifecycle metadata commit")
	}
	select {
	case <-released:
	default:
		t.Fatal("committed resource release hook was skipped")
	}
}

func TestControllerUnregisterWaitsForAdmittedUse(t *testing.T) {
	lifecycle := NewDialLifecycle()
	if err := lifecycle.Configure(nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithDialLifecycle(context.Background(), lifecycle)
	unregister, err := RegisterDialerControllerContext(ctx, func(string, string, syscall.RawConn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := WithDialOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { unregister(); close(done) }()
	select {
	case <-done:
		t.Fatal("unregister returned before admitted controller use released")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unregister did not complete after controller use receipt")
	}
}
