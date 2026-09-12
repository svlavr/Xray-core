package inbound

import (
	"context"
	stderrors "errors"
	"sync/atomic"
	"testing"

	proxymanoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	feature "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
)

type vlessReverseTestOutbound struct{ tag string }

func (*vlessReverseTestOutbound) Start() error                              { return nil }
func (*vlessReverseTestOutbound) Close() error                              { return nil }
func (h *vlessReverseTestOutbound) Tag() string                             { return h.tag }
func (*vlessReverseTestOutbound) Dispatch(context.Context, *transport.Link) {}
func (*vlessReverseTestOutbound) SenderSettings() *serial.TypedMessage      { return nil }
func (*vlessReverseTestOutbound) ProxySettings() *serial.TypedMessage       { return nil }

func reverseTestUser(email, tag string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email: email,
		Account: &vless.MemoryAccount{
			ID:      protocol.NewID(uuid.New()),
			Reverse: &vless.Reverse{Tag: tag},
		},
	}
}

func TestConfiguredReverseBindingsRegisterAtStartAndShareExactHandler(t *testing.T) {
	manager, err := proxymanoutbound.New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := &vlessReverseTestOutbound{tag: "ordinary"}
	if err := manager.AddHandler(context.Background(), ordinary); err != nil {
		t.Fatal(err)
	}
	validator := new(vless.MemoryValidator)
	first := reverseTestUser("first@example.test", "reverse")
	second := reverseTestUser("second@example.test", "reverse")
	if err := validator.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(second); err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		validator:              validator,
		outboundHandlerManager: manager,
		ctx:                    context.Background(),
		reverseBindings:        make(map[*protocol.MemoryUser]*reverseBinding),
		pendingReverse:         []*protocol.MemoryUser{first, second},
	}
	if got := manager.GetDefaultHandler(); got != ordinary {
		t.Fatal("test setup has no ordinary default outbound")
	}
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	if got := manager.GetDefaultHandler(); got != ordinary {
		t.Fatal("synthetic reverse replaced the ordinary default")
	}
	if len(h.reverseBindings) != 2 || h.reverseBindings[first].reverse != h.reverseBindings[second].reverse {
		t.Fatal("configured bindings did not share one exact Reverse")
	}
	if err := h.RemoveUser(context.Background(), first.Email); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("reverse") == nil {
		t.Fatal("non-last binding removal retired shared Reverse")
	}
	if err := h.RemoveUser(context.Background(), second.Email); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("reverse") != nil {
		t.Fatal("last binding removal retained shared Reverse")
	}
}

func TestReverseStartFailureRollsBackEarlierSyntheticBinding(t *testing.T) {
	manager, _ := proxymanoutbound.New(context.Background(), nil)
	ordinary := &vlessReverseTestOutbound{tag: "ordinary"}
	if err := manager.AddHandler(context.Background(), ordinary); err != nil {
		t.Fatal(err)
	}
	validator := new(vless.MemoryValidator)
	first := reverseTestUser("first@example.test", "reverse-first")
	conflict := reverseTestUser("conflict@example.test", ordinary.tag)
	if err := validator.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(conflict); err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		validator:              validator,
		outboundHandlerManager: manager,
		ctx:                    context.Background(),
		reverseBindings:        make(map[*protocol.MemoryUser]*reverseBinding),
		pendingReverse:         []*protocol.MemoryUser{first, conflict},
	}
	if err := h.Start(); err == nil {
		t.Fatal("conflicting later binding did not fail Start")
	}
	if h.started {
		t.Fatal("failed Start committed started state")
	}
	if len(h.reverseBindings) != 0 || manager.GetHandler("reverse-first") != nil {
		t.Fatal("failed Start retained an earlier synthetic binding")
	}
	if got := manager.GetHandler(ordinary.tag); got != ordinary {
		t.Fatal("failed Start changed the conflicting ordinary outbound")
	}
}

type scriptedReverseRegistration struct {
	handler  feature.Handler
	releases atomic.Int32
	failOnce atomic.Bool
	err      error
}

func (r *scriptedReverseRegistration) Handler() feature.Handler { return r.handler }
func (*scriptedReverseRegistration) Enter(context.Context) (feature.HandlerEntry, error) {
	return nil, stderrors.New("not used")
}

func (r *scriptedReverseRegistration) Release(context.Context) error {
	r.releases.Add(1)
	if r.failOnce.CompareAndSwap(true, false) {
		return r.err
	}
	return nil
}

func TestPrepareCloseKeepsPartialFailureReachableAndRetryable(t *testing.T) {
	want := stderrors.New("capacity")
	first := reverseTestUser("first@example.test", "first")
	second := reverseTestUser("second@example.test", "second")
	firstRegistration := &scriptedReverseRegistration{handler: &vlessReverseTestOutbound{tag: "first"}}
	secondRegistration := &scriptedReverseRegistration{handler: &vlessReverseTestOutbound{tag: "second"}, err: want}
	secondRegistration.failOnce.Store(true)
	h := &Handler{
		reverseBindings: map[*protocol.MemoryUser]*reverseBinding{
			first:  {registration: firstRegistration},
			second: {registration: secondRegistration},
		},
	}
	if err := h.PrepareClose(); !stderrors.Is(err, want) {
		t.Fatalf("PrepareClose error = %v, want %v", err, want)
	}
	if h.reversePhase != reverseLifecycleClosing {
		t.Fatalf("phase = %d, want CLOSING", h.reversePhase)
	}
	if len(h.reverseBindings) != 1 || h.reverseBindings[second] == nil {
		t.Fatal("partial failure lost the remaining exact token")
	}
	if err := h.AddUser(context.Background(), reverseTestUser("late@example.test", "late")); err == nil {
		t.Fatal("closing handler admitted a late binding")
	}
	if err := h.PrepareClose(); err != nil {
		t.Fatalf("explicit cleanup retry = %v", err)
	}
	if len(h.reverseBindings) != 0 {
		t.Fatal("retry retained a released registration")
	}
	if firstRegistration.releases.Load() != 1 || secondRegistration.releases.Load() != 2 {
		t.Fatalf("release attempts = (%d,%d), want (1,2)", firstRegistration.releases.Load(), secondRegistration.releases.Load())
	}
}
