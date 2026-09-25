package outbound

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	fout "github.com/xtls/xray-core/features/outbound"
)

type inspectionHandler struct {
	fout.Handler
	tag      string
	startErr error
	closes   int
	ordinal  uint64
}

func (h *inspectionHandler) Tag() string  { return h.tag }
func (h *inspectionHandler) Start() error { return h.startErr }
func (h *inspectionHandler) Close() error { h.closes++; return nil }

func TestInspectionHandlerIncarnation(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	first := &inspectionHandler{tag: "reused"}
	if err = m.AddHandler(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	h, id := m.ResolveHandler("reused", false)
	if h != first || id == 0 {
		t.Fatal("entry missing")
	}
	def, defID := m.ResolveHandler("", true)
	if def != first || defID != id {
		t.Fatal("default identity differs")
	}
	if err = m.RemoveHandler(context.Background(), "reused"); err != nil {
		t.Fatal(err)
	}
	if first.closes != 0 {
		t.Fatal("removal unexpectedly closed handler")
	}
	second := &inspectionHandler{tag: "reused"}
	if err = m.AddHandler(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	h, next := m.ResolveHandler("reused", false)
	if h != second || next <= id {
		t.Fatal("serial reused")
	}
	if err = m.Start(); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("native start failure")
	failed := &inspectionHandler{tag: "registered-before-start", startErr: failure}
	if err = m.AddHandler(context.Background(), failed); !errors.Is(err, failure) {
		t.Fatalf("start result: %v", err)
	}
	h, failedID := m.ResolveHandler(failed.tag, false)
	if h != failed || failedID <= next {
		t.Fatal("failed Start lost native registered entry")
	}
	m.nextSerial = math.MaxUint64
	exhausted := &inspectionHandler{tag: "exhausted"}
	if err = m.AddHandler(context.Background(), exhausted); err != nil {
		t.Fatal(err)
	}
	if h, id = m.ResolveHandler(exhausted.tag, false); h != exhausted || id != 0 {
		t.Fatal("exhaustion changed routing or wrapped identity")
	}
}

func TestInspectionConcurrentNativeEntries(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				h, id := m.ResolveHandler("same", false)
				if h != nil && id != h.(*inspectionHandler).ordinal {
					t.Errorf("mixed handler/serial: %d", id)
					return
				}
				m.Select([]string{"same"})
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	for i := uint64(1); i <= 500; i++ {
		h := &inspectionHandler{tag: "same", ordinal: i}
		if err = m.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if err = m.RemoveHandler(context.Background(), "same"); err != nil {
			t.Fatal(err)
		}
	}
}
