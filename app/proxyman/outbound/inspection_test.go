package outbound

import (
	"context"
	"errors"
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
}

func (h *inspectionHandler) Tag() string  { return h.tag }
func (h *inspectionHandler) Start() error { return h.startErr }
func (h *inspectionHandler) Close() error { h.closes++; return nil }

func TestInspectionNativeHandlerReplacement(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	first := &inspectionHandler{tag: "reused"}
	if err = m.AddHandler(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	h := m.GetHandler("reused")
	if h != first {
		t.Fatal("entry missing")
	}
	def := m.GetDefaultHandler()
	if def != first {
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
	h = m.GetHandler("reused")
	if h != second {
		t.Fatal("replacement handler missing")
	}
	if err = m.Start(); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("native start failure")
	failed := &inspectionHandler{tag: "registered-before-start", startErr: failure}
	if err = m.AddHandler(context.Background(), failed); !errors.Is(err, failure) {
		t.Fatalf("start result: %v", err)
	}
	h = m.GetHandler(failed.tag)
	if h != failed {
		t.Fatal("failed Start lost native registered entry")
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
				h := m.GetHandler("same")
				if h != nil && h.Tag() != "same" {
					t.Errorf("unexpected handler tag: %q", h.Tag())
					return
				}
				m.Select([]string{"same"})
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	for i := 0; i < 500; i++ {
		h := &inspectionHandler{tag: "same"}
		if err = m.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if err = m.RemoveHandler(context.Background(), "same"); err != nil {
			t.Fatal(err)
		}
	}
}
