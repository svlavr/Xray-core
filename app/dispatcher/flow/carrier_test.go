package flow

import (
	"context"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
)

type carrierTestHandler struct{}

func (*carrierTestHandler) Start() error                              { return nil }
func (*carrierTestHandler) Close() error                              { return nil }
func (*carrierTestHandler) Tag() string                               { return "carrier-test" }
func (*carrierTestHandler) Dispatch(context.Context, *transport.Link) {}
func (*carrierTestHandler) SenderSettings() *serial.TypedMessage      { panic("must not be called") }

func (*carrierTestHandler) ProxySettings() *serial.TypedMessage { panic("must not be called") }

// The struct type is comparable, but this value is not because its interface
// field contains a slice. reflect.Type.Comparable alone does not catch it.
type incomparableCarrierTestHandler struct{ state any }

func (incomparableCarrierTestHandler) Start() error                              { return nil }
func (incomparableCarrierTestHandler) Close() error                              { return nil }
func (incomparableCarrierTestHandler) Tag() string                               { return "incomparable" }
func (incomparableCarrierTestHandler) Dispatch(context.Context, *transport.Link) {}
func (incomparableCarrierTestHandler) SenderSettings() *serial.TypedMessage {
	panic("must not be called")
}

func (incomparableCarrierTestHandler) ProxySettings() *serial.TypedMessage {
	panic("must not be called")
}

func TestHandlerCarrierObservationBindingLifecycle(t *testing.T) {
	handler := &carrierTestHandler{}
	observation := CarrierObservation{Proof: CarrierProofProven}
	firstRelease := BindHandlerCarrierObservation(handler, observation)
	secondRelease := BindHandlerCarrierObservation(handler, observation)

	if got, ok := HandlerCarrierObservation(handler); !ok || got != observation {
		t.Fatalf("bound carrier observation = (%+v, %v), want (%+v, true)", got, ok, observation)
	}
	firstRelease()
	if got, ok := HandlerCarrierObservation(handler); !ok || got != observation {
		t.Fatalf("shared carrier observation was released early: (%+v, %v)", got, ok)
	}
	firstRelease()
	secondRelease()
	if _, ok := HandlerCarrierObservation(handler); ok {
		t.Fatal("carrier observation remained after final release")
	}
}

func TestIncomparableHandlerCarrierObservationFailsClosed(t *testing.T) {
	handler := incomparableCarrierTestHandler{state: []byte("not comparable")}
	release := BindHandlerCarrierObservation(handler, CarrierObservation{Proof: CarrierProofProven})
	release()
	if _, ok := HandlerCarrierObservation(handler); ok {
		t.Fatal("incomparable handler carrier observation did not fail closed")
	}
}

func TestHandlerCarrierObservationConflictFailsClosed(t *testing.T) {
	handler := &carrierTestHandler{}
	firstRelease := BindHandlerCarrierObservation(handler, CarrierObservation{Proof: CarrierProofProven})
	secondRelease := BindHandlerCarrierObservation(handler, CarrierObservation{Proof: CarrierProofUnknown, MuxF2Required: true})
	defer firstRelease()
	defer secondRelease()

	if _, ok := HandlerCarrierObservation(handler); ok {
		t.Fatal("conflicting carrier observations did not fail closed")
	}
}

func TestHandlerCarrierObservationConcurrentConflictFailsClosed(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		handler := &carrierTestHandler{}
		firstRelease := BindHandlerCarrierObservation(handler, CarrierObservation{Proof: CarrierProofProven})
		start := make(chan struct{})
		var readers sync.WaitGroup
		for reader := 0; reader < 4; reader++ {
			readers.Add(1)
			go func() {
				defer readers.Done()
				<-start
				for lookup := 0; lookup < 100; lookup++ {
					HandlerCarrierObservation(handler)
				}
			}()
		}
		close(start)
		secondRelease := BindHandlerCarrierObservation(handler, CarrierObservation{Proof: CarrierProofUnknown, MuxF2Required: true})
		readers.Wait()
		if _, ok := HandlerCarrierObservation(handler); ok {
			t.Fatal("concurrent conflicting carrier observations did not fail closed")
		}
		secondRelease()
		firstRelease()
	}
}

func TestHandlerCarrierObservationConcurrentReleaseFailsClosed(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		handler := &carrierTestHandler{}
		release := BindHandlerCarrierObservation(handler, CarrierObservation{Proof: CarrierProofProven})
		start := make(chan struct{})
		var readers sync.WaitGroup
		for reader := 0; reader < 4; reader++ {
			readers.Add(1)
			go func() {
				defer readers.Done()
				<-start
				for lookup := 0; lookup < 100; lookup++ {
					HandlerCarrierObservation(handler)
				}
			}()
		}
		close(start)
		release()
		readers.Wait()
		if _, ok := HandlerCarrierObservation(handler); ok {
			t.Fatal("carrier observation remained after concurrent release")
		}
	}
}
