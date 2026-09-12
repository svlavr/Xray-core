package session

import (
	"context"
	"errors"
	"testing"
)

type multiplexedContextTestKey struct{}

type multiplexedContextFeedback struct {
	errors int
}

func (f *multiplexedContextFeedback) SubmitError(error) {
	f.errors++
}

func TestMultiplexedLogicalSessionMarkerPreservesParentContext(t *testing.T) {
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), multiplexedContextTestKey{}, "kept"))
	feedback := new(multiplexedContextFeedback)
	parent = TrackedConnectionError(parent, feedback)
	marked := ContextWithMultiplexedLogicalSession(parent)

	if !IsMultiplexedLogicalSession(marked) || marked.Value(multiplexedContextTestKey{}) != "kept" {
		t.Fatal("decoded MUX marker lost its identity or an unrelated context value")
	}
	SubmitOutboundErrorToOriginator(marked, errors.New("child error"))
	if feedback.errors != 1 {
		t.Fatalf("decoded MUX marker lost upstream error feedback: got %d submissions", feedback.errors)
	}
	cancel()
	if !errors.Is(marked.Err(), context.Canceled) {
		t.Fatalf("decoded MUX marker lost parent cancellation: %v", marked.Err())
	}
}
