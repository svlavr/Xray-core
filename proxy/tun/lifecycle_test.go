package tun

import "testing"

func TestHandlerUnregisterDialerControllerIsIdempotent(t *testing.T) {
	called := 0
	handler := &Handler{unregisterController: func() { called++ }}
	handler.unregisterDialerController()
	handler.unregisterDialerController()
	if called != 1 {
		t.Fatalf("unregister calls = %d, want 1", called)
	}
}
