package flow

import "testing"

func TestMuxClientAuthorityMintsBeforeCloseAndRejectsAfterClose(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	first := r.NewMuxClientCarrierObservation()
	second := r.NewMuxClientCarrierObservation()
	if first == nil || second == nil || first.(*MuxClientCarrier).reference == second.(*MuxClientCarrier).reference {
		t.Fatal("early authorities were not uniquely minted")
	}
	r.Close()
	if got := r.NewMuxClientCarrierObservation(); got != nil {
		t.Fatal("registry minted authority after close")
	}
}
