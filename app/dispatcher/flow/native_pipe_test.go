package flow

import (
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestNativePipeCountsAcceptedBytesAndWaitsForDrain(t *testing.T) {
	root := newTestRoot(t)
	reader, writer := pipe.New(pipe.WithWriteLifecycle(NativePipeLifecycle(root.Uplink())))
	payload := buf.New()
	payload.WriteString("accepted")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	if got := root.View(); testObservation(t, got.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes != (OptionalUint64{Known: true, Value: 8}) {
		t.Fatalf("accepted bytes were not recorded: %+v", got)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if got := root.View().UplinkState; got != DirectionStateSealed {
		t.Fatalf("got %s, want sealed while accepted buffer remains", got)
	}
	data, err := reader.ReadMultiBuffer()
	if err != nil || data.String() != "accepted" {
		t.Fatalf("unexpected drain result data=%q err=%v", data.String(), err)
	}
	if got := root.View().UplinkState; got != DirectionStateQuiescent {
		t.Fatalf("got %s, want quiescent after drain", got)
	}
	if data, err = reader.ReadMultiBuffer(); err != io.EOF || !data.IsEmpty() {
		t.Fatalf("stock EOF changed: data=%v err=%v", data, err)
	}
}

func TestNativePipeInterruptDiscardsBeforeQuiescence(t *testing.T) {
	root := newTestRoot(t)
	reader, writer := pipe.New(pipe.WithWriteLifecycle(NativePipeLifecycle(root.Downlink())))
	payload := buf.New()
	payload.WriteString("discarded")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	reader.Interrupt()
	if got := root.View().DownlinkState; got != DirectionStateQuiescent {
		t.Fatalf("got %s, want quiescent after stock discard", got)
	}
	if data, err := reader.ReadMultiBuffer(); err != io.ErrClosedPipe || !data.IsEmpty() {
		t.Fatalf("stock interrupt changed: data=%v err=%v", data, err)
	}
}
