package dispatcher_test

import (
	"io"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestStatsWriterForwardsCancellation(t *testing.T) {
	r, w := pipe.New()
	defer r.Interrupt()
	var counter TestCounter
	writer := &dispatcher.SizeStatWriter{Writer: w, Counter: &counter}
	stop := make(chan struct{})
	close(stop)
	err := writer.WriteMultiBufferStop(buf.MultiBuffer{buf.FromBytes([]byte("offered"))}, stop)
	if err != io.EOF || counter.Value() != 7 {
		t.Fatalf("canceled native offer: %v %d", err, counter.Value())
	}
	if err := writer.WriteMultiBufferStop(buf.MultiBuffer{buf.FromBytes([]byte("next"))}, nil); err != nil {
		t.Fatal(err)
	}
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "next" || counter.Value() != 11 {
		t.Fatalf("native continuation: %s %v %d", mb.String(), err, counter.Value())
	}
}
