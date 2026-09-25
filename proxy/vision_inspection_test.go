package proxy_test

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

func TestVisionDuplexState(t *testing.T) {
	// A server-first non-TLS banner can be classified while the other native
	// pump pads its first request. Neither direction waits for the other's I/O.
	for range 64 {
		state := proxy.NewTrafficState(bytes.Repeat([]byte{0xaa}, 16))
		reader := proxy.NewVisionReader(buf.NewReader(bytes.NewReader([]byte("server banner"))), state, false, context.Background(), nil, nil, nil, nil)
		writer := proxy.NewVisionWriter(buf.NewWriter(io.Discard), state, true, context.Background(), nil, nil, nil)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			mb, err := reader.ReadMultiBuffer()
			if err != nil || mb.String() != "server banner" {
				t.Errorf("banner changed: %q %v", mb.String(), err)
			}
			buf.ReleaseMulti(mb)
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("client payload"))}); err != nil {
				t.Error(err)
			}
		}()
		close(start)
		wg.Wait()
	}
}

type visionPrefixWriter struct {
	limit   int
	written []byte
	err     error
}

func (w *visionPrefixWriter) Write(b []byte) (int, error) {
	n := min(len(b), w.limit)
	w.written = append(w.written, b[:n]...)
	w.limit -= n
	if n < len(b) {
		return n, io.ErrClosedPipe
	}
	return n, w.err
}

func TestVisionWriterPayloadPrefixes(t *testing.T) {
	for _, test := range []struct {
		name  string
		limit int
		known uint64
		fail  bool
	}{
		{"response-header", 1, 0, false},
		{"vision-header", 18, 0, false},
		{"content-prefix", 26, 0, false},
		{"padding-tail", 31, 0, false},
		{"complete", 10000, 7, false},
		{"full-plus-error", 10000, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
			flow.BindRoute()
			lower := &visionPrefixWriter{limit: test.limit}
			if test.fail {
				lower.err = io.ErrClosedPipe
			}
			buffered := buf.NewBufferedWriter(buf.NewWriter(lower))
			if _, err := buffered.Write([]byte{0, 0}); err != nil {
				t.Fatal(err)
			}
			buffered.SetFlushNext()
			state := proxy.NewTrafficState(bytes.Repeat([]byte{0xaa}, 16))
			state.IsTLS = true
			writer := proxy.NewVisionWriter(buffered, state, false, context.Background(), nil, nil, []uint32{900, 1, 32, 1})
			observed := buf.AttachWriterReceipt(writer, flow)
			if buf.WriterReceipt(observed) != flow {
				t.Fatal("Vision lost actual endpoint receipt")
			}
			err = observed.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
			if (test.limit < 55 || test.fail) && err == nil {
				t.Fatal("partial lower result lost its error")
			}
			flow.Finish()
			page, err := view.ReadTerminals(context.Background())
			wantFailure := test.limit < 55 || test.fail
			if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != test.known || page.Rows[0].Flow.Downlink.Incomplete != wantFailure {
				t.Fatalf("Vision prefix facts: %+v %v", page, err)
			}
		})
	}
}

type visionBlockedWriter struct{ entered, release chan struct{} }

func (w visionBlockedWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}

func TestVisionBlockedWriteKeepsReaderIndependent(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	state := proxy.NewTrafficState(bytes.Repeat([]byte{0xaa}, 16))
	lower := visionBlockedWriter{make(chan struct{}), make(chan struct{})}
	writer := proxy.NewVisionWriter(buf.NewWriter(lower), state, true, context.Background(), nil, nil, nil)
	buf.AttachWriterReceipt(writer, flow)
	writeDone := make(chan error, 1)
	go func() { writeDone <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}) }()
	<-lower.entered
	flow.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 0 {
		t.Fatalf("owner-end Vision snapshot: %+v %v", page, err)
	}
	reader := proxy.NewVisionReader(buf.NewReader(bytes.NewReader([]byte("server banner"))), state, false, context.Background(), nil, nil, nil, nil)
	readDone := make(chan error, 1)
	go func() { mb, err := reader.ReadMultiBuffer(); buf.ReleaseMulti(mb); readDone <- err }()
	select {
	case err := <-readDone:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("blocked network writer held the Vision state lock")
	}
	close(lower.release)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	page, err = view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 0 {
		t.Fatalf("pending Vision result lost: %+v %v", page, err)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, total := range totals.Rows {
		known += total.Downlink.Known
	}
	if known != 7 {
		t.Fatalf("late Vision total: %+v", totals)
	}
}
