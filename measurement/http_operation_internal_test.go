package measurement

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type bodyReadStep struct {
	data []byte
	err  error
}

func (r *bodyReadStep) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) > 0 {
		return n, nil
	}
	err := r.err
	r.err = io.EOF
	return n, err
}

func TestHTTPSharedBodyRawBoundaries(t *testing.T) {
	native := errors.New("native positive read and error")
	for _, tc := range []struct {
		name     string
		data     string
		limit    int64
		retain   bool
		readErr  error
		count    int64
		body     string
		complete bool
		capHit   bool
		wantErr  error
	}{
		{"empty-retained", "", 8, true, io.EOF, 0, "", true, false, nil},
		{"head-zero-limit", "", 0, true, io.EOF, 0, "", true, true, nil},
		{"retained-eof-at-limit", "abc", 3, true, io.EOF, 3, "abc", true, true, nil},
		{"retained-overflow", "abcd", 3, true, io.EOF, 4, "abc", false, true, ErrBodyLimit},
		{"retained-positive-error", "ab", 3, true, native, 2, "ab", false, false, native},
		{"stream-positive-error-at-cap", "abc", 3, false, native, 3, "", false, true, native},
		{"stream-native-eof-at-cap", "abc", 3, false, io.EOF, 3, "", true, true, nil},
		{"stream-cap-without-eof", "abcd", 3, false, io.EOF, 3, "", false, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &http.Response{Body: io.NopCloser(&bodyReadStep{data: []byte(tc.data), err: tc.readErr})}
			var receipt HTTPSReceipt
			count, capHit, err := consumeHTTPBody(context.Background(), response, &receipt, tc.limit, tc.retain)
			if count != tc.count || capHit != tc.capHit || receipt.BodyComplete != tc.complete || string(receipt.Body) != tc.body || receipt.BodyBytes != int64(len(tc.body)) || !errors.Is(err, tc.wantErr) {
				t.Fatalf("count=%d cap=%t receipt=%+v error=%v", count, capHit, receipt, err)
			}
			if tc.retain && receipt.Body == nil {
				t.Fatal("retained empty response changed native nonnil body representation")
			}
			if !tc.retain && receipt.Body != nil {
				t.Fatal("stream mode retained download payload")
			}
		})
	}
}

func TestHTTPSharedBodyCancellationKeepsNativeReadBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, retain := range []bool{true, false} {
		var receipt HTTPSReceipt
		response := &http.Response{Body: io.NopCloser(bytes.NewBufferString("raw"))}
		count, _, err := consumeHTTPBody(ctx, response, &receipt, 8, retain)
		if retain {
			// Former retained io.ReadAll read available native data; operation
			// finalization separately joins the caller context error.
			if err != nil || count != 3 || string(receipt.Body) != "raw" || !receipt.BodyComplete {
				t.Fatalf("retained read was preempted: %+v count=%d error=%v", receipt, count, err)
			}
		} else if !errors.Is(err, context.Canceled) || count != 0 || receipt.BodyComplete || receipt.Body != nil {
			t.Fatalf("stream cancellation boundary changed: %+v count=%d error=%v", receipt, count, err)
		}
	}
}

func TestHTTPFinishSnapshotsBeforeCleanupCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "raw")
	}))
	defer server.Close()
	e, err := New(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var admitted *operation
	var consumed, finished int
	native := errors.New("observed writer error")
	plan := httpPlan{
		method: http.MethodGet,
		consume: func(o *operation, response *http.Response, receipt *HTTPSReceipt) error {
			admitted = o
			consumed++
			return readHTTPSBody(o, response, receipt, 8)
		},
		finish: func() error {
			finished++
			if admitted == nil || admitted.Err() != nil || context.Cause(admitted) != nil || len(e.slots) != 1 {
				t.Fatal("fact snapshot ran after cleanup cancellation or admission release")
			}
			return native
		},
	}
	receipt, err := e.http(context.Background(), HTTPSRequest{Route: Route{Kind: Direct}, URL: server.URL, Timeout: time.Second, MaxBodyBytes: 8, MaxHeaderBytes: 4096}, plan)
	if consumed != 1 || finished != 1 || !errors.Is(err, native) || errors.Is(err, context.Canceled) || string(receipt.Body) != "raw" || !receipt.BodyComplete || len(e.slots) != 0 {
		t.Fatalf("finish facts: consumed=%d finished=%d receipt=%+v error=%v", consumed, finished, receipt, err)
	}
	if !errors.Is(admitted.Err(), context.Canceled) {
		t.Fatal("operation cleanup did not cancel its native resources")
	}
}
