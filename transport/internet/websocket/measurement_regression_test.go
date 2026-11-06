package websocket

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gorilla "github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestMeasurementNormalCloseDrainsBufferedPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("complete websocket payload"), 4096)
	conn, peerDone := measurementWebSocketPeer(t, func(peer *gorilla.Conn) error {
		if err := peer.WriteMessage(gorilla.BinaryMessage, payload); err != nil {
			return err
		}
		return peer.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(gorilla.CloseNormalClosure, ""), time.Now().Add(3*time.Second))
	})
	wrapped := measurementSelectedWebSocketConnection(conn, nil)
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	defer reader.Interrupt()
	// Delay the consumer until the native copy completes: ordinary EOF must close
	// the writer and retain buffered replies rather than interrupting the pipe.
	if err := buf.Copy(buf.NewReader(wrapped), writer); err != nil {
		writer.Interrupt()
		t.Fatalf("normal WebSocket close interrupted buffered payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(&buf.BufferedReader{Reader: reader})
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("buffered payload: got=%d want=%d error=%v", len(got), len(payload), err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestMeasurementAbnormalWebSocketClosePreserved(t *testing.T) {
	payload := []byte("before policy violation")
	conn, peerDone := measurementWebSocketPeer(t, func(peer *gorilla.Conn) error {
		if err := peer.WriteMessage(gorilla.BinaryMessage, payload); err != nil {
			return err
		}
		return peer.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(gorilla.ClosePolicyViolation, "fixture violation"), time.Now().Add(3*time.Second))
	})
	got, err := io.ReadAll(measurementSelectedWebSocketConnection(conn, nil))
	var closeErr *gorilla.CloseError
	if !bytes.Equal(got, payload) || !errors.As(err, &closeErr) || closeErr.Code != gorilla.ClosePolicyViolation || closeErr.Text != "fixture violation" {
		t.Fatalf("abnormal close: payload=%q error=%v", got, err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestMeasurementIncompleteWebSocketMessagePreserved(t *testing.T) {
	payload := bytes.Repeat([]byte("unfinished fragment"), 1024)
	conn, peerDone := measurementWebSocketPeer(t, func(peer *gorilla.Conn) error {
		writer, err := peer.NextWriter(gorilla.BinaryMessage)
		if err != nil {
			return err
		}
		// Gorilla flushes this large server write as a non-final frame. Deliberately
		// leave its writer open: a close control frame cannot finish that message.
		if _, err := writer.Write(payload); err != nil {
			return err
		}
		return peer.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(gorilla.CloseNormalClosure, ""), time.Now().Add(3*time.Second))
	})
	got, err := io.ReadAll(measurementSelectedWebSocketConnection(conn, nil))
	var closeErr *gorilla.CloseError
	if !bytes.Equal(got, payload) || !errors.As(err, &closeErr) || closeErr.Code != gorilla.CloseNormalClosure {
		t.Fatalf("incomplete message: got=%d want=%d error=%v", len(got), len(payload), err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestMeasurementWebSocketExtraReaderBytesWithEOF(t *testing.T) {
	conn, peerDone := measurementWebSocketPeer(t, func(peer *gorilla.Conn) error {
		if err := peer.WriteMessage(gorilla.BinaryMessage, []byte("wire payload")); err != nil {
			return err
		}
		return peer.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(gorilla.CloseNormalClosure, ""), time.Now().Add(3*time.Second))
	})
	extra := &measurementEOFReader{Reader: bytes.NewReader([]byte("extra payload/"))}
	got, err := io.ReadAll(measurementSelectedWebSocketConnection(conn, extra))
	if err != nil || string(got) != "extra payload/wire payload" {
		t.Fatalf("extra-reader bytes with EOF: payload=%q error=%v", got, err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketCloseStatusBoundary(t *testing.T) {
	for _, selected := range []bool{false, true} {
		mode := "native"
		if selected {
			mode = "selected"
		}
		for _, status := range []int{gorilla.CloseNormalClosure, gorilla.CloseNoStatusReceived, gorilla.ClosePolicyViolation} {
			t.Run(mode+"/"+strconv.Itoa(status), func(t *testing.T) {
				conn, peerDone := measurementWebSocketPeer(t, func(peer *gorilla.Conn) error {
					if err := peer.WriteMessage(gorilla.BinaryMessage, []byte("complete payload")); err != nil {
						return err
					}
					// 1005 is never sent on the wire: an empty close payload
					// represents the native no-status boundary.
					return peer.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(status, ""), time.Now().Add(3*time.Second))
				})
				wrapped := NewConnection(conn, conn.RemoteAddr(), nil, 0)
				wrapped.selected = selected
				payload := make([]byte, len("complete payload"))
				if _, err := io.ReadFull(wrapped, payload); err != nil || string(payload) != "complete payload" {
					t.Fatalf("complete message: payload=%q error=%v", payload, err)
				}
				n, err := wrapped.Read(make([]byte, 1))
				if n != 0 {
					t.Fatalf("close produced bytes: %d", n)
				}
				if status == gorilla.ClosePolicyViolation {
					var closeErr *gorilla.CloseError
					if !errors.As(err, &closeErr) || closeErr.Code != status {
						t.Fatalf("abnormal close lost status: %v", err)
					}
				} else if err != io.EOF {
					t.Fatalf("complete close: got %v, want EOF", err)
				}
				if err := <-peerDone; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestMeasurementWebSocketCloseUnblocksIO(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			release, ready := make(chan struct{}), make(chan struct{})
			releasePeer := sync.OnceFunc(func() { close(release) })
			conn, peerDone := measurementWebSocketPeer(t, func(peer *gorilla.Conn) error {
				if err := peer.UnderlyingConn().(*net.TCPConn).SetReadBuffer(1024); err != nil {
					close(ready)
					return err
				}
				close(ready)
				<-release
				return nil
			})
			defer releasePeer()
			<-ready
			if err := conn.UnderlyingConn().(*net.TCPConn).SetWriteBuffer(1024); err != nil {
				t.Fatal(err)
			}
			wrapped := measurementSelectedWebSocketConnection(conn, nil)
			done := make(chan error, 1)
			go func() {
				if operation == "read" {
					_, err := wrapped.Read(make([]byte, 1))
					done <- err
				} else {
					_, err := wrapped.Write(make([]byte, 8<<20))
					done <- err
				}
			}()
			select {
			case err := <-done:
				t.Fatalf("I/O completed before socket close: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			closed := make(chan error, 1)
			go func() { closed <- wrapped.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("selected Close did not close the socket promptly")
			}
			select {
			case err := <-done:
				var netErr net.Error
				if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
					t.Fatalf("pending I/O did not observe socket closure: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("selected Close did not unblock pending I/O")
			}
			releasePeer()
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// measurementSelectedWebSocketConnection selects the same private connection
// behavior as an explicitly selected outbound dial. The context-free public
// constructor retains ordinary native semantics.
func measurementSelectedWebSocketConnection(conn *gorilla.Conn, extra io.Reader) *connection {
	wrapped := NewConnection(conn, conn.RemoteAddr(), extra, 0)
	wrapped.selected = true
	return wrapped
}

type measurementEOFReader struct {
	*bytes.Reader
}

func (r *measurementEOFReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 && r.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func measurementWebSocketPeer(t *testing.T, exchange func(*gorilla.Conn) error) (*gorilla.Conn, <-chan error) {
	t.Helper()
	peerDone := make(chan error, 1)
	upgrader := gorilla.Upgrader{WriteBufferSize: 128}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			peerDone <- err
			return
		}
		defer peer.Close()
		if err := peer.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			peerDone <- err
			return
		}
		peerDone <- exchange(peer)
	}))
	t.Cleanup(server.Close)
	conn, response, err := gorilla.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn, peerDone
}
