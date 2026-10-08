package websocket_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gorilla "github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/websocket"
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
	wrapped := websocket.NewConnection(conn, conn.RemoteAddr(), nil, 0)
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
	got, err := io.ReadAll(websocket.NewConnection(conn, conn.RemoteAddr(), nil, 0))
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
	got, err := io.ReadAll(websocket.NewConnection(conn, conn.RemoteAddr(), nil, 0))
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
	got, err := io.ReadAll(websocket.NewConnection(conn, conn.RemoteAddr(), extra, 0))
	if err != nil || string(got) != "extra payload/wire payload" {
		t.Fatalf("extra-reader bytes with EOF: payload=%q error=%v", got, err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
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
