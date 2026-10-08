package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type inspectionWriteFunc func([]byte) (int, error)

func (f inspectionWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestInspectionSS2022NativeCodecResults(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, err := GetCipherMethod(name)
			if err != nil {
				t.Fatal(err)
			}
			key := make([]byte, method.KeySaltLength)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			aead, err := method.NewAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			writer := NewStreamWriter(&wire, aead)
			payload := []byte("native decoded payload")
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
				t.Fatal(err)
			}
			reader := NewStreamReader(&wire, aead)
			decoded, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if got := decoded.String(); got != string(payload) {
				t.Fatalf("decoded: %q", got)
			}
			buf.ReleaseMulti(decoded)
		})
	}
}

func TestInspectionSS2022FrameWriteFailures(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	for _, tc := range []struct {
		name  string
		write inspectionWriteFunc
	}{
		{"zero-error", func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }},
		{"partial-error", func([]byte) (int, error) { return 1, io.ErrUnexpectedEOF }},
		{"complete-error", func(p []byte) (int, error) { return len(p), io.ErrUnexpectedEOF }},
		{"short-nil", func([]byte) (int, error) { return 1, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aead, err := method.NewAEAD(make([]byte, method.KeySaltLength))
			if err != nil {
				t.Fatal(err)
			}
			writer := NewStreamWriter(tc.write, aead)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err == nil {
				t.Fatal("missing native write error")
			}
		})
	}
}

func TestInspectionSS2022PendingWrite(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	method, _ := GetCipherMethod(MethodAES128GCM)
	aead, _ := method.NewAEAD(make([]byte, method.KeySaltLength))
	writer := NewStreamWriter(inspectionWriteFunc(func(p []byte) (int, error) { close(started); <-release; return len(p), nil }), aead)
	mb := buf.MultiBuffer{buf.FromBytes([]byte("late"))}
	done := make(chan error, 1)
	go func() { done <- writer.WriteMultiBuffer(mb) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write stuck")
	}
	for _, b := range mb {
		if !b.IsEmpty() {
			t.Fatal("native input buffer not released")
		}
	}
}

func TestInspectionSS2022HandshakeShortWrite(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	key := make([]byte, method.KeySaltLength)
	short := inspectionWriteFunc(func([]byte) (int, error) { return 1, nil })
	_, err := WriteTCPRequest(short, method, [][]byte{key}, net.TCPDestination(net.LocalHostIP, 443), key, []byte("request"))
	if err != io.ErrShortWrite {
		t.Fatalf("request handshake: %v", err)
	}
	writer := NewServerStreamWriter(short, method, key, key)
	if n, err := writer.Write([]byte("response")); n != 0 || err != io.ErrShortWrite {
		t.Fatalf("response handshake: n=%d err=%v", n, err)
	}
}

func TestInspectionSS2022StreamWriteAcceptedPrefix(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	key := make([]byte, method.KeySaltLength)
	for _, response := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "response"}[response], func(t *testing.T) {
			calls := 0
			output := inspectionWriteFunc(func(p []byte) (int, error) {
				calls++
				if calls == 2 {
					return 1, io.ErrUnexpectedEOF
				}
				return len(p), nil
			})
			var writer io.Writer
			if response {
				writer = NewServerStreamWriter(output, method, key, key)
			} else {
				aead, _ := method.NewAEAD(key)
				writer = NewStreamWriter(output, aead)
			}
			payload := bytes.Repeat([]byte{7}, MaxPacketSize+10)
			if n, err := writer.Write(payload); n != MaxPacketSize || err != io.ErrUnexpectedEOF {
				t.Fatalf("accepted prefix: n=%d err=%v", n, err)
			}
		})
	}
}

type inspectionPartialReader struct {
	buf.Reader
	mb  buf.MultiBuffer
	err error
}

func (r *inspectionPartialReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, r.err
}
func (*inspectionPartialReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }

type inspectionPipeDialer struct {
	internet.Dialer
	conn stat.Connection
}

func (d inspectionPipeDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func TestInspectionSS2022EarlyPayloadAndTerminalError(t *testing.T) {
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF} {
		t.Run(terminal.Error(), func(t *testing.T) {
			instance, err := core.New(&core.Config{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
			dest := net.TCPDestination(net.LocalHostIP, 443)
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
			key := make([]byte, 16)
			outbound, err := NewClient(ctx, &ClientConfig{Method: MethodAES128GCM, Key: base64.StdEncoding.EncodeToString(key), Address: net.NewIPOrDomain(net.LocalHostIP), Port: 8388})
			if err != nil {
				t.Fatal(err)
			}
			client, server := stdnet.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server.SetDeadline(time.Now().Add(3 * time.Second))
			received := make(chan []byte, 1)
			serverDone := make(chan error, 1)
			go func() {
				defer server.Close()
				method, _ := GetCipherMethod(MethodAES128GCM)
				header := make([]byte, method.KeySaltLength+RequestHeaderFixedChunkLength+AEADTagSize)
				if _, err := io.ReadFull(server, header); err != nil {
					serverDone <- err
					return
				}
				salt := header[:method.KeySaltLength]
				aead, _ := method.NewAEAD(DeriveSessionSubKey(key, salt, method.KeySaltLength))
				reader := NewStreamReader(server, aead)
				request, err := ReadClientRequestHeaderWithFixed(reader, header[method.KeySaltLength:])
				if err != nil {
					serverDone <- err
					return
				}
				payload := bytes.Clone(request.EarlyData)
				if len(payload) > 0 {
					mb, err := reader.ReadMultiBuffer()
					if err != nil {
						serverDone <- err
						return
					}
					payload = append(payload, []byte(mb.String())...)
					buf.ReleaseMulti(mb)
				}
				received <- payload
				_, err = NewServerStreamWriter(server, method, key, salt).Write([]byte("answer"))
				serverDone <- err
			}()
			first, second := buf.New(), buf.New()
			first.WriteString("first")
			second.WriteString("second")
			reader := &inspectionPartialReader{mb: buf.MultiBuffer{first, second}, err: terminal}
			var answer bytes.Buffer
			err = outbound.Process(ctx, &transport.Link{Reader: reader, Writer: buf.NewWriter(&answer)}, inspectionPipeDialer{conn: client})
			if terminal == io.EOF {
				if err != nil || answer.String() != "answer" {
					t.Fatalf("EOF completion: answer=%q err=%v", answer.String(), err)
				}
			} else if errors.Cause(err) != terminal {
				t.Fatalf("terminal error lost: %v", err)
			}
			select {
			case payload := <-received:
				if string(payload) != "firstsecond" {
					t.Fatalf("early payload lost: %q", payload)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("server did not receive request")
			}
			if !first.IsEmpty() || !second.IsEmpty() {
				t.Fatal("early buffers not released")
			}
			<-serverDone
		})
	}
}
