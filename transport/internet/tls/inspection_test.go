package tls

import (
	stdtls "crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type inspectionTLSReceipt struct {
	stats.Exchange
	downlink atomic.Uint64
}

func (r *inspectionTLSReceipt) AddDownlink(n uint64) { r.downlink.Add(n) }

func inspectionTLSPair(t *testing.T) (*Conn, *stdtls.Conn) {
	t.Helper()
	serverRaw, clientRaw := net.Pipe()
	t.Cleanup(func() {
		serverRaw.Close()
		clientRaw.Close()
	})
	_, certificate := testCertificate(t, "inspection.local", "inspection.local")
	deadline := time.Now().Add(5 * time.Second)
	serverRaw.SetDeadline(deadline)
	clientRaw.SetDeadline(deadline)
	server := &Conn{Conn: stdtls.Server(serverRaw, &stdtls.Config{Certificates: []stdtls.Certificate{*certificate}})}
	client := stdtls.Client(clientRaw, &stdtls.Config{InsecureSkipVerify: true}) //nolint:gosec // The test owns both pipe endpoints.
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	clientErr := client.Handshake()
	serverErr := <-serverResult
	if clientErr != nil || serverErr != nil {
		t.Fatalf("TLS handshake: client=%v server=%v", clientErr, serverErr)
	}
	return server, client
}

func inspectionTLSReadWrite(t *testing.T, client *stdtls.Conn, want string, write func() error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- write() }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("TLS read: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("TLS write: %v", err)
	}
	if string(got) != want {
		t.Fatalf("TLS payload = %q, want %q", got, want)
	}
}

func TestInspectionTLSWriterUsesNativeResults(t *testing.T) {
	server, client := inspectionTLSPair(t)
	receipt := new(inspectionTLSReceipt)
	writer := server.WithWriterReceipt(receipt)
	if writer != server {
		t.Fatal("observed TLS writer lost its native identity")
	}
	if got := buf.WriterReceipt(writer); got != receipt {
		t.Fatal("observed TLS writer lost its original receipt")
	}
	direct, ok := writer.(io.Writer)
	if !ok {
		t.Fatal("observed TLS writer lost io.Writer")
	}
	if _, observed := writer.(io.ReaderFrom); observed {
		if _, native := any(server).(io.ReaderFrom); !native {
			t.Fatal("observed TLS writer gained ReaderFrom")
		}
	} else if _, native := any(server).(io.ReaderFrom); native {
		t.Fatal("observed TLS writer lost ReaderFrom")
	}
	if _, ok := writer.(net.Conn); !ok {
		t.Fatal("observed TLS writer lost net.Conn")
	}
	inspectionTLSReadWrite(t, client, "direct", func() error {
		n, err := direct.Write([]byte("direct"))
		if err == nil && n != len("direct") {
			return io.ErrShortWrite
		}
		return err
	})
	inspectionTLSReadWrite(t, client, "firstsecond", func() error {
		return writer.WriteMultiBuffer(buf.MultiBuffer{
			buf.FromBytes([]byte("first")), buf.FromBytes([]byte("second")),
		})
	})
	if got, want := receipt.downlink.Load(), uint64(len("directfirstsecond")); got != want {
		t.Fatalf("decoded TLS bytes = %d, want %d", got, want)
	}
	client.NetConn().Close()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("failed"))}); err == nil {
		t.Fatal("closed TLS peer accepted batch")
	}
	if got, want := receipt.downlink.Load(), uint64(len("directfirstsecond")); got != want {
		t.Fatalf("failed TLS batch credited %d, want %d", got, want)
	}
}

func TestInspectionTLSWriterAttachesAfterBufferedHeaderFlush(t *testing.T) {
	server, client := inspectionTLSPair(t)
	receipt := new(inspectionTLSReceipt)
	writer := buf.NewBufferedWriter(server)
	t.Cleanup(func() { buf.DiscardBufferedWriter(writer) })
	if _, err := writer.Write([]byte("head")); err != nil {
		t.Fatal(err)
	}
	if got, attached := buf.AttachWriterReceiptWithStatus(writer, receipt); attached || got != writer || buf.WriterReceipt(got) != nil {
		t.Fatal("pre-buffered TLS writer accepted a receipt or changed identity")
	}
	inspectionTLSReadWrite(t, client, "head", func() error { return writer.SetBuffered(false) })
	if receipt.downlink.Load() != 0 {
		t.Fatal("rejected TLS attachment credited the header")
	}
	if got, attached := buf.AttachWriterReceiptWithStatus(writer, receipt); !attached || got != writer || buf.WriterReceipt(got) != receipt {
		t.Fatal("flushed TLS writer lost its receipt or identity")
	}
	inspectionTLSReadWrite(t, client, "payload", func() error {
		n, err := writer.Write([]byte("payload"))
		if err == nil && n != len("payload") {
			return io.ErrShortWrite
		}
		return err
	})
	inspectionTLSReadWrite(t, client, "tail", func() error {
		return writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("tail"))})
	})
	if got, want := receipt.downlink.Load(), uint64(len("payloadtail")); got != want {
		t.Fatalf("decoded bytes = %d, want %d; header was counted or payload was lost", got, want)
	}
}

// Test-only representation of the former nested attachment for one-run cost comparison.
type legacyInspectionTLSWriter struct {
	*Conn
	writer buf.Writer
}

func (w *legacyInspectionTLSWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(buf.Compact(mb))
}

var inspectionTLSConstructionSink buf.Writer

// BenchmarkInspectionTLSWriterConstruction measures attachment allocations only.
// It does not measure TLS handshakes, socket I/O or network throughput.
func BenchmarkInspectionTLSWriterConstruction(b *testing.B) {
	conn := new(Conn) // No I/O occurs in this construction benchmark.
	receipt := new(inspectionTLSReceipt)
	for _, mode := range []string{"legacy-chain", "native-direct"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if mode == "legacy-chain" {
					inspectionTLSConstructionSink = &legacyInspectionTLSWriter{
						Conn: conn, writer: buf.AttachWriterReceipt(&buf.SequentialWriter{Writer: conn}, receipt),
					}
				} else {
					inspectionTLSConstructionSink = conn.WithWriterReceipt(receipt)
				}
			}
		})
	}
}
