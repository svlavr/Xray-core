package measurement

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net/cnc"
)

// This writer has no downstream sink and returns no accepted-byte count.
// It records the supplied bytes, releases their buffers, and returns an error.
type auditDNSErrorOnlyWriter struct {
	err      error
	calls    int
	supplied []byte
	buffers  []*buf.Buffer
}

func (w *auditDNSErrorOnlyWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls++
	for _, b := range mb {
		w.supplied = append(w.supplied, b.Bytes()...)
		w.buffers = append(w.buffers, b)
	}
	buf.ReleaseMulti(mb)
	return w.err
}

type auditDNSUnreadResponse struct{ calls int }

func (r *auditDNSUnreadResponse) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.calls++
	return nil, io.EOF
}

func TestAuditDNSCNCErrorOnlyWriterProvenance(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("fixture.invalid.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []DNSTransport{DNSUDP, DNSTCP} {
		t.Run(fmt.Sprint(transport), func(t *testing.T) {
			sentinel := errors.New("audit DNS error-only writer")
			writer := &auditDNSErrorOnlyWriter{err: sentinel}
			reader := new(auditDNSUnreadResponse)
			conn := cnc.NewConnection(cnc.ConnectionInputMulti(writer), cnc.ConnectionOutputMulti(reader))
			t.Cleanup(func() { _ = conn.Close() })
			var receipt DNSReceipt
			err := exchangeDNSWire(conn, wire, DNSRequest{Transport: transport, MaxResponseBytes: 512}, &receipt)
			if !errors.Is(err, sentinel) {
				t.Fatalf("writer error lost: %v", err)
			}
			wantSupplied := wire
			if transport == DNSTCP {
				wantSupplied = make([]byte, len(wire)+2)
				binary.BigEndian.PutUint16(wantSupplied, uint16(len(wire)))
				copy(wantSupplied[2:], wire)
			}
			if writer.calls != 1 || !bytes.Equal(writer.supplied, wantSupplied) {
				t.Fatalf("unexpected writer input: calls=%d supplied=%x want=%x", writer.calls, writer.supplied, wantSupplied)
			}
			if receipt.WrittenBytes == nil || *receipt.WrittenBytes != len(wire) {
				t.Fatalf("CNC supplied-length fact changed: %+v", receipt)
			}
			if reader.calls != 0 || len(receipt.Wire) != 0 || receipt.Message != nil || receipt.ResponseComplete {
				t.Fatalf("write error admitted response processing: reads=%d receipt=%+v", reader.calls, receipt)
			}
			for _, b := range writer.buffers {
				if b.Len() != 0 {
					t.Fatal("writer did not release supplied buffer")
				}
			}
			// This is a provenance witness, not an independent acceptance assertion:
			// CNC returns len(input) even though this error-only writer has no sink.
			t.Logf("CNC input=%d DNS WrittenBytes=%d error=%v; error-only writer, no downstream write, independent accepted-byte count unavailable", len(writer.supplied), *receipt.WrittenBytes, err)
		})
	}
}

// A deterministic net.Conn control supplies a positive partial (n, error).
// It models returned-count propagation; it is not an actual socket result.
type auditDNSCountConn struct {
	net.Conn
	n          int
	err        error
	writeCalls int
	readCalls  int
}

func (c *auditDNSCountConn) Write([]byte) (int, error) {
	c.writeCalls++
	return c.n, c.err
}

func (c *auditDNSCountConn) Read([]byte) (int, error) {
	c.readCalls++
	return 0, io.EOF
}

func TestAuditDNSReturnedPartialCountControl(t *testing.T) {
	wire := []byte("query")
	for _, transport := range []DNSTransport{DNSUDP, DNSTCP} {
		for _, n := range []int{1, 2, 4} {
			t.Run(fmt.Sprintf("transport=%d/n=%d", transport, n), func(t *testing.T) {
				sentinel := errors.New("audit DNS deterministic partial write")
				conn := &auditDNSCountConn{n: n, err: sentinel}
				var receipt DNSReceipt
				err := exchangeDNSWire(conn, wire, DNSRequest{Transport: transport, MaxResponseBytes: 512}, &receipt)
				want := n
				if transport == DNSTCP {
					want = max(0, n-2)
				}
				if !errors.Is(err, sentinel) || receipt.WrittenBytes == nil || *receipt.WrittenBytes != want {
					t.Fatalf("returned partial count/error lost: receipt=%+v error=%v want=%d", receipt, err, want)
				}
				if conn.writeCalls != 1 || conn.readCalls != 0 || len(receipt.Wire) != 0 || receipt.Message != nil || receipt.ResponseComplete {
					t.Fatalf("unexpected I/O after partial error: writes=%d reads=%d receipt=%+v", conn.writeCalls, conn.readCalls, receipt)
				}
				t.Logf("deterministic count-returning control: n=%d DNS WrittenBytes=%d; not socket evidence", n, *receipt.WrittenBytes)
			})
		}
	}
}
