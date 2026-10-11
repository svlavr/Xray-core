package measurement

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

type dnsWireConn struct {
	net.Conn
	reader io.Reader
	write  func([]byte) (int, error)
}

func TestDNSShortStreamRetainsFramingAndBytes(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("fixture.invalid.", dns.TypeA)
	for _, size := range []int{0, 8, 11} {
		body := bytes.Repeat([]byte{1}, size)
		frame := make([]byte, size+2)
		binary.BigEndian.PutUint16(frame, uint16(size))
		copy(frame[2:], body)
		conn := &dnsWireConn{reader: bytes.NewReader(frame), write: func(p []byte) (int, error) { return len(p), nil }}
		var receipt DNSReceipt
		if err := exchangeDNSWire(conn, []byte("query"), DNSRequest{Transport: DNSTCP, MaxResponseBytes: 12}, &receipt); err != nil || !receipt.ResponseComplete || !bytes.Equal(receipt.Wire, body) {
			t.Fatal("lost framed short reply", size, receipt, err)
		}
		if message, err := parseDNSResponse(context.Background(), receipt.Wire, query, DNSTCP); message != nil || !errors.Is(err, ErrDNSResponse) {
			t.Fatal("malformed reply accepted", size, message, err)
		}
	}
}

func TestDNSWrongSourceDoesNotEraseReadCompletion(t *testing.T) {
	packet := []byte("0123456789abcdef")
	for _, nativeErr := range []error{nil, io.ErrUnexpectedEOF} {
		conn := &udpTestPacketConn{udpTestConn: &udpTestConn{write: func(p []byte) (int, error) { return len(p), nil }}, readFrom: func(p []byte) (int, net.Addr, error) {
			return copy(p, packet), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9}, nativeErr
		}}
		var receipt DNSReceipt
		err := exchangeDNSWire(conn, []byte("query"), DNSRequest{Transport: DNSUDP, Resolver: netip.MustParseAddrPort("127.0.0.1:9"), MaxResponseBytes: 64}, &receipt)
		if !errors.Is(err, ErrDNSResponse) || !bytes.Equal(receipt.Wire, packet) || receipt.ResponseComplete != (nativeErr == nil) || receipt.Message != nil {
			t.Fatal("source qualification altered raw read", receipt, err)
		}
		if nativeErr != nil && !errors.Is(err, nativeErr) {
			t.Fatal("native error lost", err)
		}
	}
}

func (c *dnsWireConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *dnsWireConn) Write(p []byte) (int, error) { return c.write(p) }

func TestDNSWirePartialStreamFacts(t *testing.T) {
	native := errors.New("native partial DNS write")
	query := []byte("query")
	for _, tc := range []struct {
		name        string
		n           int
		writeErr    error
		response    []byte
		wantWritten int
		wantWire    []byte
		wantErr     error
	}{
		{"prefix-only", 1, native, nil, 0, nil, native},
		{"payload-prefix", 5, native, nil, 3, nil, native},
		{"zero-write", 0, nil, nil, 0, nil, io.ErrShortWrite},
		{"partial-response", 7, nil, []byte{0, 12, 1, 2, 3}, 5, []byte{1, 2, 3}, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &dnsWireConn{reader: bytes.NewReader(tc.response), write: func([]byte) (int, error) { return tc.n, tc.writeErr }}
			receipt := DNSReceipt{QueryID: 42}
			err := exchangeDNSWire(conn, query, DNSRequest{Transport: DNSTCP, MaxResponseBytes: 12}, &receipt)
			if !errors.Is(err, tc.wantErr) || receipt.WrittenBytes == nil || *receipt.WrittenBytes != tc.wantWritten || !bytes.Equal(receipt.Wire, tc.wantWire) || receipt.ResponseComplete || receipt.QueryID != 42 {
				t.Fatalf("partial wire facts: %+v, error=%v", receipt, err)
			}
		})
	}
}

func TestDNSWirePacketErrorKeepsBytesAndReleasesBatch(t *testing.T) {
	native := errors.New("native DNS batch error")
	packet := []byte("0123456789abcdef")
	b := buf.New()
	_, _ = b.Write(packet)
	dest := xnet.UDPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 9)
	b.UDP = &dest
	conn := &udpTestConn{
		write: func(p []byte) (int, error) { return len(p), nil },
		read:  func() (buf.MultiBuffer, error) { return buf.MultiBuffer{b}, native },
	}
	request := DNSRequest{Transport: DNSUDP, Resolver: netip.MustParseAddrPort("127.0.0.1:9"), MaxResponseBytes: 12}
	var receipt DNSReceipt
	err := exchangeDNSWire(conn, []byte("query"), request, &receipt)
	if !errors.Is(err, native) || !errors.Is(err, ErrDNSLimit) || receipt.WrittenBytes == nil || *receipt.WrittenBytes != 5 || !bytes.Equal(receipt.Wire, packet[:12]) || receipt.ResponseComplete {
		t.Fatalf("packet facts: %+v, error=%v", receipt, err)
	}
	if b.Len() != 0 || b.UDP != nil {
		t.Fatal("native packet buffer was not released")
	}
}
