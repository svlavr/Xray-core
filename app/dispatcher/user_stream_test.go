package dispatcher

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type directUserConn struct {
	bytes.Buffer
	closed bool
}

func (c *directUserConn) Close() error                   { c.closed = true; return nil }
func (*directUserConn) LocalAddr() stdnet.Addr           { return directUserAddr("local") }
func (*directUserConn) RemoteAddr() stdnet.Addr          { return directUserAddr("remote") }
func (*directUserConn) SetDeadline(time.Time) error      { return nil }
func (*directUserConn) SetReadDeadline(time.Time) error  { return nil }
func (*directUserConn) SetWriteDeadline(time.Time) error { return nil }

type directUserAddr string

func (a directUserAddr) Network() string { return string(a) }
func (a directUserAddr) String() string  { return string(a) }

func observationStream() routing.UserStream {
	return routing.UserStream{
		Connection: new(directUserConn),
	}
}

func preparedObservationLink(d *DefaultDispatcher, row *connectionEntry, reader buf.Reader, writer io.Writer) *transport.Link {
	uplink, downlink := d.connections.prepareUserStream(row, nil)
	return &transport.Link{
		Reader: newUserStreamReader(reader, nil, io.NopCloser(bytes.NewReader(nil)), uplink),
		Writer: buf.NewBufferToBytesWriter(writer, nil, downlink),
	}
}

func TestDispatchUserStreamBuildsCanonicalOwners(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	dest := xnet.TCPDestination(xnet.DomainAddress("direct.test"), 443)
	d.ohm = observationManager{h: &observationHandler{tag: "direct", run: func(_ context.Context, link *transport.Link) {
		if _, ok := link.Reader.(*userStreamReader); !ok {
			t.Fatalf("reader owner: %T", link.Reader)
		}
		if _, ok := link.Writer.(*buf.BufferToBytesWriter); !ok {
			t.Fatalf("writer owner: %T", link.Writer)
		}
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil || string(mb[0].Bytes()) != "prefetched" {
			t.Fatalf("retained payload: %q %v", mb.String(), err)
		}
		buf.ReleaseMulti(mb)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("reply"))}); err != nil {
			t.Fatal(err)
		}
		row := d.ConnectionSnapshot().Connections[0]
		if row.UplinkReadBytes != 10 || row.DownlinkWrittenBytes != 5 || row.UplinkCoverage != BytesExact || row.DownlinkCoverage != BytesExact {
			t.Fatalf("direct accounting: %+v", row)
		}
		finish := buf.BeginRawCopy(link.Writer)
		if finish == nil || d.ConnectionSnapshot().Connections[0].DownlinkCoverage != BytesDeferredRawCopy {
			t.Fatal("raw copy state not visible")
		}
		finish(2)
	}}}
	conn := new(directUserConn)
	stream := routing.UserStream{
		Connection: conn,
		Retained:   buf.MultiBuffer{buf.FromBytes([]byte("prefetched"))},
	}
	if err := d.DispatchUserStream(context.Background(), dest, stream); err != nil {
		t.Fatal(err)
	}
	if got := conn.String(); got != "reply" || !conn.closed {
		t.Fatalf("written payload/ownership: %q closed=%t", got, conn.closed)
	}
	total := outboundTotals(t, d, "direct")
	if total.UplinkReadBytes != 10 || total.DownlinkWrittenBytes != 7 || total.UplinkCoverage != BytesExact || total.DownlinkCoverage != BytesExact {
		t.Fatalf("retired direct total: %+v", total)
	}
}

func TestDispatchUserStreamDisabledAndRejectedOwnership(t *testing.T) {
	d := new(DefaultDispatcher)
	d.ohm = observationManager{h: &observationHandler{run: func(_ context.Context, link *transport.Link) {
		if _, ok := link.Reader.(*userStreamReader); !ok {
			t.Fatalf("disabled reader owner: %T", link.Reader)
		}
	}}}
	dest := xnet.TCPDestination(xnet.LocalHostIP, 80)
	if err := d.DispatchUserStream(context.Background(), dest, observationStream()); err != nil {
		t.Fatal(err)
	}
	if snapshot := d.ConnectionSnapshot(); snapshot.Enabled || len(snapshot.Connections) != 0 || len(snapshot.OutboundTotals) != 0 {
		t.Fatalf("disabled observation changed: %+v", snapshot)
	}

	conn := new(directUserConn)
	retained := buf.New()
	_, _ = retained.Write([]byte("owned"))
	stream := routing.UserStream{Connection: conn, Retained: buf.MultiBuffer{retained}}
	if err := d.DispatchUserStream(context.Background(), xnet.UDPDestination(xnet.LocalHostIP, 53), stream); err == nil {
		t.Fatal("accepted packet stream")
	}
	if !conn.closed || !retained.IsEmpty() {
		t.Fatal("rejected admission retained transferred owners")
	}
	if err := d.DispatchUserStream(context.Background(), dest, routing.UserStream{}); err == nil {
		t.Fatal("accepted missing owners")
	}
}

var _ stdnet.Conn = (*directUserConn)(nil)
