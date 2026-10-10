package measurement

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type auditErrorOnlyPacketWriter struct {
	*udpTestConn
	err error
}

func (c *auditErrorOnlyPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return c.err
}

func TestAuditUDPWriterCountProvenance(t *testing.T) {
	native := errors.New("native writer failure")
	for _, tc := range []struct {
		name  string
		multi bool
		err   error
		count int
	}{
		{"reported_partial_count", false, native, 7},
		{"supplied_error_only_length", true, native, 32},
		{"reported_success", false, nil, 32},
		{"supplied_success", true, nil, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &udpTestConn{closed: make(chan struct{})}
			c.write = func([]byte) (int, error) { return tc.count, tc.err }
			c.read = func() (buf.MultiBuffer, error) { <-c.closed; return nil, io.ErrClosedPipe }
			request := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), Count: 1, PacketBytes: 32, ReplyWait: time.Millisecond, MaxReplies: 4}
			payload := make([]byte, 32)
			copy(payload, "MUE1")
			var receipt UDPEchoReceipt
			var err error
			if tc.multi {
				err = runUDPTrain(context.Background(), &auditErrorOnlyPacketWriter{udpTestConn: c, err: tc.err}, request, payload, time.Now(), &receipt)
			} else {
				err = runUDPTrain(context.Background(), c, request, payload, time.Now(), &receipt)
			}
			if !errors.Is(err, tc.err) || len(receipt.Sends) != 1 || receipt.Sends[0].WriteReturned == nil || !errors.Is(receipt.Sends[0].Error, tc.err) {
				t.Fatalf("write facts/error lost: %+v %v", receipt, err)
			}
			got := receipt.Sends[0]
			if tc.multi {
				if got.WriterBytes != 32 || got.WriterBytesObserved {
					t.Fatalf("error-only writer supplied length represented as observed return: %+v", got)
				}
			} else if got.WriterBytes != tc.count || !got.WriterBytesObserved {
				t.Fatalf("real positive count with error not retained: %+v", got)
			}
		})
	}
}
