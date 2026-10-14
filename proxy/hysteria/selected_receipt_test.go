package hysteria

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/apernet/quic-go"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func measurementReceipt(t *testing.T) fs.Exchange {
	t.Helper()
	m := new(appstats.Manager)
	if _, err := m.EnableInspection(fs.ObservationOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	flow := m.Observation().Begin(net.Network_UDP, fs.TrafficOriginControlledMeasurement, net.Destination{}, net.Destination{}, nil)
	t.Cleanup(flow.Finish)
	return flow
}

func TestSelectedHysteriaCompleteFrameWithError(t *testing.T) {
	for _, mode := range []string{"full-error", "partial-error", "last-fragment-full-error", "last-fragment-partial-error"} {
		t.Run(mode, func(t *testing.T) {
			m := new(appstats.Manager)
			view, err := m.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close() })
			flow := m.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
			flow.Route(fs.OutboundRef{Tag: "selected"})
			calls := 0
			terminal := io.ErrUnexpectedEOF
			w := &UDPWriter{addr: "127.0.0.1:9000", writer: udpWriterFunc(func(p []byte) (int, error) {
				calls++
				if mode == "full-error" {
					return len(p), terminal
				}
				if mode == "partial-error" {
					return len(p) - 1, terminal
				}
				if calls == 1 {
					return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 96}
				}
				msg, parseErr := ParseUDPMessage(p)
				if parseErr != nil {
					return 0, parseErr
				}
				if msg.FragID+1 == msg.FragCount {
					if mode == "last-fragment-partial-error" {
						return len(p) - 1, terminal
					}
					return len(p), terminal
				}
				return len(p), nil
			})}
			payload := bytes.Repeat([]byte("p"), 200)
			err = buf.AttachWriterReceipt(w, flow).WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)})
			if !errors.Is(err, terminal) {
				t.Fatalf("terminal error %v", err)
			}
			flow.Finish()
			totals, err := view.ReadTotals()
			want := uint64(0)
			if mode == "full-error" || mode == "last-fragment-full-error" {
				want = uint64(len(payload))
			}
			if err != nil || totals.User.Downlink != want {
				t.Fatalf("complete-frame receipt: got=%d want=%d err=%v", totals.User.Downlink, want, err)
			}
		})
	}
}
