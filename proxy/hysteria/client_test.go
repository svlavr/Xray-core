package hysteria

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/apernet/quic-go"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

type udpWriterFunc func([]byte) (int, error)

func (f udpWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestUDPWriterSendMessageLargeAndShortWrite(t *testing.T) {
	data := bytes.Repeat([]byte("p"), buf.Size)
	message := &UDPMessage{FragCount: 1, Addr: "127.0.0.1:53", Data: data}
	var encoded []byte
	writer := &UDPWriter{writer: udpWriterFunc(func(p []byte) (int, error) {
		encoded = append([]byte(nil), p...)
		return len(p), nil
	})}
	if err := writer.SendMessage(message); err != nil {
		t.Fatal(err)
	}
	if len(encoded) != message.Size() || len(encoded) <= buf.Size {
		t.Fatalf("encoded size %d, want %d above fixed buffer", len(encoded), message.Size())
	}
	parsed, err := ParseUDPMessage(encoded)
	if err != nil || parsed.Addr != message.Addr || !bytes.Equal(parsed.Data, data) {
		t.Fatalf("large message was not serialized intact: %+v %v", parsed, err)
	}

	writer.writer = udpWriterFunc(func(p []byte) (int, error) { return len(p) - 1, nil })
	if err := writer.SendMessage(&UDPMessage{FragCount: 1, Addr: "127.0.0.1:53", Data: []byte("payload")}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write returned %v", err)
	}
}

func TestUDPWriterFragmentationAndFailures(t *testing.T) {
	t.Run("fragments", func(t *testing.T) {
		const maxDatagram = 128
		var writes [][]byte
		first := true
		writer := &UDPWriter{addr: "127.0.0.1:53", writer: udpWriterFunc(func(p []byte) (int, error) {
			if first {
				first = false
				return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: maxDatagram}
			}
			writes = append(writes, append([]byte(nil), p...))
			return len(p), nil
		})}
		payload := bytes.Repeat([]byte("fragmented"), 80)
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
			t.Fatal(err)
		}
		if len(writes) < 2 {
			t.Fatalf("fragment count %d", len(writes))
		}
		var joined []byte
		for i, encoded := range writes {
			if len(encoded) > maxDatagram {
				t.Fatalf("fragment %d size %d", i, len(encoded))
			}
			message, err := ParseUDPMessage(encoded)
			if err != nil {
				t.Fatalf("fragment %d (%d bytes, prefix %x): %v", i, len(encoded), encoded[:min(len(encoded), 16)], err)
			}
			if int(message.FragID) != i || int(message.FragCount) != len(writes) || message.PacketID == 0 {
				t.Fatalf("fragment metadata: %+v", message)
			}
			joined = append(joined, message.Data...)
		}
		if !bytes.Equal(joined, payload) {
			t.Fatal("fragmentation changed payload")
		}
	})

	t.Run("empty-fragmentation", func(t *testing.T) {
		calls := 0
		writer := &UDPWriter{addr: "127.0.0.1:53", writer: udpWriterFunc(func(p []byte) (int, error) {
			calls++
			return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1}
		})}
		err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
		if err == nil || calls != 1 {
			t.Fatalf("empty fragmentation returned %v after %d writes", err, calls)
		}
	})

	t.Run("fragment-write-error", func(t *testing.T) {
		failure := errors.New("fragment failed")
		calls := 0
		writer := &UDPWriter{addr: "127.0.0.1:53", writer: udpWriterFunc(func(p []byte) (int, error) {
			calls++
			if calls == 1 {
				return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 128}
			}
			return 0, failure
		})}
		err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(bytes.Repeat([]byte("x"), 512))})
		if !errors.Is(err, failure) || calls != 2 {
			t.Fatalf("fragment failure returned %v after %d writes", err, calls)
		}
	})
}

func TestInspectionUDPFragmentCountLimit(t *testing.T) {
	message := &UDPMessage{Addr: "127.0.0.1:53", Data: bytes.Repeat([]byte("p"), 256)}
	if fragments := FragUDPMessage(message, message.HeaderSize()+1); len(fragments) != 0 {
		t.Fatalf("unrepresentable fragment count: %d", len(fragments))
	}
	message.Data = message.Data[:255]
	if fragments := FragUDPMessage(message, message.HeaderSize()+1); len(fragments) != 255 {
		t.Fatalf("maximum representable fragment count: %d", len(fragments))
	}
}

func TestInspectionHysteriaPacketResults(t *testing.T) {
	for _, mode := range []string{"full", "full-error", "short-nil", "zero-error", "fragments", "first-fragment-error", "middle-fragment-error", "last-fragment-full-error", "too-many-fragments"} {
		t.Run(mode, func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close() })
			flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
			flow.BindRoute()
			failure := errors.New("packet result failure")
			calls := 0
			writer := &UDPWriter{addr: "127.0.0.1:53", writer: udpWriterFunc(func(p []byte) (int, error) {
				calls++
				switch mode {
				case "full":
					return len(p), nil
				case "full-error":
					return len(p), failure
				case "short-nil":
					return len(p) - 1, nil
				case "zero-error":
					return 0, failure
				case "too-many-fragments":
					message, _ := ParseUDPMessage(p)
					return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(message.HeaderSize() + 1)}
				}
				if calls == 1 {
					return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 128}
				}
				message, err := ParseUDPMessage(p)
				if err != nil {
					return 0, err
				}
				if mode == "first-fragment-error" && message.FragID == 0 {
					return 0, failure
				}
				if mode == "middle-fragment-error" && message.FragID == 1 {
					return 0, failure
				}
				if mode == "last-fragment-full-error" && message.FragID == message.FragCount-1 {
					return len(p), failure
				}
				return len(p), nil
			})}
			if writer.WithWriterReceipt(nil) != writer {
				t.Fatal("disabled packet writer changed")
			}
			observed := buf.AttachWriterReceipt(writer, flow)
			payload := buf.New()
			payload.Write(bytes.Repeat([]byte("p"), 512))
			err = observed.WriteMultiBuffer(buf.MultiBuffer{payload})
			if (mode == "full" || mode == "fragments") != (err == nil) {
				t.Fatalf("native packet result: %v", err)
			}
			if !payload.IsEmpty() {
				t.Fatal("packet was not released")
			}
			flow.Finish()
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("packet terminal: %+v %v", page, err)
			}
			fact := page.Rows[0].Flow.Downlink
			switch mode {
			case "full", "full-error", "fragments", "last-fragment-full-error":
				if fact.Known != 512 || fact.Incomplete {
					t.Fatalf("complete packet result: %+v", fact)
				}
			case "short-nil", "middle-fragment-error":
				if fact.Known != 0 || !fact.Incomplete {
					t.Fatalf("partial packet result: %+v", fact)
				}
			default:
				if fact.Known != 0 || fact.Incomplete {
					t.Fatalf("no accepted packet: %+v", fact)
				}
			}
		})
	}
}

func TestInspectionHysteriaPacketBatchFailure(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	calls := 0
	native := &UDPWriter{addr: "127.0.0.1:53", writer: udpWriterFunc(func(p []byte) (int, error) {
		calls++
		if calls == 2 {
			return 0, io.ErrUnexpectedEOF
		}
		return len(p), nil
	})}
	var mb buf.MultiBuffer
	for _, payload := range []string{"first", "second", "third"} {
		b := buf.New()
		b.WriteString(payload)
		mb = append(mb, b)
	}
	if err := buf.AttachWriterReceipt(native, flow).WriteMultiBuffer(mb); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("batch error: %v", err)
	}
	for _, b := range mb {
		if !b.IsEmpty() {
			t.Fatal("failed batch retained payload")
		}
	}
	flow.Finish()
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 {
		t.Fatal("missing batch terminal")
	}
	fact := page.Rows[0].Flow.Downlink
	if calls != 2 || fact.Known != 5 || fact.Incomplete {
		t.Fatalf("batch results: %+v, calls %d", fact, calls)
	}
}
