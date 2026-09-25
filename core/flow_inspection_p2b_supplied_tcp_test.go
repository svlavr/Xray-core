package core_test

import (
	"bytes"
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
)

type inspectionSuppliedTCPReceiver func(*testing.T, bool, bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig)

func TestFlowInspectionP2BSuppliedTCP(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{
		{name: "VLESS", receiver: inspectionVLESSReceiver},
		{name: "Hysteria", receiver: inspectionHysteriaReceiver},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspectionDecodedTCPReceiverAcceptance(t, test.receiver)
		})
	}
}

func inspectionDecodedTCPReceiverAcceptance(t *testing.T, receiver inspectionSuppliedTCPReceiver) {
	t.Helper()
	inspectionDecodedTCPReceiverAcceptanceMode(t, receiver, false)
}

func inspectionDecodedTCPReceiverAcceptanceMode(t *testing.T, receiver inspectionSuppliedTCPReceiver, pendingPeerEOF bool) {
	t.Helper()
	t.Run("disabled", func(t *testing.T) {
		receiving, _, outbound := receiver(t, false, false)
		_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
		destination := startOutboundStatsTCPServer(t)
		inspectionSOCKS(t, address, destination, []byte("disabled supplied TCP"))
		if receiving.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
			t.Fatal("disabled receiver acquired inspection state")
		}
	})
	t.Run("payload-stop-sibling", func(t *testing.T) {
		_, view, outbound := receiver(t, true, true)
		sender, _, address := inspectionTCPOutboundThrough(t, false, outbound)
		destination := startOutboundStatsTCPServer(t)
		payload := append([]byte("GET / HTTP/1.1\r\nHost: supplied.invalid\r\n\r\n"), bytes.Repeat([]byte("p"), 8192)...)
		first := inspectionSOCKS(t, address, destination, payload)

		var firstRow fs.FlowRecord
		inspectionWait(t, func() bool {
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 || live.Rows[0].Uplink.Known != uint64(len(payload)) || live.Rows[0].Downlink.Known != uint64(len(payload)) {
				return false
			}
			firstRow = live.Rows[0]
			return true
		})
		assertDecodedTCPReceiverFacts(t, firstRow, destination, uint64(len(payload)))

		sibling := inspectionSOCKS(t, address, destination, payload)
		inspectionWait(t, func() bool {
			live, err := view.ReadLive(context.Background())
			return err == nil && len(live.Rows) == 2
		})
		outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{firstRow.Ref})
		if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("supplied TCP exact stop: %+v %v", outcomes, err)
		}
		if pendingPeerEOF {
			// The local native close is not a remote half-close completion receipt.
			first.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("stopped endpoint returned %d, %v", n, err)
		} else if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() && !pendingPeerEOF {
			t.Fatal("stopped endpoint did not close before deadline")
		}
		extra := []byte("sibling after supplied TCP stop")
		if err := sibling.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := sibling.Write(extra); err != nil {
			t.Fatal(err)
		}
		inspectionResponse(t, sibling, extra)
		sibling.Close()
		if pendingPeerEOF {
			// Native sing copy retains its other pipe pump after client EOF.
			// Require actual local stop/join rather than inventing an ending.
			var siblingRef fs.FlowRef
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				live, _ := view.ReadLive(context.Background())
				if len(page.Rows) != 1 || page.Rows[0].Flow.Ref != firstRow.Ref || len(live.Rows) != 1 {
					return false
				}
				siblingRef = live.Rows[0].Ref
				return siblingRef != firstRow.Ref
			})
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{siblingRef})
			if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("pending sibling stop: %+v %v", outcomes, err)
			}
		}
		inspectionWait(t, func() bool {
			page, _ := view.ReadTerminals(context.Background())
			if len(page.Rows) != 2 {
				return false
			}
			for _, row := range page.Rows {
				if row.Flow.Ref == firstRow.Ref {
					return row.Reason == fs.EndReasonLocalStop && row.Flow.Uplink.Known == uint64(len(payload)) && row.Flow.Downlink.Known == uint64(len(payload))
				}
			}
			return false
		})
		inspectionOutboundTotals(t, view, "direct", uint64(2*len(payload)+len(extra)))
		if sender.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
			t.Fatal("disabled sender acquired inspection state")
		}
	})
}

func TestFlowInspectionP2BVLESSEarlyStopExcludesResponseHeader(t *testing.T) {
	_, view, outbound := inspectionVLESSReceiver(t, true, false)
	_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
	destination := startOutboundStatsTCPServer(t)
	client := inspectionSOCKS(t, address, destination, nil)
	var row fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		row = live.Rows[0]
		return row.AccountingRoute.Outbound.Tag == "direct" && row.AccountingRoute.Outbound.Serial != 0
	})
	if row.Uplink.Known != 0 || row.Downlink.Known != 0 {
		t.Fatalf("VLESS response framing credited before payload: %+v", row)
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("VLESS early stop: %+v %v", outcomes, err)
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("stopped VLESS endpoint returned %d, %v", n, err)
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == row.Ref && page.Rows[0].Reason == fs.EndReasonLocalStop && page.Rows[0].Flow.Downlink.Known == 0
	})
	inspectionOutboundTotals(t, view, "direct", 0)
}

func TestFlowInspectionP2BSpecialCarriersNotAdmitted(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{
		{name: "VLESS-MUX", receiver: inspectionVLESSReceiver},
		{name: "Hysteria-MUX", receiver: inspectionHysteriaReceiver},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, view, outbound := test.receiver(t, true, false)
			inspectionEnableOutboundMux(t, outbound)
			_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
			destination := startOutboundStatsTCPServer(t)
			inspectionSOCKS(t, address, destination, []byte("excluded shared carrier"))
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 || live.Rows[0].InitialDestination != destination {
				t.Fatalf("shared carrier admitted as a logical exchange: %+v %v", live, err)
			}
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 0 {
				t.Fatalf("shared carrier produced a terminal exchange: %+v %v", page, err)
			}
		})
	}
}

func inspectionEnableOutboundMux(t *testing.T, outbound *core.OutboundHandlerConfig) {
	t.Helper()
	var sender *proxyman.SenderConfig
	if outbound.SenderSettings != nil {
		message, err := outbound.SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		sender = message.(*proxyman.SenderConfig)
	} else {
		sender = new(proxyman.SenderConfig)
	}
	sender.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4}
	outbound.SenderSettings = serial.ToTypedMessage(sender)
}

func assertDecodedTCPReceiverFacts(t *testing.T, row fs.FlowRecord, destination cnet.Destination, payload uint64) {
	t.Helper()
	if row.Kind != fs.FlowKindTCP || row.InitialDestination != destination || row.AccountingRoute.Outbound.Tag != "direct" || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != destination || row.Origin != fs.TrafficOriginUser || row.Uplink.Incomplete || row.Downlink.Incomplete || row.Uplink.Known != payload || row.Downlink.Known != payload {
		t.Fatalf("supplied TCP facts: %+v", row)
	}
}
