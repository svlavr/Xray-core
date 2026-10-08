package core_test

import (
	"context"
	"testing"

	fout "github.com/xtls/xray-core/features/outbound"
	fs "github.com/xtls/xray-core/features/stats"
)

func inspectionAppClientRejectedReceiver(t *testing.T, receiver inspectionSuppliedTCPReceiver) {
	t.Helper()
	receiving, remote, outbound := receiver(t, true, true)
	if err := receiving.GetFeature(fout.ManagerType()).(fout.Manager).RemoveHandler(context.Background(), "direct"); err != nil {
		t.Fatal(err)
	}
	_, view, address := inspectionTCPOutboundThrough(t, true, outbound)
	payload := []byte("GET / HTTP/1.1\r\nHost: rejected.invalid\r\n\r\n")
	client := inspectionSOCKS(t, address, startOutboundStatsTCPServer(t), nil)
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("rejected receiver returned %d, %v", n, err)
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals()
		if err != nil || len(page.Rows) != 1 {
			return false
		}
		row := page.Rows[0].Flow
		if row.Outbound.Tag != outbound.Tag || row.Outbound.Tag == "" || row.Downlink != 0 || row.Uplink > uint64(len(payload)) {
			t.Fatalf("app rejected flow: %+v", row)
		}
		return true
	})
	assertNoDedicatedServerInspection(t, remote)
}

func assertNoDedicatedServerInspection(t *testing.T, view fs.FlowInspection) {
	t.Helper()
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("dedicated server live rows: %+v %v", live, err)
	}
	ended, err := view.ReadTerminals()
	if err != nil || len(ended.Rows) != 0 {
		t.Fatalf("dedicated server terminal rows: %+v %v", ended, err)
	}
	totals, err := view.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	if totals.User != (fs.ClientTotals{}) || len(totals.Rows) != 0 {
		t.Fatalf("dedicated server public USER credit: %+v", totals)
	}
}
