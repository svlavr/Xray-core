//go:build linux || android

package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/platform"
	fs "github.com/xtls/xray-core/features/stats"
)

// This must observe progress while both the SOCKS client and Freedom peer remain
// open. Final-only ReadFrom accounting cannot satisfy the first sample.
func TestFlowInspectionRawProgressLinux(t *testing.T) {
	t.Setenv(platform.UseFreedomSplice, "enable")
	t.Setenv(platform.UseReadV, "enable")
	for _, sniff := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "after-sniff-replay"}[sniff], func(t *testing.T) {
			_, view, address := inspectionCore(t, true, sniff)
			destination := startOutboundStatsTCPServer(t)
			first := []byte("GET / HTTP/1.1\r\nHost: progress.invalid\r\n\r\n")
			conn := inspectionSOCKS(t, address, destination, first)
			var ref fs.FlowRef
			check := func(want uint64) {
				t.Helper()
				inspectionWait(t, func() bool {
					live, err := view.ReadLive(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					if len(live.Rows) != 1 {
						return false
					}
					flow := live.Rows[0]
					if flow.Uplink.Known != want || flow.Downlink.Known != want {
						return false
					}
					if flow.Downlink.Incomplete {
						t.Fatalf("raw fact: %+v", flow.Downlink)
					}
					ref = flow.Ref
					totals, err := view.ReadTotals(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range totals.Rows {
						if row.Outbound.Serial == flow.AccountingRoute.Outbound.Serial && row.Origin == fs.TrafficOriginUser {
							if row.Downlink.Known != want || row.Downlink.Incomplete {
								return false
							}
							return true
						}
					}
					return false
				})
			}
			check(uint64(len(first)))
			second := []byte("small second transfer on the same open stream")
			if _, err := conn.Write(second); err != nil {
				t.Fatal(err)
			}
			inspectionResponse(t, conn, second)
			check(uint64(len(first) + len(second)))
			outcome, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
			if err != nil || outcome[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("close: %+v %v", outcome, err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Rows) != 1 {
					return false
				}
				final := page.Rows[0]
				if final.Flow.Downlink.Known != uint64(len(first)+len(second)) || final.Flow.Downlink.Incomplete || final.Reason != fs.EndReasonLocalStop {
					t.Fatalf("raw final: %+v", final)
				}
				return true
			})
		})
	}
}
