package splithttp

import "testing"

func TestReleaseRedundantXmuxRotationReceiptKeepsBaseHolds(t *testing.T) {
	base := new(XmuxClient)
	download := new(XmuxClient)
	dynamic := new(XmuxClient)

	base.AddRunning()
	download.AddRunning()
	dynamic.AddRunning()

	for _, test := range []struct {
		name     string
		acquired *XmuxClient
		wantBase int32
		wantDown int32
		wantDyn  int32
	}{
		{name: "upload base", acquired: base, wantBase: 1, wantDown: 1, wantDyn: 1},
		{name: "download base", acquired: download, wantBase: 1, wantDown: 1, wantDyn: 1},
		{name: "non-base dynamic", acquired: dynamic, wantBase: 1, wantDown: 1, wantDyn: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.acquired.AddRunning()
			releaseRedundantXmuxRotationReceipt(test.acquired, base, download)
			if got := base.Running.Load(); got != test.wantBase {
				t.Fatalf("base Running = %d, want %d", got, test.wantBase)
			}
			if got := download.Running.Load(); got != test.wantDown {
				t.Fatalf("download Running = %d, want %d", got, test.wantDown)
			}
			if got := dynamic.Running.Load(); got != test.wantDyn {
				t.Fatalf("dynamic Running = %d, want %d", got, test.wantDyn)
			}
			if test.acquired == dynamic {
				dynamic.DoneRunning()
			}
		})
	}
}
