//go:build linux && !android

package tun

import (
	"errors"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// The platform and borrowed service are composed outside core.Close. A client's
// registration order cannot establish that OS DNS has already been reverted.
type compositionDNSClient struct {
	systemDNSLeaseClient
	events          *[]string
	closedWithLease bool
}

func (c *compositionDNSClient) Close() error {
	c.closedWithLease = c.acquired != c.released
	*c.events = append(*c.events, "client-close")
	return nil
}

func TestSystemDNSCompositionRevertBeforeBorrowedServiceClose(t *testing.T) {
	for _, mode := range []string{"ordered", "failed-revert", "core-close-alone"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			client := &compositionDNSClient{systemDNSLeaseClient: systemDNSLeaseClient{Client: localdns.New()}, events: &events}
			ctx := systemDNSClientContext(t, client)
			stubDNSRouting(t, nil)
			original := resolvectlRunner
			failRevert := mode == "failed-revert"
			resolvectlRunner = func(_ string, args ...string) ([]byte, error) {
				events = append(events, "os-"+args[0])
				if args[0] == "revert" && failRevert {
					return nil, errors.New("revert failed")
				}
				return nil, nil
			}
			t.Cleanup(func() { resolvectlRunner = original })
			tun := optedInTun()
			if err := tun.ConfigureSystemDNS(ctx, "tun"); err != nil {
				t.Fatal(err)
			}
			events = nil
			instance := core.FromContext(ctx)
			borrowedClosed := false
			closeBorrowed := func() { borrowedClosed = true; events = append(events, "borrowed-close") }
			if mode == "core-close-alone" {
				if err := instance.Close(); err != nil {
					t.Fatal(err)
				}
				if !client.closedWithLease || borrowedClosed {
					t.Fatal("registration-order Close unexpectedly establishes platform/service ordering")
				}
				tun.unsetSystemDNS()
				closeBorrowed()
				return
			}
			tun.unsetSystemDNS()
			if mode == "failed-revert" {
				if !tun.systemDNSDirty || client.released != 0 || borrowedClosed || !reflect.DeepEqual(events, []string{"os-revert"}) {
					t.Fatalf("failed revert released service custody: events=%v client=%+v", events, client)
				}
				// Composition retries cleanup without closing the borrowed service.
				failRevert = false
				tun.unsetSystemDNS()
			}
			if err := instance.Close(); err != nil {
				t.Fatal(err)
			}
			if borrowedClosed {
				t.Fatal("client Close closed borrowed service")
			}
			closeBorrowed()
			want := []string{"os-revert", "client-close", "borrowed-close"}
			if mode == "failed-revert" {
				want = append([]string{"os-revert"}, want...)
			}
			if client.closedWithLease || client.released != 1 || !reflect.DeepEqual(events, want) {
				t.Fatalf("wrong composition order: events=%v want=%v client=%+v", events, want, client)
			}
		})
	}
}
