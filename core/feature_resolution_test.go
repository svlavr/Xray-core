package core_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

func TestFeatureResolutionPreservesCallbackErrors(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			instance := new(core.Instance)
			failures := []error{errors.New("first"), errors.New("second"), errors.New("optional")}
			var calls []int
			for i := range failures {
				if err := instance.RequireFeatures(func(d dns.Client) error {
					calls = append(calls, i)
					if mask&(1<<i) != 0 {
						return failures[i]
					}
					return nil
				}, i == 2); err != nil {
					t.Fatal(err)
				}
			}
			feature := localdns.New()
			err := instance.AddFeature(feature)
			if !slices.Equal(calls, []int{0, 1, 2}) || instance.GetFeature(dns.ClientType()) != feature {
				t.Fatalf("callback execution/order or registration changed: %v", calls)
			}
			if mask == 0 && err != nil {
				t.Fatalf("successful resolution failed: %v", err)
			}
			for i, failure := range failures {
				if errors.Is(err, failure) != (mask&(1<<i) != 0) {
					t.Fatalf("callback %d error missing or fabricated: %v", i, err)
				}
			}
		})
	}
}
