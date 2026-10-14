package dns

import (
	"context"
	"errors"
	"fmt"
	featuredns "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
	"runtime"
	"testing"
	"time"
)

// A real terminal A outcome is selected first; only the unanswered AAAA family
// is interrupted. Cancellation cannot rewrite that already-selected outcome.
func TestCachedFetchSelectedTerminalThenCancellation(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("disabled=%v/raw=%v", disabled, raw), func(t *testing.T) {
				cache := NewCacheController(t.Name(), disabled, false, 0)
				defer cache.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				selected := make(chan struct{})
				want := error(featuredns.RCodeError(dnsmessage.RCodeNameError))
				if raw {
					want = errors.New("definitive native response error")
				}
				server := &candidateNameserver{cache: cache}
				server.send = func(_ context.Context, ch chan<- error, fqdn string, _ featuredns.IPOption) {
					if raw {
						ch <- want
					} else {
						cache.pub.Publish(cache.keyPrefix+fqdn+"4", &IPRecord{Expire: time.Now().Add(time.Minute), RCode: dnsmessage.RCodeNameError})
					}
					go func() {
						defer close(selected)
						deadline := time.Now().Add(3 * time.Second)
						for {
							consumed := len(ch) == 0
							if !raw {
								consumed = dnsTestLiveSubscribers(cache, fqdn+"4") == 0
							}
							if consumed {
								cancel()
								return
							}
							if time.Now().After(deadline) {
								t.Error("terminal outcome was not selected")
								cancel()
								return
							}
							runtime.Gosched()
						}
					}()
				}
				got := doFetch(ctx, server, "terminal.example.", featuredns.IPOption{IPv4Enable: true, IPv6Enable: true})
				<-selected
				if got.error != want || got.interrupted || got.retryableLeaderExpiry || len(got.ips) != 0 {
					t.Fatalf("selected terminal was lost or made retryable: %+v, want %v", got, want)
				}
			})
		}
	}
}
