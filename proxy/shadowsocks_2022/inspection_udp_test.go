package shadowsocks_2022

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal"

	"github.com/xtls/xray-core/common/utils"
)

func TestInspectionSS2022RetiredSessionKeepsReplacement(t *testing.T) {
	sessions := utils.NewTypedSyncMap[uint64, *udpConnEntry]()
	const id uint64 = 42
	old := new(udpConnEntry)
	old.onClose = func() { sessions.CompareAndDelete(id, old) }
	sessions.Store(id, old)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := new(udpConnEntry)
	replacement.onClose = func() { sessions.CompareAndDelete(id, replacement) }
	sessions.Store(id, replacement)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() { defer workers.Done(); old.Close() }()
	}
	workers.Wait()
	if got, ok := sessions.Load(id); !ok || got != replacement {
		t.Fatal("old session retired its replacement")
	}
	if replacement.isClosed() {
		t.Fatal("replacement was stopped")
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := sessions.Load(id); ok {
		t.Fatal("replacement remains in active map")
	}
}

func TestInspectionSS2022TimerCloseReentry(t *testing.T) {
	for _, when := range []string{"before-timer", "timer-callback", "after-timer"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entry := &udpConnEntry{cancel: cancel}
			done := make(chan struct{})
			go func() {
				if when == "before-timer" {
					entry.Close()
				}
				timeout := time.Hour
				if when == "timer-callback" {
					timeout = 0
				}
				entry.setTimer(signal.CancelAfterInactivity(ctx, func() { entry.Close() }, timeout))
				entry.Close()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("recursive timer close blocked")
			}
			if ctx.Err() == nil || !entry.isClosed() {
				t.Fatal("association not closed")
			}
		})
	}
}
