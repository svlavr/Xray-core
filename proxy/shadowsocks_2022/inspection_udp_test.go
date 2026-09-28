package shadowsocks_2022

import (
	"sync"
	"testing"

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
