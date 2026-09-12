package tls

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func TestECHCacheOwnerCancellationJoinsBlockedUpdate(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	ctx := owner.Context()
	key := ECHCacheKeyContext(ctx, "udp://resolver", "example.com", nil)
	cache, err := newECHConfigCache(ctx, key, owner)
	if err != nil {
		t.Fatal(err)
	}
	GlobalECHConfigCache.Store(key, cache)
	entered := make(chan struct{})
	cache.query = func(ctx context.Context, _ *ECHConfigCache, _, _ string, _ *internet.SocketConfig) ([]byte, uint32, error) {
		close(entered)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	updateDone := make(chan error, 1)
	go func() {
		_, err := cache.UpdateContext(ctx, "example.com", "udp://resolver", nil)
		updateDone <- err
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.CloseAndWait() }()
	select {
	case err := <-updateDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("update error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner cancellation did not unblock ECH update")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner did not join ECH update")
	}
	if current, ok := GlobalECHConfigCache.Load(key); ok && current == cache {
		t.Fatal("closed ECH cache remained globally reachable")
	}
}

func TestECHCacheRejectsLatePublicationAfterSeal(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	ctx := owner.Context()
	key := ECHCacheKeyContext(ctx, "udp://resolver", "example.org", nil)
	cache, err := newECHConfigCache(ctx, key, owner)
	if err != nil {
		t.Fatal(err)
	}
	GlobalECHConfigCache.Store(key, cache)
	entered := make(chan struct{})
	release := make(chan struct{})
	cache.query = func(context.Context, *ECHConfigCache, string, string, *internet.SocketConfig) ([]byte, uint32, error) {
		close(entered)
		<-release
		return []byte{1, 2, 3}, 60, nil
	}
	updateDone := make(chan error, 1)
	go func() {
		_, err := cache.UpdateContext(ctx, "example.org", "udp://resolver", nil)
		updateDone <- err
	}()
	<-entered
	owner.SignalStop()
	close(release)
	if err := <-updateDone; err == nil {
		t.Fatal("late ECH result published after owner seal")
	}
	if record := cache.configRecord.Load(); record == nil || len(record.config) != 0 {
		t.Fatalf("late ECH result changed record: %+v", record)
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestECHCacheFreshHitRejectedAfterOwnerSeal(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	ctx := owner.Context()
	key := ECHCacheKeyContext(ctx, "udp://resolver", "fresh.example", nil)
	cache, err := newECHConfigCache(ctx, key, owner)
	if err != nil {
		t.Fatal(err)
	}
	cache.configRecord.Store(&echConfigRecord{config: []byte{9, 9}, expire: time.Now().Add(time.Hour)})
	GlobalECHConfigCache.Store(key, cache)
	owner.SignalStop()
	if config, err := QueryRecordContext(ctx, "fresh.example", "udp://resolver", nil); err == nil || config != nil {
		t.Fatalf("sealed fresh cache returned config=%v err=%v", config, err)
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestECHLegacyLockedUpdateParticipatesInOwnerReceipt(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	ctx := owner.Context()
	key := ECHCacheKeyContext(ctx, "udp://resolver", "legacy.example", nil)
	cache, err := newECHConfigCache(ctx, key, owner)
	if err != nil {
		t.Fatal(err)
	}
	GlobalECHConfigCache.Store(key, cache)
	entered := make(chan struct{})
	cache.query = func(ctx context.Context, _ *ECHConfigCache, _, _ string, _ *internet.SocketConfig) ([]byte, uint32, error) {
		close(entered)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	updateDone := make(chan error, 1)
	go func() {
		_, err := cache.Update("legacy.example", "udp://resolver", true, nil)
		updateDone <- err
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.CloseAndWait() }()
	select {
	case err := <-updateDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("legacy update error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy locked update did not observe owner cancellation")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner did not join legacy locked update")
	}
}

func TestTLSConfigLifecycleCancelsAndJoinsReload(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	config := new(Config)
	resource := newConfigLifecycle(owner.Context(), config)
	if resource == nil {
		t.Fatal("TLS config lifecycle was not created")
	}
	if got := newConfigLifecycle(owner.Context(), config); got != resource {
		t.Fatal("same owner/config did not reuse exact TLS lifecycle")
	}
	entered := make(chan struct{})
	returned := make(chan struct{})
	setupOcspTickerContext(resource, &Certificate{}, new(sync.RWMutex), func(ctx context.Context, _, _ bool) {
		close(entered)
		<-ctx.Done()
		close(returned)
	})
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.CloseAndWait() }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("TLS reload did not observe owner cancellation")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner did not join TLS reload")
	}
	if current, ok := configLifecycles.Load(resource.key); ok && current == resource {
		t.Fatal("closed TLS lifecycle remained cached")
	}
}

func TestTLSConfigLifecycleClosesMasterKeyLog(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	resource := newConfigLifecycle(owner.Context(), new(Config))
	path := filepath.Join(t.TempDir(), "keys.log")
	writer := resource.keyLog(path)
	if writer == nil {
		t.Fatal("master key log was not opened")
	}
	if _, err := writer.Write([]byte("before close\n")); err != nil {
		t.Fatal(err)
	}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("after close\n")); err == nil {
		t.Fatal("master key log remained writable after owner close")
	}
}
