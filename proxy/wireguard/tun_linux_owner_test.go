//go:build linux

package wireguard

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

type ownerTestAnchor struct{ closes atomic.Int32 }

func (a *ownerTestAnchor) Close() error { a.closes.Add(1); return nil }
func (a *ownerTestAnchor) Fd() uintptr  { return 1 }

type ownerTestOps struct {
	mu              sync.Mutex
	results         []kernelMutationResult
	actions         []kernelAction
	resources       []kernelResource
	reconcileAbsent bool
	reconcileErr    error
	sysctl          map[string]string
	readErrors      []error
	writeErr        error
	releaseOwned    *bool
	releaseErr      error
	beforeMutate    func(kernelAction, kernelResource)
	releaseCheck    func(kernelResource) (bool, error)
}

func (o *ownerTestOps) releaseIdentity(_ context.Context, resource kernelResource) (bool, error) {
	if o.releaseCheck != nil {
		return o.releaseCheck(resource)
	}
	if o.releaseOwned == nil {
		return true, o.releaseErr
	}
	return *o.releaseOwned, o.releaseErr
}

func (o *ownerTestOps) mutate(_ context.Context, action kernelAction, resource kernelResource) kernelMutationResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.beforeMutate != nil {
		o.beforeMutate(action, resource)
	}
	o.actions = append(o.actions, action)
	o.resources = append(o.resources, cloneKernelResource(resource))
	if len(o.results) == 0 {
		if action == kernelApply {
			return acknowledgedOwned(resource)
		}
		return confirmedAbsent()
	}
	result := o.results[0]
	o.results = o.results[1:]
	if result.normalized.name == "" {
		result.normalized = cloneKernelResource(resource)
	}
	return result
}

func (o *ownerTestOps) reconcile(context.Context, kernelNamespaceID, kernelNamespaceAnchor, []kernelResource) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reconcileAbsent, o.reconcileErr
}

func (o *ownerTestOps) readSysctl(path string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.readErrors) != 0 {
		err := o.readErrors[0]
		o.readErrors = o.readErrors[1:]
		if err != nil {
			return "", err
		}
	}
	value, found := o.sysctl[path]
	if !found {
		return "", os.ErrNotExist
	}
	return value, nil
}

func (o *ownerTestOps) writeSysctl(path, value string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	// Model a syscall result that can be lost after the value was applied.
	o.sysctl[path] = value
	return o.writeErr
}

func acknowledgedOwned(resource kernelResource) kernelMutationResult {
	return kernelMutationResult{acknowledged: true, complete: true, observation: kernelOwned, normalized: cloneKernelResource(resource)}
}

func confirmedAbsent() kernelMutationResult {
	return kernelMutationResult{complete: true, observation: kernelAbsent}
}

func resetKernelOwners(t *testing.T) {
	t.Helper()
	kernelNamespaceOwners.Lock()
	owners := kernelNamespaceOwners.owners
	kernelNamespaceOwners.owners = make(map[kernelNamespaceID]*kernelNamespaceOwner)
	kernelNamespaceOwners.Unlock()
	for _, owner := range owners {
		_ = owner.anchor.Close()
	}
}

func acquireTestLease(t *testing.T, id kernelNamespaceID, ops *ownerTestOps, anchor *ownerTestAnchor, table int) *kernelOwnerLease {
	t.Helper()
	lease, err := acquireKernelOwner(context.Background(), id, anchor, ops, table, table)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func testResource(name string) kernelResource {
	return kernelResource{kind: kernelRoute, name: name, table: 10230}
}

func TestKernelTunApplyAndRollbackOutcomes(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })

	t.Run("lost ACK confirmed absent", func(t *testing.T) {
		ops := &ownerTestOps{results: []kernelMutationResult{{complete: true, observation: kernelAbsent, mutationErr: errors.New("lost ACK")}}}
		anchor := new(ownerTestAnchor)
		lease := acquireTestLease(t, kernelNamespaceID{dev: 1, ino: 1}, ops, anchor, 10230)
		if err := lease.apply(context.Background(), testResource("route")); err == nil {
			t.Fatal("ambiguous apply succeeded")
		}
		if len(lease.journal) != 0 {
			t.Fatal("confirmed-absent resource entered rollback journal")
		}
		_ = lease.abort(context.Background(), errors.New("setup failed"))
		if anchor.closes.Load() != 1 {
			t.Fatal("confirmed rollback did not release namespace")
		}
	})

	t.Run("ACK then normalization failure remains rollback owned", func(t *testing.T) {
		resetKernelOwners(t)
		ops := &ownerTestOps{results: []kernelMutationResult{{acknowledged: true, observeErr: errors.New("dump interrupted")}, confirmedAbsent()}}
		lease := acquireTestLease(t, kernelNamespaceID{dev: 1, ino: 2}, ops, new(ownerTestAnchor), 10231)
		if err := lease.apply(context.Background(), testResource("rule")); err == nil {
			t.Fatal("un-normalized ACK succeeded")
		}
		if len(lease.journal) != 1 {
			t.Fatal("ACKed resource was lost from rollback journal")
		}
		unresolved, err := lease.releaseBeforeTun(context.Background())
		if err != nil || len(unresolved) != 0 {
			t.Fatalf("rollback unresolved=%d err=%v", len(unresolved), err)
		}
		if err := lease.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	})

	for name, result := range map[string]kernelMutationResult{
		"unacknowledged present": {complete: true, observation: kernelOwned, mutationErr: errors.New("lost ACK")},
		"replacement conflict":   {complete: true, observation: kernelConflict, mutationErr: errors.New("collision")},
		"interrupted dump":       {interrupted: true, observeErr: errors.New("dump interrupted")},
		"reconciliation failure": {observeErr: errors.New("read failed")},
	} {
		t.Run(name, func(t *testing.T) {
			resetKernelOwners(t)
			id := kernelNamespaceID{dev: 2, ino: uint64(len(name))}
			ops := &ownerTestOps{results: []kernelMutationResult{result}, reconcileErr: errors.New("still unknown")}
			anchor := new(ownerTestAnchor)
			lease := acquireTestLease(t, id, ops, anchor, 11000)
			if err := lease.apply(context.Background(), testResource("route")); err == nil {
				t.Fatal("unproven apply succeeded")
			}
			if _, err := acquireKernelOwner(context.Background(), id, new(ownerTestAnchor), ops, 11001, 11001); !errors.Is(err, errKernelNamespaceQuarantined) {
				t.Fatalf("next admission err=%v", err)
			}
			if anchor.closes.Load() != 0 {
				t.Fatal("quarantine released namespace anchor")
			}
		})
	}
}

func TestKernelTunPartialConstructionRollbackOrder(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })
	ops := &ownerTestOps{results: []kernelMutationResult{
		acknowledgedOwned(testResource("one")),
		acknowledgedOwned(testResource("two")),
		{complete: true, observation: kernelAbsent, mutationErr: errors.New("third failed")},
		confirmedAbsent(), confirmedAbsent(),
	}}
	lease := acquireTestLease(t, kernelNamespaceID{dev: 3, ino: 4}, ops, new(ownerTestAnchor), 12000)
	for _, name := range []string{"one", "two"} {
		if err := lease.apply(context.Background(), testResource(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := lease.apply(context.Background(), testResource("three")); err == nil {
		t.Fatal("third apply succeeded")
	}
	unresolved, err := lease.releaseBeforeTun(context.Background())
	if err != nil || len(unresolved) != 0 {
		t.Fatalf("rollback unresolved=%d err=%v", len(unresolved), err)
	}
	if got := []string{ops.resources[3].name, ops.resources[4].name}; got[0] != "two" || got[1] != "one" {
		t.Fatalf("rollback order=%v", got)
	}
	if err = lease.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestKernelTunRollbackRetainsEveryUnattemptedResource(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })
	ops := &ownerTestOps{results: []kernelMutationResult{
		acknowledgedOwned(testResource("one")),
		acknowledgedOwned(testResource("two")),
		acknowledgedOwned(testResource("three")),
		{complete: true, observation: kernelOwned, mutationErr: errors.New("delete failed")},
	}}
	lease := acquireTestLease(t, kernelNamespaceID{dev: 3, ino: 5}, ops, new(ownerTestAnchor), 12001)
	for _, name := range []string{"one", "two", "three"} {
		if err := lease.apply(context.Background(), testResource(name)); err != nil {
			t.Fatal(err)
		}
	}
	unresolved, err := lease.releaseBeforeTun(context.Background())
	if err == nil || len(unresolved) != 3 {
		t.Fatalf("unresolved=%d err=%v", len(unresolved), err)
	}
	for i, want := range []string{"three", "two", "one"} {
		if unresolved[i].name != want {
			t.Fatalf("unresolved[%d]=%q want=%q", i, unresolved[i].name, want)
		}
	}
}

func TestKernelTunRollbackRefusesLostTUNIncarnation(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })
	owned := false
	ops := &ownerTestOps{releaseOwned: &owned}
	lease := acquireTestLease(t, kernelNamespaceID{dev: 3, ino: 6}, ops, new(ownerTestAnchor), 12002)
	for _, name := range []string{"address", "route"} {
		resource := testResource(name)
		resource.ifName = "wg0"
		resource.ifIndex = 7
		if err := lease.apply(context.Background(), resource); err != nil {
			t.Fatal(err)
		}
	}
	unresolved, err := lease.releaseBeforeTun(context.Background())
	if err == nil || len(unresolved) != 2 {
		t.Fatalf("unresolved=%d err=%v", len(unresolved), err)
	}
	if len(ops.actions) != 2 {
		t.Fatalf("destructive mutation ran after identity loss: actions=%v", ops.actions)
	}
}

func TestKernelTunSharedSysctlAndQuarantine(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })
	const path = "/proc/sys/net/ipv4/conf/all/rp_filter"
	id := kernelNamespaceID{dev: 4, ino: 5}
	ops := &ownerTestOps{sysctl: map[string]string{path: "2"}}
	firstAnchor := new(ownerTestAnchor)
	first := acquireTestLease(t, id, ops, firstAnchor, 12500)
	if err := first.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	secondAnchor := new(ownerTestAnchor)
	second := acquireTestLease(t, id, ops, secondAnchor, 12501)
	if secondAnchor.closes.Load() != 1 {
		t.Fatal("redundant namespace anchor was retained")
	}
	if err := second.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	if err := first.finishAfterTun(context.Background(), nil, nil, nil); err != nil || ops.sysctl[path] != "0" {
		t.Fatalf("first release err=%v value=%q", err, ops.sysctl[path])
	}
	if err := second.finishAfterTun(context.Background(), nil, nil, nil); err != nil || ops.sysctl[path] != "2" {
		t.Fatalf("last release err=%v value=%q", err, ops.sysctl[path])
	}
	if firstAnchor.closes.Load() != 1 {
		t.Fatal("namespace anchor not released after last holder")
	}

	resetKernelOwners(t)
	ops = &ownerTestOps{sysctl: map[string]string{path: "1"}, readErrors: []error{nil, errors.New("verification failed")}}
	anchor := new(ownerTestAnchor)
	lease := acquireTestLease(t, kernelNamespaceID{dev: 4, ino: 6}, ops, anchor, 12502)
	if err := lease.acquireSharedSysctl(context.Background(), path, "0"); err == nil {
		t.Fatal("lost verification succeeded")
	}
	lease.owner.mu.Lock()
	baseline := lease.owner.shared.baseline
	lease.owner.mu.Unlock()
	if baseline != "1" {
		t.Fatalf("baseline lost: %q", baseline)
	}
	if err := lease.abort(context.Background(), errors.New("setup failed")); err == nil {
		t.Fatal("abort lost setup error")
	}
	if ops.sysctl[path] != "1" {
		t.Fatalf("baseline not restored: %q", ops.sysctl[path])
	}
	if anchor.closes.Load() != 1 {
		t.Fatal("confirmed baseline restore did not release namespace owner")
	}

	resetKernelOwners(t)
	ops = &ownerTestOps{sysctl: map[string]string{path: "1"}}
	anchor = new(ownerTestAnchor)
	lease = acquireTestLease(t, kernelNamespaceID{dev: 4, ino: 7}, ops, anchor, 12503)
	if err := lease.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	ops.sysctl[path] = "2"
	if err := lease.finishAfterTun(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("external sysctl replacement was overwritten")
	}
	if ops.sysctl[path] != "2" || anchor.closes.Load() != 0 {
		t.Fatal("external conflict did not remain quarantined")
	}
	ops.sysctl[path] = "1"
	ops.reconcileAbsent = true
	recoveryAnchor := new(ownerTestAnchor)
	recovered, err := acquireKernelOwner(context.Background(), kernelNamespaceID{dev: 4, ino: 7}, recoveryAnchor, ops, 12504, 12504)
	if err != nil {
		t.Fatalf("read-only baseline reconciliation did not recover owner: %v", err)
	}
	if anchor.closes.Load() != 1 {
		t.Fatal("reconciled namespace owner retained its old anchor")
	}
	if err := recovered.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	resetKernelOwners(t)
	ops = &ownerTestOps{sysctl: map[string]string{path: "0"}, reconcileErr: errors.New("temporary interrupted reconciliation")}
	anchor = new(ownerTestAnchor)
	id = kernelNamespaceID{dev: 4, ino: 8}
	lease = acquireTestLease(t, id, ops, anchor, 12505)
	if err := lease.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	unresolved := []kernelResource{{kind: kernelLink, name: "link", token: lease.token, ifName: "wg0", ifIndex: 5}}
	if err := lease.finishAfterTun(context.Background(), unresolved, errors.New("delete unknown"), nil); err == nil {
		t.Fatal("interrupted final reconciliation succeeded")
	}
	lease.owner.mu.Lock()
	holders := lease.owner.shared.holders
	lease.owner.mu.Unlock()
	if holders != 0 {
		t.Fatalf("retired lease left shared holders=%d", holders)
	}
	ops.reconcileErr = nil
	ops.reconcileAbsent = true
	recoveryAnchor = new(ownerTestAnchor)
	recovered, err = acquireKernelOwner(context.Background(), id, recoveryAnchor, ops, 12506, 12506)
	if err != nil {
		t.Fatalf("read-only recovery after transient reconciliation failed: %v", err)
	}
	if anchor.closes.Load() != 1 {
		t.Fatal("recovered owner retained old namespace anchor")
	}
	if err := recovered.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	resetKernelOwners(t)
	ops = &ownerTestOps{sysctl: map[string]string{path: "2"}}
	id = kernelNamespaceID{dev: 4, ino: 9}
	anchor = new(ownerTestAnchor)
	first = acquireTestLease(t, id, ops, anchor, 12507)
	if err := first.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	second = acquireTestLease(t, id, ops, new(ownerTestAnchor), 12508)
	if err := second.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	ops.reconcileErr = errors.New("temporary interrupted reconciliation")
	unresolved = []kernelResource{{kind: kernelLink, name: "link", token: first.token, ifName: "wg0", ifIndex: 6}}
	if err := first.finishAfterTun(context.Background(), unresolved, errors.New("delete unknown"), nil); err == nil {
		t.Fatal("first holder lost unresolved cleanup")
	}
	ops.reconcileErr = nil
	if err := second.finishAfterTun(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("last live holder restored over transferred obligation")
	}
	if ops.sysctl[path] != "0" {
		t.Fatalf("shared baseline restored before dependent cleanup proof: %q", ops.sysctl[path])
	}
	second.owner.mu.Lock()
	holders = second.owner.shared.holders
	second.owner.mu.Unlock()
	if holders != 0 {
		t.Fatalf("transferred last holder count=%d", holders)
	}
	ops.sysctl[path] = "2"
	ops.reconcileAbsent = true
	recoveryAnchor = new(ownerTestAnchor)
	recovered, err = acquireKernelOwner(context.Background(), id, recoveryAnchor, ops, 12509, 12509)
	if err != nil {
		t.Fatalf("two-holder read-only recovery failed: %v", err)
	}
	if err := recovered.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	resetKernelOwners(t)
	ops = &ownerTestOps{sysctl: map[string]string{path: "2"}}
	id = kernelNamespaceID{dev: 4, ino: 10}
	anchor = new(ownerTestAnchor)
	first = acquireTestLease(t, id, ops, anchor, 12510)
	if err := first.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	second = acquireTestLease(t, id, ops, new(ownerTestAnchor), 12511)
	if err := second.acquireSharedSysctl(context.Background(), path, "0"); err != nil {
		t.Fatal(err)
	}
	ops.reconcileErr = errors.New("temporary interrupted reconciliation")
	unresolved = []kernelResource{{kind: kernelLink, name: "link", token: first.token, ifName: "wg0", ifIndex: 7}}
	if err := first.finishAfterTun(context.Background(), unresolved, errors.New("delete unknown"), nil); err == nil {
		t.Fatal("first holder lost unresolved cleanup")
	}
	ops.reconcileErr = nil
	if err := second.abort(context.Background(), errors.New("late construction failure")); err == nil {
		t.Fatal("peer construction abort lost cleanup failure")
	}
	second.owner.mu.Lock()
	for _, obligation := range second.owner.obligations {
		if obligation.kind == 0 {
			second.owner.mu.Unlock()
			t.Fatal("construction abort created an unreconcilable synthetic obligation")
		}
	}
	second.owner.mu.Unlock()
	ops.sysctl[path] = "2"
	ops.reconcileAbsent = true
	recoveryAnchor = new(ownerTestAnchor)
	recovered, err = acquireKernelOwner(context.Background(), id, recoveryAnchor, ops, 12512, 12512)
	if err != nil {
		t.Fatalf("read-only recovery after peer abort failed: %v", err)
	}
	if err := recovered.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

type ownerTestTun struct {
	closes atomic.Int32
	err    error
	events chan tun.Event
}

type ownerTestCloser struct{ closes atomic.Int32 }

func (c *ownerTestCloser) Close() error { c.closes.Add(1); return nil }

func (d *ownerTestTun) File() *os.File                         { return nil }
func (d *ownerTestTun) Read([][]byte, []int, int) (int, error) { return 0, os.ErrClosed }
func (d *ownerTestTun) Write([][]byte, int) (int, error)       { return 0, os.ErrClosed }
func (d *ownerTestTun) MTU() (int, error)                      { return 1500, nil }
func (d *ownerTestTun) Name() (string, error)                  { return "wg0", nil }
func (d *ownerTestTun) Events() <-chan tun.Event               { return d.events }
func (d *ownerTestTun) BatchSize() int                         { return 1 }
func (d *ownerTestTun) Close() error                           { d.closes.Add(1); return d.err }

func TestKernelTunCloseHandoffAndSequentialInstanceQuarantine(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })
	id := kernelNamespaceID{dev: 7, ino: 8}
	ops := &ownerTestOps{results: []kernelMutationResult{acknowledgedOwned(testResource("route")), confirmedAbsent()}, reconcileAbsent: true}
	anchor := new(ownerTestAnchor)
	lease := acquireTestLease(t, id, ops, anchor, 14000)
	if err := lease.apply(context.Background(), testResource("route")); err != nil {
		t.Fatal(err)
	}
	device := &ownerTestTun{events: make(chan tun.Event)}
	owned := &ownedKernelTun{Device: device, lease: lease, link: kernelResource{kind: kernelLink, name: "link", ifName: "wg0", ifIndex: 7}, rawCloseDone: make(chan struct{}), finishDone: make(chan struct{})}
	owned.markDeviceOwned()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = owned.Close() }()
	}
	wg.Wait()
	if device.closes.Load() != 1 || anchor.closes.Load() != 0 {
		t.Fatalf("device closes=%d anchor closes=%d", device.closes.Load(), anchor.closes.Load())
	}
	if err := owned.closeOutcome(); err != nil {
		t.Fatal(err)
	}
	if anchor.closes.Load() != 1 {
		t.Fatal("owner not released after device handoff")
	}

	resetKernelOwners(t)
	ops = &ownerTestOps{results: []kernelMutationResult{acknowledgedOwned(testResource("route")), {complete: true, observation: kernelOwned, mutationErr: errors.New("delete failed")}}, reconcileErr: errors.New("read failed")}
	anchor = new(ownerTestAnchor)
	lease = acquireTestLease(t, id, ops, anchor, 14001)
	if err := lease.apply(context.Background(), testResource("route")); err != nil {
		t.Fatal(err)
	}
	unresolved, releaseErr := lease.releaseBeforeTun(context.Background())
	if len(unresolved) != 1 || releaseErr == nil {
		t.Fatalf("unresolved=%d err=%v", len(unresolved), releaseErr)
	}
	if err := lease.finishAfterTun(context.Background(), unresolved, releaseErr, nil); err == nil {
		t.Fatal("unproven cleanup succeeded")
	}
	newAnchor := new(ownerTestAnchor)
	if _, err := acquireKernelOwner(context.Background(), id, newAnchor, ops, 14001, 14001); !errors.Is(err, errKernelNamespaceQuarantined) {
		t.Fatalf("subsequent Instance admission err=%v", err)
	}
	if anchor.closes.Load() != 0 || newAnchor.closes.Load() != 1 {
		t.Fatalf("old anchor=%d new anchor=%d", anchor.closes.Load(), newAnchor.closes.Load())
	}
}

func TestKernelTunIdentityHoldSurvivesDestructiveCleanup(t *testing.T) {
	resetKernelOwners(t)
	t.Cleanup(func() { resetKernelOwners(t) })
	id := kernelNamespaceID{dev: 8, ino: 9}
	device := &ownerTestTun{events: make(chan tun.Event)}
	hold := new(ownerTestCloser)
	ops := &ownerTestOps{reconcileAbsent: true}
	ops.releaseCheck = func(kernelResource) (bool, error) {
		if device.closes.Load() != 0 || hold.closes.Load() != 0 {
			t.Fatal("TUN incarnation was released before identity proof")
		}
		return true, nil
	}
	ops.beforeMutate = func(action kernelAction, _ kernelResource) {
		if action == kernelRelease && (device.closes.Load() != 0 || hold.closes.Load() != 0) {
			t.Fatal("TUN incarnation was released before destructive mutation")
		}
	}
	lease := acquireTestLease(t, id, ops, new(ownerTestAnchor), 14500)
	resource := testResource("route")
	resource.ifName, resource.ifIndex = "wg0", 7
	if err := lease.apply(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
	owned := &ownedKernelTun{Device: device, lease: lease, identityHold: hold, link: kernelResource{kind: kernelLink, name: "link", ifName: "wg0", ifIndex: 7}, rawCloseDone: make(chan struct{}), finishDone: make(chan struct{})}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if device.closes.Load() != 1 || hold.closes.Load() != 1 {
		t.Fatalf("device closes=%d hold closes=%d", device.closes.Load(), hold.closes.Load())
	}
}

func TestKernelTableSelectionCollisionWrapAndExhaustion(t *testing.T) {
	used := map[int]struct{}{10230: {}, 10231: {}, 253: {}, 254: {}, 255: {}}
	reserved := map[int]struct{}{10232: {}}
	selected, next, err := selectKernelTable(10230, used, reserved)
	if err != nil || selected != 10233 || next != 10234 {
		t.Fatalf("selected=%d next=%d err=%v", selected, next, err)
	}
	selected, next, err = selectKernelTable(32765, map[int]struct{}{32765: {}}, nil)
	if err != nil || selected != 1 || next != 2 {
		t.Fatalf("wrapped selected=%d next=%d err=%v", selected, next, err)
	}
	all := make(map[int]struct{}, 32765)
	for value := 1; value <= 32765; value++ {
		all[value] = struct{}{}
	}
	if _, _, err = selectKernelTable(10230, all, nil); err == nil {
		t.Fatal("exhausted table selection succeeded")
	}
}

func TestKernelOwnerCleanReleaseAdmissionRace(t *testing.T) {
	for iteration := range 200 {
		resetKernelOwners(t)
		id := kernelNamespaceID{dev: 9, ino: uint64(iteration + 1)}
		ops := &ownerTestOps{}
		first := acquireTestLease(t, id, ops, new(ownerTestAnchor), 15000)
		start := make(chan struct{})
		var second *kernelOwnerLease
		var acquireErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = first.finishAfterTun(context.Background(), nil, nil, nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			second, acquireErr = acquireKernelOwner(context.Background(), id, new(ownerTestAnchor), ops, 15001, 15001)
		}()
		close(start)
		wg.Wait()
		if acquireErr != nil {
			t.Fatalf("iteration %d admission failed: %v", iteration, acquireErr)
		}
		if err := second.finishAfterTun(context.Background(), nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	resetKernelOwners(t)
}
