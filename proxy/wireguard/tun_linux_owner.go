//go:build linux

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

type kernelNamespaceID struct{ dev, ino uint64 }

type kernelNamespaceAnchor interface {
	io.Closer
	Fd() uintptr
}

type kernelResourceKind uint8

const (
	kernelAddress kernelResourceKind = iota + 1
	kernelRoute
	kernelRule
	kernelLink
	kernelInterfaceSysctl
)

type kernelResource struct {
	kind     kernelResourceKind
	name     string
	token    uint64
	ifName   string
	ifIndex  int
	table    int
	priority int
	path     string
	target   string
	address  netlink.Addr
	route    netlink.Route
	rule     netlink.Rule
}

type kernelObservation uint8

const (
	kernelUnknown kernelObservation = iota
	kernelAbsent
	kernelOwned
	kernelConflict
)

type kernelMutationResult struct {
	acknowledged bool
	complete     bool
	interrupted  bool
	observation  kernelObservation
	normalized   kernelResource
	mutationErr  error
	observeErr   error
}

type kernelAction uint8

const (
	kernelApply kernelAction = iota + 1
	kernelRelease
)

type kernelOwnerOps interface {
	mutate(context.Context, kernelAction, kernelResource) kernelMutationResult
	releaseIdentity(context.Context, kernelResource) (bool, error)
	reconcile(context.Context, kernelNamespaceID, kernelNamespaceAnchor, []kernelResource) (bool, error)
	readSysctl(string) (string, error)
	writeSysctl(string, string) error
}

var (
	errKernelNamespaceQuarantined = errors.New("WireGuard kernel namespace is quarantined")
	errKernelReservationInUse     = errors.New("WireGuard kernel reservation is in use")
	errKernelOwnerRetired         = errors.New("WireGuard kernel namespace owner retired")
	kernelNamespaceOwners         = struct {
		sync.Mutex
		owners map[kernelNamespaceID]*kernelNamespaceOwner
	}{owners: make(map[kernelNamespaceID]*kernelNamespaceOwner)}
)

type kernelReservation struct {
	kind byte
	id   int
}

type sharedSysctlState struct {
	path     string
	target   string
	baseline string
	holders  int
	active   bool
}

type kernelNamespaceOwner struct {
	mu          sync.Mutex
	id          kernelNamespaceID
	anchor      kernelNamespaceAnchor
	leases      int
	nextToken   uint64
	reserved    map[kernelReservation]struct{}
	obligations []kernelResource
	quarantined bool
	recycling   bool
	retired     bool
	revision    uint64
	sharedGate  chan struct{}
	shared      sharedSysctlState
}

type kernelOwnerLease struct {
	owner        *kernelNamespaceOwner
	ops          kernelOwnerOps
	token        uint64
	reservations []kernelReservation
	journal      []kernelResource
	sharedHeld   bool

	finishOnce sync.Once
	finishDone chan struct{}
	finishErr  error
}

func acquireKernelOwner(ctx context.Context, id kernelNamespaceID, anchor kernelNamespaceAnchor, ops kernelOwnerOps, table, priority int) (*kernelOwnerLease, error) {
	if anchor == nil || ops == nil {
		return nil, errors.New("WireGuard kernel owner requires namespace anchor and operations")
	}
	for {
		kernelNamespaceOwners.Lock()
		owner := kernelNamespaceOwners.owners[id]
		if owner == nil {
			owner = &kernelNamespaceOwner{id: id, anchor: anchor, reserved: make(map[kernelReservation]struct{}), nextToken: 1, sharedGate: make(chan struct{}, 1)}
			owner.sharedGate <- struct{}{}
			kernelNamespaceOwners.owners[id] = owner
			kernelNamespaceOwners.Unlock()
			return owner.newLease(ops, table, priority)
		}
		kernelNamespaceOwners.Unlock()

		owner.mu.Lock()
		if owner.retired {
			owner.mu.Unlock()
			continue
		}
		if !owner.quarantined {
			owner.mu.Unlock()
			lease, err := owner.newLease(ops, table, priority)
			if errors.Is(err, errKernelOwnerRetired) {
				continue
			}
			_ = anchor.Close()
			return lease, err
		}
		if owner.recycling {
			owner.mu.Unlock()
			_ = anchor.Close()
			return nil, errKernelNamespaceQuarantined
		}
		owner.recycling = true
		obligations := cloneKernelResources(owner.obligations)
		shared := owner.shared
		if shared.active {
			obligations = withoutKernelResourcePath(obligations, shared.path)
		}
		revision := owner.revision
		ownerAnchor := owner.anchor
		owner.mu.Unlock()

		absent, reconcileErr := ops.reconcile(ctx, id, ownerAnchor, obligations)
		sharedSafe := !shared.active
		if reconcileErr == nil && shared.active && shared.holders == 0 {
			current, readErr := ops.readSysctl(shared.path)
			if readErr != nil {
				reconcileErr = readErr
			} else {
				sharedSafe = current == shared.baseline
			}
		}
		kernelNamespaceOwners.Lock()
		owner.mu.Lock()
		current := kernelNamespaceOwners.owners[id] == owner && !owner.retired
		owner.recycling = false
		unchanged := owner.revision == revision
		canRetire := current && unchanged && absent && sharedSafe && reconcileErr == nil && owner.leases == 0
		if canRetire {
			owner.obligations = nil
			owner.shared = sharedSysctlState{}
			owner.quarantined = false
			owner.retired = true
			delete(kernelNamespaceOwners.owners, id)
		}
		owner.mu.Unlock()
		kernelNamespaceOwners.Unlock()
		if !canRetire {
			_ = anchor.Close()
			return nil, errors.Join(errKernelNamespaceQuarantined, reconcileErr)
		}
		_ = ownerAnchor.Close()
	}
}

func (o *kernelNamespaceOwner) newLease(ops kernelOwnerOps, table, priority int) (*kernelOwnerLease, error) {
	reservations := make([]kernelReservation, 0, 2)
	if table != 0 {
		reservations = append(reservations, kernelReservation{kind: 't', id: table})
	}
	if priority != 0 {
		reservations = append(reservations, kernelReservation{kind: 'p', id: priority})
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired {
		return nil, errKernelOwnerRetired
	}
	if o.quarantined {
		return nil, errKernelNamespaceQuarantined
	}
	for _, reservation := range reservations {
		if _, found := o.reserved[reservation]; found {
			return nil, errKernelReservationInUse
		}
	}
	for _, reservation := range reservations {
		o.reserved[reservation] = struct{}{}
	}
	token := o.nextToken
	o.nextToken++
	o.leases++
	return &kernelOwnerLease{owner: o, ops: ops, token: token, reservations: reservations, finishDone: make(chan struct{})}, nil
}

func (l *kernelOwnerLease) apply(ctx context.Context, resource kernelResource) error {
	resource.token = l.token
	intentIndex := len(l.journal)
	l.journal = append(l.journal, cloneKernelResource(resource))
	result := l.ops.mutate(ctx, kernelApply, resource)
	if result.acknowledged {
		recorded := cloneKernelResource(resource)
		if result.complete && !result.interrupted && result.observation == kernelOwned && result.observeErr == nil {
			recorded = cloneKernelResource(result.normalized)
		}
		recorded.token = l.token
		l.journal[intentIndex] = recorded
		if result.complete && !result.interrupted && result.observation == kernelOwned && result.observeErr == nil && result.mutationErr == nil {
			return nil
		}
		return kernelMutationError("apply", resource.name, result)
	}
	l.journal = l.journal[:intentIndex]
	if result.complete && !result.interrupted && result.observation == kernelAbsent && result.observeErr == nil {
		return kernelMutationError("apply", resource.name, result)
	}
	l.quarantine(resource)
	return kernelMutationError("apply", resource.name, result)
}

func (l *kernelOwnerLease) acquireSharedSysctl(ctx context.Context, path, target string) error {
	o := l.owner
	select {
	case <-o.sharedGate:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { o.sharedGate <- struct{}{} }()

	o.mu.Lock()
	if o.quarantined || o.retired {
		o.mu.Unlock()
		return errKernelNamespaceQuarantined
	}
	active := o.shared.active
	baseline := o.shared.baseline
	o.mu.Unlock()

	current, err := l.ops.readSysctl(path)
	if err == nil && !active {
		baseline = current
	}
	if err == nil && active && current != target {
		err = fmt.Errorf("shared sysctl %s changed externally to %q", path, current)
	}
	writeMayHaveApplied := false
	if err == nil && !active && current != target {
		writeMayHaveApplied = true
		writeErr := l.ops.writeSysctl(path, target)
		observed, readErr := l.ops.readSysctl(path)
		switch {
		case readErr != nil:
			err = errors.Join(writeErr, readErr)
		case observed == target:
			err = nil
		case observed == baseline:
			err = writeErr
		default:
			err = errors.Join(writeErr, fmt.Errorf("sysctl %s is %q after write, want %q", path, observed, target))
		}
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil {
		if !o.shared.active {
			o.shared = sharedSysctlState{path: path, target: target, baseline: baseline, active: true}
		}
		o.shared.holders++
		o.revision++
		l.sharedHeld = true
		return nil
	}
	if writeMayHaveApplied {
		o.shared = sharedSysctlState{path: path, target: target, baseline: baseline, holders: 1, active: true}
		l.sharedHeld = true
	}
	o.quarantined = true
	o.revision++
	return err
}

func (l *kernelOwnerLease) releaseSharedSysctl(ctx context.Context) error {
	if !l.sharedHeld {
		return nil
	}
	o := l.owner
	select {
	case <-o.sharedGate:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { o.sharedGate <- struct{}{} }()

	o.mu.Lock()
	if o.shared.holders > 1 {
		o.shared.holders--
		o.revision++
		l.sharedHeld = false
		o.mu.Unlock()
		return nil
	}
	if len(o.obligations) != 0 {
		o.shared.holders = 0
		l.sharedHeld = false
		o.quarantined = true
		o.revision++
		o.mu.Unlock()
		return errors.New("shared sysctl remains owned until quarantined kernel resources are absent")
	}
	shared := o.shared
	o.mu.Unlock()

	current, err := l.ops.readSysctl(shared.path)
	if err == nil && current == shared.target && current != shared.baseline {
		writeErr := l.ops.writeSysctl(shared.path, shared.baseline)
		observed, readErr := l.ops.readSysctl(shared.path)
		switch {
		case readErr != nil:
			err = errors.Join(writeErr, readErr)
		case observed == shared.baseline:
			err = nil
		default:
			err = errors.Join(writeErr, fmt.Errorf("sysctl %s restore is %q, want %q", shared.path, observed, shared.baseline))
		}
	} else if err == nil && current != shared.baseline {
		err = fmt.Errorf("sysctl %s changed externally to %q", shared.path, current)
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil {
		o.shared = sharedSysctlState{}
		l.sharedHeld = false
		if len(o.obligations) == 0 {
			o.quarantined = false
		}
		o.revision++
		return nil
	}
	o.shared.holders = 0
	l.sharedHeld = false
	o.quarantined = true
	o.obligations = appendUniqueKernelResource(o.obligations, kernelResource{kind: kernelInterfaceSysctl, name: shared.path, path: shared.path, target: shared.target, token: l.token})
	o.revision++
	return err
}

func (l *kernelOwnerLease) releaseBeforeTun(ctx context.Context) ([]kernelResource, error) {
	var unresolved []kernelResource
	var releaseErr error
	for i := len(l.journal) - 1; i >= 0; i-- {
		resource := l.journal[i]
		if resource.kind != kernelInterfaceSysctl && resource.kind != kernelLink {
			owned, identityErr := l.ops.releaseIdentity(ctx, resource)
			if identityErr != nil || !owned {
				for j := i; j >= 0; j-- {
					unresolved = append(unresolved, cloneKernelResource(l.journal[j]))
				}
				releaseErr = errors.Join(releaseErr, identityErr, errors.New("WireGuard TUN incarnation is not proven for destructive cleanup"))
				break
			}
		}
		result := l.ops.mutate(ctx, kernelRelease, resource)
		if result.complete && !result.interrupted && result.observation == kernelAbsent && result.observeErr == nil {
			continue
		}
		unresolved = append(unresolved, cloneKernelResource(resource))
		for j := i - 1; j >= 0; j-- {
			unresolved = append(unresolved, cloneKernelResource(l.journal[j]))
		}
		releaseErr = errors.Join(releaseErr, kernelMutationError("release", resource.name, result))
		break
	}
	return unresolved, releaseErr
}

func (l *kernelOwnerLease) abort(ctx context.Context, cause error) error {
	cleanupErr := l.releaseSharedSysctl(ctx)
	proven := cleanupErr == nil
	if !proven {
		l.owner.mu.Lock()
		l.owner.quarantined = true
		l.owner.revision++
		l.owner.mu.Unlock()
	}
	l.finish(proven)
	return errors.Join(cause, cleanupErr)
}

func (l *kernelOwnerLease) finishAfterTun(ctx context.Context, unresolved []kernelResource, releaseErr, terminalErr error) error {
	l.finishOnce.Do(func() {
		l.owner.mu.Lock()
		for _, resource := range l.owner.obligations {
			if resource.token == l.token {
				unresolved = appendUniqueKernelResource(unresolved, resource)
			}
		}
		l.owner.mu.Unlock()
		if len(unresolved) != 0 {
			absent, err := l.ops.reconcile(ctx, l.owner.id, l.owner.anchor, unresolved)
			if err != nil || !absent {
				for _, resource := range unresolved {
					l.quarantine(resource)
				}
				releaseErr = errors.Join(releaseErr, errKernelNamespaceQuarantined, err)
			} else {
				l.owner.mu.Lock()
				l.owner.obligations = removeKernelObligations(l.owner.obligations, l.token)
				if len(l.owner.obligations) == 0 && !l.owner.shared.active {
					l.owner.quarantined = false
				}
				l.owner.revision++
				l.owner.mu.Unlock()
				unresolved = nil
				releaseErr = nil
			}
		}
		var sharedErr error
		if len(unresolved) == 0 {
			sharedErr = l.releaseSharedSysctl(ctx)
		} else {
			l.transferSharedSysctl()
		}
		proven := len(unresolved) == 0 && sharedErr == nil
		l.finish(proven)
		l.finishErr = errors.Join(releaseErr, terminalErr, sharedErr)
		close(l.finishDone)
	})
	<-l.finishDone
	return l.finishErr
}

func (l *kernelOwnerLease) transferSharedSysctl() {
	if !l.sharedHeld {
		return
	}
	o := l.owner
	<-o.sharedGate
	o.mu.Lock()
	if o.shared.holders > 0 {
		o.shared.holders--
	}
	l.sharedHeld = false
	o.quarantined = true
	o.revision++
	o.mu.Unlock()
	o.sharedGate <- struct{}{}
}

func (l *kernelOwnerLease) quarantine(resource kernelResource) {
	o := l.owner
	o.mu.Lock()
	o.quarantined = true
	for _, recorded := range l.journal {
		o.obligations = appendUniqueKernelResource(o.obligations, recorded)
	}
	o.obligations = appendUniqueKernelResource(o.obligations, resource)
	o.revision++
	o.mu.Unlock()
}

func (l *kernelOwnerLease) finish(proven bool) {
	o := l.owner
	o.mu.Lock()
	o.leases--
	if proven {
		for _, reservation := range l.reservations {
			delete(o.reserved, reservation)
		}
	}
	retire := proven && o.leases == 0 && !o.quarantined && !o.shared.active
	if retire {
		o.retired = true
	}
	o.mu.Unlock()
	if !retire {
		return
	}
	kernelNamespaceOwners.Lock()
	if kernelNamespaceOwners.owners[o.id] == o {
		delete(kernelNamespaceOwners.owners, o.id)
	}
	kernelNamespaceOwners.Unlock()
	_ = o.anchor.Close()
}

func kernelMutationError(action, name string, result kernelMutationResult) error {
	err := errors.Join(result.mutationErr, result.observeErr)
	if err == nil {
		err = errors.New("kernel outcome was not proven")
	}
	return fmt.Errorf("%s %s: %w", action, name, err)
}

func appendUniqueKernelResource(resources []kernelResource, resource kernelResource) []kernelResource {
	for _, existing := range resources {
		if existing.kind == resource.kind && existing.name == resource.name && existing.token == resource.token {
			return resources
		}
	}
	return append(resources, cloneKernelResource(resource))
}

func removeKernelObligations(resources []kernelResource, token uint64) []kernelResource {
	kept := resources[:0]
	for _, resource := range resources {
		if resource.token != token {
			kept = append(kept, resource)
		}
	}
	return kept
}

func withoutKernelResourcePath(resources []kernelResource, path string) []kernelResource {
	kept := resources[:0]
	for _, resource := range resources {
		if resource.path != path {
			kept = append(kept, resource)
		}
	}
	return kept
}

func cloneKernelResources(resources []kernelResource) []kernelResource {
	cloned := make([]kernelResource, len(resources))
	for i := range resources {
		cloned[i] = cloneKernelResource(resources[i])
	}
	return cloned
}

func cloneKernelResource(resource kernelResource) kernelResource {
	resource.address = cloneNetlinkAddr(resource.address)
	resource.route = cloneNetlinkRoute(resource.route)
	resource.rule = cloneNetlinkRule(resource.rule)
	return resource
}

func cloneNetlinkAddr(address netlink.Addr) netlink.Addr {
	cloned := address
	if address.IPNet != nil {
		cloned.IPNet = cloneIPNet(address.IPNet)
	}
	if address.Peer != nil {
		cloned.Peer = cloneIPNet(address.Peer)
	}
	return cloned
}

func cloneNetlinkRoute(route netlink.Route) netlink.Route {
	cloned := route
	cloned.Dst = cloneIPNet(route.Dst)
	cloned.Src = append(net.IP(nil), route.Src...)
	cloned.Gw = append(net.IP(nil), route.Gw...)
	return cloned
}

func cloneNetlinkRule(rule netlink.Rule) netlink.Rule {
	cloned := rule
	cloned.Src = cloneIPNet(rule.Src)
	cloned.Dst = cloneIPNet(rule.Dst)
	if rule.Mask != nil {
		mask := *rule.Mask
		cloned.Mask = &mask
	}
	return cloned
}

func cloneIPNet(value *net.IPNet) *net.IPNet {
	if value == nil {
		return nil
	}
	return &net.IPNet{IP: append(net.IP(nil), value.IP...), Mask: append(net.IPMask(nil), value.Mask...)}
}
