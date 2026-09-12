//go:build linux

package wireguard

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const kernelNetlinkTimeout = 2 * time.Second

var kernelTableCursor struct {
	sync.Mutex
	next int
}

type realKernelOps struct {
	namespace kernelNamespaceID
	anchor    kernelNamespaceAnchor
	tunFile   *os.File
	ifName    string
	ifIndex   int
}

type ownedKernelTun struct {
	tun.Device
	dialer       *net.Dialer
	listenConfig *net.ListenConfig
	lease        *kernelOwnerLease
	link         kernelResource
	identityHold io.Closer

	mu           sync.Mutex
	deviceOwned  bool
	rawCloseOnce sync.Once
	rawCloseDone chan struct{}
	unresolved   []kernelResource
	releaseErr   error
	deviceErr    error
	finishOnce   sync.Once
	finishDone   chan struct{}
	finishErr    error
}

func createKernelTun(ctx context.Context, localAddresses, dnsServers []netip.Addr, mtu int) (tdev tun.Device, tnet *Net, err error) {
	var hasV4, hasV6 bool
	for _, address := range localAddresses {
		hasV4 = hasV4 || address.Is4()
		hasV6 = hasV6 || address.Is6()
	}

	id, anchor, err := openKernelNamespaceAnchor()
	if err != nil {
		return nil, nil, err
	}
	ops := &realKernelOps{namespace: id, anchor: anchor}
	table := 0
	if hasV6 {
		table, err = allocateKernelTable(ops)
		if err != nil {
			_ = anchor.Close()
			return nil, nil, err
		}
	}
	lease, err := acquireKernelOwner(ctx, id, anchor, ops, table, table)
	if err != nil {
		return nil, nil, err
	}
	ops.anchor = lease.owner.anchor
	if hasV4 {
		if err = lease.acquireSharedSysctl(ctx, "/proc/sys/net/ipv4/conf/all/rp_filter", "0"); err != nil {
			return nil, nil, lease.abort(context.Background(), fmt.Errorf("acquire shared rp_filter: %w", err))
		}
	}

	device, name, err := createExclusiveKernelTun(mtu)
	if err != nil {
		return nil, nil, lease.abort(context.Background(), err)
	}
	holdFD, err := unix.FcntlInt(device.File().Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, nil, lease.abort(context.Background(), stderrors.Join(err, device.Close()))
	}
	identityHold := os.NewFile(uintptr(holdFD), "/dev/net/tun ownership hold")
	owned := &ownedKernelTun{Device: device, lease: lease, identityHold: identityHold, rawCloseDone: make(chan struct{}), finishDone: make(chan struct{})}
	ops.tunFile = identityHold
	ops.ifName = name
	committed := false
	defer func() {
		if !committed {
			err = stderrors.Join(err, owned.Close())
		}
	}()

	handle, err := ops.newHandle()
	if err != nil {
		return nil, nil, err
	}
	defer handle.Close()
	link, err := handle.LinkByName(name)
	if err != nil {
		return nil, nil, err
	}
	index := link.Attrs().Index
	ops.ifIndex = index
	owned.link = kernelResource{kind: kernelLink, name: "link " + name, ifName: name, ifIndex: index}

	if hasV4 {
		resource := kernelResource{kind: kernelInterfaceSysctl, name: "ipv4 rp_filter " + name, ifName: name, ifIndex: index, path: "/proc/sys/net/ipv4/conf/" + name + "/rp_filter", target: "0"}
		if err = lease.apply(ctx, resource); err != nil {
			return nil, nil, err
		}
	}
	if hasV6 {
		resource := kernelResource{kind: kernelInterfaceSysctl, name: "ipv6 enable " + name, ifName: name, ifIndex: index, path: "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", target: "0"}
		if err = lease.apply(ctx, resource); err != nil {
			return nil, nil, err
		}
	}
	for _, address := range localAddresses {
		addr := netlink.Addr{IPNet: &net.IPNet{IP: address.AsSlice(), Mask: net.CIDRMask(address.BitLen(), address.BitLen())}}
		resource := kernelResource{kind: kernelAddress, name: "address " + addr.String(), ifName: name, ifIndex: index, address: addr}
		if err = lease.apply(ctx, resource); err != nil {
			return nil, nil, err
		}
	}
	if err = handle.LinkSetMTU(link, mtu); err != nil {
		return nil, nil, fmt.Errorf("set WireGuard TUN MTU: %w", err)
	}
	if err = handle.LinkSetUp(link); err != nil {
		return nil, nil, fmt.Errorf("set WireGuard TUN up: %w", err)
	}
	if hasV6 {
		route := netlink.Route{
			LinkIndex: index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Table:     table,
			Protocol:  unix.RTPROT_STATIC,
			Scope:     netlink.SCOPE_UNIVERSE,
			Type:      unix.RTN_UNICAST,
			Family:    unix.AF_INET6,
		}
		resource := kernelResource{kind: kernelRoute, name: fmt.Sprintf("route table %d", table), ifName: name, ifIndex: index, table: table, route: route}
		if err = lease.apply(ctx, resource); err != nil {
			return nil, nil, err
		}
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority = unix.AF_INET6, table, table
		rule.OifName, rule.Protocol, rule.Type = name, unix.RTPROT_STATIC, unix.RTN_UNICAST
		resource = kernelResource{kind: kernelRule, name: fmt.Sprintf("rule priority %d", table), ifName: name, ifIndex: index, table: table, priority: table, rule: *rule}
		if err = lease.apply(ctx, resource); err != nil {
			return nil, nil, err
		}
	}

	control := func(_ string, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) { bindErr = syscall.BindToDevice(int(fd), name) }); err != nil {
			return err
		}
		return bindErr
	}
	owned.dialer = &net.Dialer{Control: control}
	owned.listenConfig = &net.ListenConfig{Control: control}
	committed = true
	return owned, newNet(owned.DialContextTCPAddrPort, owned.DialUDPAddrPort, dnsServers, hasV4, hasV6), nil
}

func createExclusiveKernelTun(mtu int) (tun.Device, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	ifreq, err := unix.NewIfreq("wg%d")
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}
	ifreq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_TUN_EXCL)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq); err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	device, err := tun.CreateTUNFromFile(file, mtu)
	if err != nil {
		return nil, "", err // the maintained dependency owns and closes file on error
	}
	name, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	return device, name, nil
}

func openKernelNamespaceAnchor() (kernelNamespaceID, *os.File, error) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return kernelNamespaceID{}, nil, err
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(file.Fd()), &stat); err != nil {
		_ = file.Close()
		return kernelNamespaceID{}, nil, err
	}
	return kernelNamespaceID{dev: uint64(stat.Dev), ino: stat.Ino}, file, nil
}

func (o *realKernelOps) newHandle() (*netlink.Handle, error) {
	return newKernelNetlinkHandle(o.anchor)
}

func newKernelNetlinkHandle(anchor kernelNamespaceAnchor) (*netlink.Handle, error) {
	if anchor == nil {
		return nil, stderrors.New("WireGuard kernel namespace anchor is unavailable")
	}
	handle, err := netlink.NewHandleAt(netns.NsHandle(anchor.Fd()), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = handle.SetSocketTimeout(kernelNetlinkTimeout); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

func (o *realKernelOps) readSysctl(path string) (string, error) {
	data, err := os.ReadFile(path)
	return strings.TrimSpace(string(data)), err
}

func (o *realKernelOps) writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}

func (o *realKernelOps) releaseIdentity(ctx context.Context, resource kernelResource) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if o.tunFile == nil || o.ifName == "" || o.ifIndex == 0 || resource.ifName != o.ifName || resource.ifIndex != o.ifIndex {
		return false, nil
	}
	ifreq, err := unix.NewIfreq("")
	if err != nil {
		return false, err
	}
	if err = unix.IoctlIfreq(int(o.tunFile.Fd()), unix.TUNGETIFF, ifreq); err != nil {
		return false, err
	}
	if ifreq.Name() != o.ifName {
		return false, nil
	}
	handle, err := o.newHandle()
	if err != nil {
		return false, err
	}
	defer handle.Close()
	link, err := handle.LinkByIndex(o.ifIndex)
	if isLinkNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return link.Attrs().Name == o.ifName, nil
}

func (o *realKernelOps) mutate(ctx context.Context, action kernelAction, resource kernelResource) kernelMutationResult {
	if err := ctx.Err(); err != nil {
		return kernelMutationResult{mutationErr: err}
	}
	if resource.kind == kernelInterfaceSysctl {
		var mutationErr error
		if action == kernelApply {
			mutationErr = o.writeSysctl(resource.path, resource.target)
		}
		result := o.observeSysctl(resource)
		result.acknowledged = mutationErr == nil
		result.mutationErr = mutationErr
		return result
	}
	handle, err := o.newHandle()
	if err != nil {
		return kernelMutationResult{mutationErr: err}
	}
	defer handle.Close()
	var mutationErr error
	switch resource.kind {
	case kernelAddress:
		link, linkErr := handle.LinkByIndex(resource.ifIndex)
		if linkErr != nil {
			mutationErr = linkErr
		} else if action == kernelApply {
			mutationErr = handle.AddrAdd(link, &resource.address)
		} else {
			mutationErr = handle.AddrDel(link, &resource.address)
		}
	case kernelRoute:
		if action == kernelApply {
			mutationErr = handle.RouteAdd(&resource.route)
		} else {
			mutationErr = handle.RouteDel(&resource.route)
		}
	case kernelRule:
		if action == kernelApply {
			mutationErr = handle.RuleAdd(&resource.rule)
		} else {
			mutationErr = handle.RuleDel(&resource.rule)
		}
	}
	verifyHandle, verifyErr := o.newHandle()
	if verifyErr != nil {
		return kernelMutationResult{acknowledged: mutationErr == nil, mutationErr: mutationErr, observeErr: verifyErr}
	}
	defer verifyHandle.Close()
	result := o.observeWithHandle(verifyHandle, resource)
	result.acknowledged = mutationErr == nil
	result.mutationErr = mutationErr
	if mutationErr != nil && action == kernelApply && result.observation == kernelOwned {
		// A visible identical object after a lost ACK has no incarnation token.
		result.observation = kernelUnknown
	}
	return result
}

func (o *realKernelOps) observeSysctl(resource kernelResource) kernelMutationResult {
	value, err := o.readSysctl(resource.path)
	if os.IsNotExist(err) {
		return kernelMutationResult{complete: true, observation: kernelAbsent}
	}
	if err != nil {
		return kernelMutationResult{observeErr: err}
	}
	if value == resource.target {
		return kernelMutationResult{complete: true, observation: kernelOwned, normalized: cloneKernelResource(resource)}
	}
	return kernelMutationResult{complete: true, observation: kernelConflict}
}

func (o *realKernelOps) observeWithHandle(handle *netlink.Handle, resource kernelResource) kernelMutationResult {
	switch resource.kind {
	case kernelLink:
		link, err := handle.LinkByIndex(resource.ifIndex)
		if isLinkNotFound(err) {
			return kernelMutationResult{complete: true, observation: kernelAbsent}
		}
		if err != nil {
			return kernelMutationResult{observeErr: err}
		}
		if link.Attrs().Name != resource.ifName {
			return kernelMutationResult{complete: true, observation: kernelConflict}
		}
		return kernelMutationResult{complete: true, observation: kernelOwned, normalized: cloneKernelResource(resource)}
	case kernelAddress:
		link, err := handle.LinkByIndex(resource.ifIndex)
		if isLinkNotFound(err) {
			return kernelMutationResult{complete: true, observation: kernelAbsent}
		}
		if err != nil {
			return kernelMutationResult{observeErr: err}
		}
		addresses, err := handle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return kernelMutationResult{observeErr: err}
		}
		for _, candidate := range addresses {
			if sameAddress(candidate, resource.address) {
				normalized := cloneKernelResource(resource)
				normalized.address = cloneNetlinkAddr(candidate)
				return kernelMutationResult{complete: true, observation: kernelOwned, normalized: normalized}
			}
		}
		return kernelMutationResult{complete: true, observation: kernelAbsent}
	case kernelRoute:
		filter := &netlink.Route{Table: resource.table}
		routes, err := handle.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_TABLE)
		if err != nil {
			return kernelMutationResult{interrupted: stderrors.Is(err, netlink.ErrDumpInterrupted), observeErr: err}
		}
		var matched *netlink.Route
		for i := range routes {
			if sameRoute(routes[i], resource.route) {
				copy := routes[i]
				matched = &copy
				continue
			}
			return kernelMutationResult{complete: true, observation: kernelConflict}
		}
		if matched == nil {
			return kernelMutationResult{complete: true, observation: kernelAbsent}
		}
		normalized := cloneKernelResource(resource)
		normalized.route = cloneNetlinkRoute(*matched)
		return kernelMutationResult{complete: true, observation: kernelOwned, normalized: normalized}
	case kernelRule:
		rules, err := handle.RuleList(netlink.FAMILY_V6)
		if err != nil {
			return kernelMutationResult{interrupted: stderrors.Is(err, netlink.ErrDumpInterrupted), observeErr: err}
		}
		var matched *netlink.Rule
		for i := range rules {
			candidate := rules[i]
			if candidate.Priority != resource.priority && candidate.Table != resource.table {
				continue
			}
			if sameRule(candidate, resource.rule) {
				candidate.Type = resource.rule.Type
				copy := candidate
				matched = &copy
				continue
			}
			return kernelMutationResult{complete: true, observation: kernelConflict}
		}
		if matched == nil {
			return kernelMutationResult{complete: true, observation: kernelAbsent}
		}
		normalized := cloneKernelResource(resource)
		normalized.rule = cloneNetlinkRule(*matched)
		return kernelMutationResult{complete: true, observation: kernelOwned, normalized: normalized}
	}
	return kernelMutationResult{}
}

func (o *realKernelOps) reconcile(ctx context.Context, id kernelNamespaceID, anchor kernelNamespaceAnchor, resources []kernelResource) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if id != o.namespace {
		return false, stderrors.New("WireGuard kernel namespace identity mismatch")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(anchor.Fd()), &stat); err != nil {
		return false, err
	}
	if uint64(stat.Dev) != id.dev || stat.Ino != id.ino {
		return false, stderrors.New("WireGuard retained namespace identity mismatch")
	}
	handle, err := newKernelNetlinkHandle(anchor)
	if err != nil {
		return false, err
	}
	defer handle.Close()
	for _, resource := range resources {
		var result kernelMutationResult
		if resource.kind == kernelInterfaceSysctl {
			result = o.observeSysctl(resource)
		} else {
			result = o.observeWithHandle(handle, resource)
		}
		if result.observeErr != nil || !result.complete || result.interrupted {
			return false, stderrors.Join(result.observeErr, stderrors.New("incomplete WireGuard kernel reconciliation"))
		}
		if result.observation != kernelAbsent {
			return false, nil
		}
	}
	return true, nil
}

func (t *ownedKernelTun) Close() error {
	t.rawCloseOnce.Do(func() {
		t.unresolved, t.releaseErr = t.lease.releaseBeforeTun(context.Background())
		t.deviceErr = t.Device.Close()
		if t.identityHold != nil {
			t.deviceErr = stderrors.Join(t.deviceErr, t.identityHold.Close())
		}
		t.unresolved = append(t.unresolved, cloneKernelResource(t.link))
		close(t.rawCloseDone)
	})
	<-t.rawCloseDone
	t.mu.Lock()
	deferred := t.deviceOwned
	t.mu.Unlock()
	if !deferred {
		return t.finalizeOwner()
	}
	return t.deviceErr
}

func (t *ownedKernelTun) closeOutcome() error {
	<-t.rawCloseDone
	return t.finalizeOwner()
}

func (t *ownedKernelTun) markDeviceOwned() {
	t.mu.Lock()
	t.deviceOwned = true
	t.mu.Unlock()
}

func (t *ownedKernelTun) finalizeOwner() error {
	t.finishOnce.Do(func() {
		t.finishErr = t.lease.finishAfterTun(context.Background(), t.unresolved, t.releaseErr, t.deviceErr)
		close(t.finishDone)
	})
	<-t.finishDone
	return t.finishErr
}

func (t *ownedKernelTun) DialContextTCPAddrPort(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	return t.dialer.DialContext(ctx, "tcp", address.String())
}

func (t *ownedKernelTun) DialUDPAddrPort(ctx context.Context, _, remote netip.AddrPort) (net.Conn, error) {
	conn, err := t.listenConfig.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{PacketConn: conn, Dest: net.UDPAddrFromAddrPort(remote)}, nil
}

func allocateKernelTable(ops *realKernelOps) (int, error) {
	handle, err := ops.newHandle()
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	routes, err := handle.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, err
	}
	rules4, err := handle.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return 0, err
	}
	rules6, err := handle.RuleList(netlink.FAMILY_V6)
	if err != nil {
		return 0, err
	}
	used := make(map[int]struct{})
	for _, route := range routes {
		used[route.Table] = struct{}{}
	}
	for _, rule := range append(rules4, rules6...) {
		used[rule.Table] = struct{}{}
		used[rule.Priority] = struct{}{}
	}
	reserved := kernelReservedIDs(ops.namespace)
	kernelTableCursor.Lock()
	defer kernelTableCursor.Unlock()
	if kernelTableCursor.next == 0 {
		kernelTableCursor.next = 10230
	}
	candidate, next, err := selectKernelTable(kernelTableCursor.next, used, reserved)
	if err != nil {
		return 0, err
	}
	kernelTableCursor.next = next
	return candidate, nil
}

func selectKernelTable(start int, used, reserved map[int]struct{}) (int, int, error) {
	candidate := start
	for checked := 0; checked < 32765; checked++ {
		next := candidate + 1
		if next > 32765 {
			next = 1
		}
		if candidate == 253 || candidate == 254 || candidate == 255 {
			candidate = next
			continue
		}
		if _, found := used[candidate]; found {
			candidate = next
			continue
		}
		if _, found := reserved[candidate]; found {
			candidate = next
			continue
		}
		return candidate, next, nil
	}
	return 0, start, stderrors.New("no free WireGuard kernel table and rule priority")
}

func kernelReservedIDs(id kernelNamespaceID) map[int]struct{} {
	reserved := make(map[int]struct{})
	kernelNamespaceOwners.Lock()
	owner := kernelNamespaceOwners.owners[id]
	kernelNamespaceOwners.Unlock()
	if owner == nil {
		return reserved
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	for reservation := range owner.reserved {
		reserved[reservation.id] = struct{}{}
	}
	return reserved
}

func sameAddress(a, b netlink.Addr) bool {
	return a.IPNet != nil && b.IPNet != nil && a.IPNet.String() == b.IPNet.String() && a.Label == b.Label
}

func sameRoute(a, b netlink.Route) bool {
	return a.Equal(b) && a.Family == b.Family && a.MTU == b.MTU && a.MTULock == b.MTULock && a.Window == b.Window && a.Rtt == b.Rtt && a.RttVar == b.RttVar && a.Ssthresh == b.Ssthresh && a.Cwnd == b.Cwnd && a.AdvMSS == b.AdvMSS && a.Reordering == b.Reordering && a.InitCwnd == b.InitCwnd && a.Features == b.Features && a.RtoMin == b.RtoMin && a.RtoMinLock == b.RtoMinLock && a.InitRwnd == b.InitRwnd && a.QuickACK == b.QuickACK && a.Congctl == b.Congctl && a.FastOpenNoCookie == b.FastOpenNoCookie
}

func sameRule(a, b netlink.Rule) bool {
	// netlink v1.3.1 does not copy fib_rule_hdr.Action into Rule.Type on
	// dumps. Every other decoded selector is compared; the acknowledged
	// requested action is retained in the normalized journal for exact delete.
	return a.Family == b.Family && a.Priority == b.Priority && a.Table == b.Table && a.OifName == b.OifName && a.IifName == b.IifName && a.Protocol == b.Protocol && a.Mark == b.Mark && sameMask(a.Mask, b.Mask) && sameIPNet(a.Src, b.Src) && sameIPNet(a.Dst, b.Dst) && a.Tos == b.Tos && a.TunID == b.TunID && a.Flow == b.Flow && a.Invert == b.Invert && a.Goto == b.Goto && a.SuppressIfgroup == b.SuppressIfgroup && a.SuppressPrefixlen == b.SuppressPrefixlen && sameRulePortRange(a.Dport, b.Dport) && sameRulePortRange(a.Sport, b.Sport) && a.IPProto == b.IPProto && sameRuleUIDRange(a.UIDRange, b.UIDRange)
}

func sameRulePortRange(a, b *netlink.RulePortRange) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Start == b.Start && a.End == b.End
}

func sameRuleUIDRange(a, b *netlink.RuleUIDRange) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Start == b.Start && a.End == b.End
}

func sameMask(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameIPNet(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func isLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	var notFound netlink.LinkNotFoundError
	return stderrors.As(err, &notFound)
}

func KernelTunSupported() (bool, error) {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = 0
	var data unix.CapUserData
	if err := unix.Capget(&hdr, &data); err != nil {
		return false, fmt.Errorf("failed to get capabilities: %v", err)
	}
	return (data.Effective & (1 << unix.CAP_NET_ADMIN)) != 0, nil
}
