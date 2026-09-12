package internet

import (
	"context"
	"fmt"
	"strings"
	"sync"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// Dialer is the interface for dialing outbound connections.
type Dialer interface {
	// Dial dials a system connection to the given destination.
	Dial(ctx context.Context, destination net.Destination) (stat.Connection, error)

	// DestIpAddress returns the ip of proxy server. It is useful in case of Android client, which prepare an IP before proxy connection is established
	DestIpAddress() net.IP

	// SetOutboundGateway set outbound gateway
	SetOutboundGateway(ctx context.Context, ob *session.Outbound)
}

// dialFunc is an interface to dial network connection to a specific destination.
type dialFunc func(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error)

var transportDialerCache = make(map[string]dialFunc)

// RegisterTransportDialer registers a Dialer with given name.
func RegisterTransportDialer(protocol string, dialer dialFunc) error {
	if _, found := transportDialerCache[protocol]; found {
		return errors.New(protocol, " dialer already registered").AtError()
	}
	transportDialerCache[protocol] = dialer
	return nil
}

// Dial dials a internet connection towards the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error) {
	owned := snapshotForContext(ctx) == nil && DialLifecycleFromContext(ctx) != nil
	operationCtx, release, err := WithDialOperation(ctx)
	if err != nil {
		return nil, err
	}
	ctx = operationCtx
	var connection stat.Connection
	if dest.Network == net.Network_TCP {
		if streamSettings == nil {
			s, err := ToMemoryStreamConfig(nil)
			if err != nil {
				release()
				return nil, errors.New("failed to create default stream settings").Base(err)
			}
			streamSettings = s
		}

		protocol := streamSettings.ProtocolName
		dialer := transportDialerCache[protocol]
		if dialer == nil {
			release()
			return nil, errors.New(protocol, " dialer not registered").AtError()
		}
		connection, err = dialer(ctx, dest, streamSettings)
	} else if dest.Network == net.Network_UDP {
		udpDialer := transportDialerCache["udp"]
		if udpDialer == nil {
			release()
			return nil, errors.New("UDP dialer not registered").AtError()
		}
		connection, err = udpDialer(ctx, dest, streamSettings)
	} else {
		release()
		return nil, errors.New("unknown network ", dest.Network)
	}
	if err != nil {
		release()
		return nil, err
	}
	ownedConnection := ownStatConnection(connection, release)
	var commitResource func() error
	if !owned {
		resourceRelease, commit, err := AdoptDialResource(ctx, ownedConnection)
		if err != nil {
			ownedConnection.commit(func() bool { return false })
			_ = ownedConnection.Close()
			return nil, err
		}
		ownedConnection.resourceRelease = resourceRelease
		commitResource = commit
	}
	ownedConnection.commit(context.AfterFunc(ctx, func() { _ = ownedConnection.Close() }))
	if commitResource != nil {
		if err := commitResource(); err != nil {
			_ = ownedConnection.Close()
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		_ = ownedConnection.Close()
		return nil, err
	}
	return ownedConnection, nil
}

// DestIpAddress returns the ip of proxy server. It is useful in case of Android client, which prepare an IP before proxy connection is established
func DestIpAddress() net.IP {
	dialerLock.RLock()
	dialer := effectiveSystemDialer
	dialerLock.RUnlock()
	return dialer.DestIpAddress()
}

func DestIpAddressForContext(ctx context.Context) net.IP {
	if lifecycle := DialLifecycleFromContext(ctx); lifecycle != nil {
		lifecycle.mu.Lock()
		dialer := lifecycle.dialer
		configured := lifecycle.configured
		lifecycle.mu.Unlock()
		if configured && dialer != nil {
			return dialer.DestIpAddress()
		}
	}
	return DestIpAddress()
}

var (
	dnsClient            dns.Client
	obm                  outbound.Manager
	dialDependenciesLock sync.RWMutex
)

func LookupForIP(domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	return LookupForIPContext(context.Background(), domain, strategy, localAddr)
}

// LookupForIPContext keeps legacy DNS behavior while allowing instance-owned
// callers to retain request cancellation when their DNS implementation supports
// the additive context-aware lookup capability.
func LookupForIPContext(ctx context.Context, domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	operationCtx, release, err := WithDialOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx = operationCtx
	dialDependenciesLock.RLock()
	client := dnsClient
	dialDependenciesLock.RUnlock()
	if snapshot := snapshotForContext(ctx); snapshot != nil {
		client = snapshot.dns
	}
	if client == nil {
		return nil, errors.New("DNS client not initialized").AtError()
	}
	lookup := func(option dns.IPOption) ([]net.IP, uint32, error) {
		if contextual, ok := client.(interface {
			LookupIPContext(context.Context, string, dns.IPOption) ([]net.IP, uint32, error)
		}); ok {
			return contextual.LookupIPContext(ctx, domain, option)
		}
		return client.LookupIP(domain, option)
	}
	ips, _, err := lookup(dns.IPOption{
		IPv4Enable: (localAddr == nil && strategy.PreferIP4()) || (localAddr != nil && localAddr.Family().IsIPv4() && (strategy.PreferIP4() || strategy.FallbackIP4())),
		IPv6Enable: (localAddr == nil && strategy.PreferIP6()) || (localAddr != nil && localAddr.Family().IsIPv6() && (strategy.PreferIP6() || strategy.FallbackIP6())),
	})
	{ // Resolve fallback
		if (len(ips) == 0 || err != nil) && strategy.HasFallback() && localAddr == nil {
			ips, _, err = lookup(dns.IPOption{
				IPv4Enable: strategy.FallbackIP4(),
				IPv6Enable: strategy.FallbackIP6(),
			})
		}
	}

	if err == nil && len(ips) == 0 {
		return nil, dns.ErrEmptyResponse
	}
	return ips, err
}

func redirect(ctx context.Context, dst net.Destination, obt string, h outbound.Handler, releaseEntries ...func()) net.Conn {
	errors.LogInfo(ctx, "redirecting request "+dst.String()+" to "+obt)
	outbounds := session.OutboundsFromContext(ctx)
	ctx = session.ContextWithOutbounds(ctx, append(outbounds, &session.Outbound{
		Target:  dst,
		Gateway: nil,
		Tag:     obt,
	})) // add another outbound in session ctx

	ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
	dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)

	link := &transport.Link{Reader: ur, Writer: dw}
	// Preserve the stable request-detachment behavior. Exact in-tree Handler
	// Dispatch immediately derives a fresh task from the retained generation
	// right carried in values, restoring generation cancellation before I/O.
	dispatchCtx := context.WithoutCancel(ctx)
	var detour *flow_observation.DetourScope
	if dst.Network == net.Network_TCP {
		detour = flow_observation.BeginDetour(ctx, link, obt, fmt.Sprintf("%T", h), flow_observation.HandlerEntryDialerProxy)
		dispatchCtx = detour.Context(dispatchCtx)
	}
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		if len(releaseEntries) != 0 && releaseEntries[0] != nil {
			defer releaseEntries[0]()
		}
		if detour != nil {
			defer detour.Release(nil)
		}
		h.Dispatch(dispatchCtx, link)
	}()
	var readerOpt cnc.ConnectionOption
	if dst.Network == net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(dr)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(dr)
	}
	nc := cnc.NewConnection(
		cnc.ConnectionInputMulti(uw),
		readerOpt,
		cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
	)
	return &redirectConnection{Conn: nc, done: dispatchDone}
}

func checkAddressPortStrategy(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (*net.Destination, error) {
	if sockopt.AddressPortStrategy == AddressPortStrategy_None {
		return nil, nil
	}
	newDest := dest
	var OverridePort, OverrideAddress bool
	var OverrideBy string
	switch sockopt.AddressPortStrategy {
	case AddressPortStrategy_SrvPortOnly:
		OverridePort = true
		OverrideAddress = false
		OverrideBy = "srv"
	case AddressPortStrategy_SrvAddressOnly:
		OverridePort = false
		OverrideAddress = true
		OverrideBy = "srv"
	case AddressPortStrategy_SrvPortAndAddress:
		OverridePort = true
		OverrideAddress = true
		OverrideBy = "srv"
	case AddressPortStrategy_TxtPortOnly:
		OverridePort = true
		OverrideAddress = false
		OverrideBy = "txt"
	case AddressPortStrategy_TxtAddressOnly:
		OverridePort = false
		OverrideAddress = true
		OverrideBy = "txt"
	case AddressPortStrategy_TxtPortAndAddress:
		OverridePort = true
		OverrideAddress = true
		OverrideBy = "txt"
	default:
		return nil, errors.New("unknown AddressPortStrategy")
	}

	if !dest.Address.Family().IsDomain() {
		return nil, nil
	}

	if OverrideBy == "srv" {
		errors.LogDebug(ctx, "query SRV record for "+dest.Address.String())
		parts := strings.SplitN(dest.Address.String(), ".", 3)
		if len(parts) != 3 {
			return nil, errors.New("invalid address format", dest.Address.String())
		}
		_, srvRecords, err := net.DefaultResolver.LookupSRV(ctx, parts[0][1:], parts[1][1:], parts[2])
		if err != nil {
			return nil, errors.New("failed to lookup SRV record").Base(err)
		}
		errors.LogDebug(ctx, "SRV record: "+fmt.Sprintf("addr=%s, port=%d, priority=%d, weight=%d", srvRecords[0].Target, srvRecords[0].Port, srvRecords[0].Priority, srvRecords[0].Weight))
		if OverridePort {
			newDest.Port = net.Port(srvRecords[0].Port)
		}
		if OverrideAddress {
			newDest.Address = net.ParseAddress(srvRecords[0].Target)
		}
		return &newDest, nil
	}
	if OverrideBy == "txt" {
		errors.LogDebug(ctx, "query TXT record for "+dest.Address.String())
		txtRecords, err := net.DefaultResolver.LookupTXT(ctx, dest.Address.String())
		if err != nil {
			errors.LogError(ctx, "failed to lookup SRV record: "+err.Error())
			return nil, errors.New("failed to lookup SRV record").Base(err)
		}
		for _, txtRecord := range txtRecords {
			errors.LogDebug(ctx, "TXT record: "+txtRecord)
			addr_s, port_s, _ := net.SplitHostPort(string(txtRecord))
			addr := net.ParseAddress(addr_s)
			port, err := net.PortFromString(port_s)
			if err != nil {
				continue
			}

			if OverridePort {
				newDest.Port = port
			}
			if OverrideAddress {
				newDest.Address = addr
			}
			return &newDest, nil
		}
	}
	return nil, nil
}

// DialSystem calls system dialer to create a network connection.
func DialSystem(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	operationCtx, release, err := WithDialOperation(ctx)
	if err != nil {
		return nil, err
	}
	ctx = operationCtx
	connection, err := dialSystemOperation(ctx, dest, sockopt)
	if err != nil {
		release()
		return nil, err
	}
	if sockopt != nil && len(sockopt.DialerProxy) > 0 {
		return ownSystemConnection(ctx, connection, release), nil
	}
	release()
	return connection, nil
}

func dialSystemOperation(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	var src net.Address
	outbounds := session.OutboundsFromContext(ctx)
	var outboundName string
	var origTargetAddr net.Address
	if len(outbounds) > 0 {
		ob := outbounds[len(outbounds)-1]
		if sockopt == nil || len(sockopt.DialerProxy) == 0 {
			src = ob.Gateway
		}
		outboundName = ob.Name
		origTargetAddr = ob.OriginalTarget.Address
		if origTargetAddr == nil {
			origTargetAddr = ob.Target.Address
		}
	}
	dialer := systemDialerForContext(ctx)
	if sockopt == nil {
		return dialer.Dial(ctx, src, dest, sockopt)
	}

	if newDest, err := checkAddressPortStrategy(ctx, dest, sockopt); err == nil && newDest != nil {
		errors.LogInfo(ctx, "replace destination with "+newDest.String())
		dest = *newDest
	}

	if sockopt.DomainStrategy.HasStrategy() && dest.Address.Family().IsDomain() {
		finalStrategy := sockopt.DomainStrategy
		if outboundName == "freedom" && dest.Network == net.Network_UDP && origTargetAddr != nil && src == nil {
			finalStrategy = finalStrategy.GetDynamicStrategy(origTargetAddr.Family())
		}
		ips, err := LookupForIPContext(ctx, dest.Address.Domain(), finalStrategy, src)
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to resolve ip")
			if sockopt.DomainStrategy.ForceIP() {
				return nil, err
			}
		} else if sockopt.HappyEyeballs == nil || sockopt.HappyEyeballs.TryDelayMs == 0 || sockopt.HappyEyeballs.MaxConcurrentTry == 0 || len(ips) < 2 || len(sockopt.DialerProxy) > 0 || dest.Network != net.Network_TCP {
			dest.Address = net.IPAddress(ips[dice.Roll(len(ips))])
			errors.LogInfo(ctx, "replace destination with "+dest.String())
		} else {
			return tcpRaceDialWithDialer(ctx, src, ips, dest.Port, sockopt, dest.Address.String(), dialer)
		}
	}

	if len(sockopt.DialerProxy) > 0 {
		dialDependenciesLock.RLock()
		manager := obm
		dialDependenciesLock.RUnlock()
		if snapshot := snapshotForContext(ctx); snapshot != nil {
			manager = snapshot.outbound
		}
		if manager == nil {
			return nil, errors.New("there is no outbound manager for dialerProxy").AtError()
		}
		var h outbound.Handler
		var releaseEntry func()
		if generationManager, ok := manager.(outbound.GenerationManager); ok {
			entry, err := generationManager.EnterHandler(ctx, sockopt.DialerProxy)
			if err != nil {
				return nil, errors.New("there is no active outbound handler for dialerProxy").Base(err).AtError()
			}
			h = entry.Handler()
			ctx = entry.Context()
			releaseEntry = entry.Release
		} else {
			h = manager.GetHandler(sockopt.DialerProxy)
			if h == nil {
				return nil, errors.New("there is no outbound handler for dialerProxy").AtError()
			}
		}
		return redirect(ctx, dest, sockopt.DialerProxy, h, releaseEntry), nil
	}

	return dialer.Dial(ctx, src, dest, sockopt)
}

type lifecycleStatConnection struct {
	stat.Connection
	once            sync.Once
	stop            func() bool
	release         func()
	resourceRelease func()
	err             error
	ready           chan struct{}
	commitOnce      sync.Once
}

type lifecycleSystemConnection struct {
	net.Conn
	once    sync.Once
	stop    func() bool
	release func()
	err     error
	ready   chan struct{}
}

func (c *lifecycleSystemConnection) UnwrapConnection() net.Conn { return c.Conn }

func ownSystemConnection(ctx context.Context, connection net.Conn, release func()) net.Conn {
	owned := &lifecycleSystemConnection{Conn: connection, release: release, ready: make(chan struct{})}
	owned.stop = context.AfterFunc(ctx, func() { _ = owned.Close() })
	close(owned.ready)
	return owned
}

func (c *lifecycleSystemConnection) Close() error {
	c.once.Do(func() {
		<-c.ready
		if c.stop != nil {
			c.stop()
		}
		c.err = c.Conn.Close()
		c.release()
	})
	return c.err
}

type redirectConnection struct {
	net.Conn
	done chan struct{}
	once sync.Once
	err  error
}

func (c *redirectConnection) UnwrapConnection() net.Conn { return c.Conn }

func (c *redirectConnection) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		<-c.done
	})
	return c.err
}

type ownedPacketConnView struct {
	net.PacketConn
	owner net.Conn
	once  sync.Once
	err   error
}

func (c *ownedPacketConnView) Close() error {
	c.once.Do(func() { c.err = c.owner.Close() })
	return c.err
}

// PacketConnView exposes packet I/O through the concrete leaf while retaining
// the complete outer connection chain as the sole Close owner.
func PacketConnView(connection net.Conn) (net.PacketConn, *net.UDPAddr, error) {
	if connection == nil {
		return nil, nil, errors.New("nil packet connection")
	}
	leaf := stat.TryUnwrapStatsConn(connection)
	var packetConn net.PacketConn
	switch typed := leaf.(type) {
	case *PacketConnWrapper:
		packetConn = typed.PacketConn
	case *cnc.Connection:
		packetConn = &FakePacketConn{Conn: typed}
	default:
		return nil, nil, errors.New("unsupported packet connection shape: ", fmt.Sprintf("%T", leaf))
	}
	remote, ok := connection.RemoteAddr().(*net.UDPAddr)
	if !ok {
		if tcpRemote, tcpOK := connection.RemoteAddr().(*net.TCPAddr); tcpOK {
			remote = &net.UDPAddr{IP: tcpRemote.IP, Port: tcpRemote.Port}
		} else {
			return nil, nil, errors.New("packet connection has unsupported remote address: ", fmt.Sprintf("%T", connection.RemoteAddr()))
		}
	}
	return &ownedPacketConnView{PacketConn: packetConn, owner: connection}, remote, nil
}

func (c *lifecycleStatConnection) UnwrapConnection() net.Conn { return c.Connection }

func ownStatConnection(connection stat.Connection, release func()) *lifecycleStatConnection {
	return &lifecycleStatConnection{Connection: connection, release: release, ready: make(chan struct{})}
}

func (c *lifecycleStatConnection) commit(stop func() bool) {
	c.commitOnce.Do(func() {
		c.stop = stop
		close(c.ready)
	})
}

func (c *lifecycleStatConnection) Close() error {
	c.once.Do(func() {
		<-c.ready
		if c.stop != nil {
			c.stop()
		}
		c.err = c.Connection.Close()
		if c.resourceRelease != nil {
			c.resourceRelease()
		}
		c.release()
	})
	return c.err
}

func InitSystemDialer(dc dns.Client, om outbound.Manager) {
	dialDependenciesLock.Lock()
	dnsClient = dc
	obm = om
	dialDependenciesLock.Unlock()
}

func systemDialerForContext(ctx context.Context) SystemDialer {
	if snapshot := snapshotForContext(ctx); snapshot != nil && snapshot.dialer != nil {
		return snapshot.dialer
	}
	dialerLock.RLock()
	dialer := effectiveSystemDialer
	dialerLock.RUnlock()
	return dialer
}
