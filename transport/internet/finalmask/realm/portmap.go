package realm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/realm/internal/nat"
)

const (
	defaultPortMapTimeout  = 10 * time.Second
	defaultPortMapLifetime = 10 * time.Minute
	maxPortMapLifetime     = 7 * 24 * time.Hour
	portMapDescription     = "hysteria-realm"
	portMapProtocol        = "udp"
)

var ErrInvalidPortMapConfig = errors.New("invalid port mapping config")

type PortMapConfig struct{ Timeout, Lifetime time.Duration }

func (c PortMapConfig) withDefaults() (PortMapConfig, error) {
	if c.Timeout == 0 {
		c.Timeout = defaultPortMapTimeout
	}
	if c.Timeout < 0 {
		return c, fmt.Errorf("%w: timeout must not be negative", ErrInvalidPortMapConfig)
	}
	if c.Lifetime == 0 {
		c.Lifetime = defaultPortMapLifetime
	}
	if c.Lifetime < time.Second || c.Lifetime > maxPortMapLifetime || c.Lifetime%time.Second != 0 {
		return c, fmt.Errorf("%w: lifetime must be a whole second in [1, %d]", ErrInvalidPortMapConfig, int(maxPortMapLifetime/time.Second))
	}
	return c, nil
}

func portMapConfigFromProto(config *PortMapping) (PortMapConfig, error) {
	if config == nil {
		return PortMapConfig{}, nil
	}
	if config.Timeout < 0 || config.Timeout > int64(^uint64(0)>>1)/int64(time.Second) {
		return PortMapConfig{}, fmt.Errorf("%w: timeout seconds out of range", ErrInvalidPortMapConfig)
	}
	if config.Lifetime < 0 || config.Lifetime > int64(maxPortMapLifetime/time.Second) {
		return PortMapConfig{}, fmt.Errorf("%w: lifetime seconds out of range", ErrInvalidPortMapConfig)
	}
	return (PortMapConfig{
		Timeout:  time.Duration(config.Timeout) * time.Second,
		Lifetime: time.Duration(config.Lifetime) * time.Second,
	}).withDefaults()
}

type gateway interface {
	Type() string
	AddPortMappingGrant(context.Context, string, int, string, time.Duration) (nat.Grant, error)
	DeletePortMappingGrant(context.Context, string, int, nat.Grant) error
	GetExternalAddressContext(context.Context) (net.IP, error)
}

type PortMapReceipt uint8

const (
	PortMapUnreleased PortMapReceipt = iota
	PortMapRemoteDeleteConfirmed
	PortMapRemoteDeleteUnconfirmed
)

type PortMapper struct {
	gateway                gateway
	internalPort           int
	config                 PortMapConfig
	mu                     sync.Mutex
	renewMu                sync.Mutex
	opCancel               context.CancelFunc
	externalAddr           netip.AddrPort
	grant                  nat.Grant
	owned, sealed, closing bool
	closeDone              chan struct{}
	receipt                PortMapReceipt
	closeErr               error
}

func NewPortMapper(ctx context.Context, internalPort int, config PortMapConfig) (*PortMapper, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return nil, fmt.Errorf("%w: invalid internal port %d", ErrInvalidPortMapConfig, internalPort)
	}
	config, err := config.withDefaults()
	if err != nil {
		return nil, err
	}
	discoverCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	discovered, err := nat.DiscoverGateway(discoverCtx)
	if err != nil {
		return nil, fmt.Errorf("gateway discovery failed: %w", err)
	}
	g, ok := discovered.(nat.ManagedNAT)
	if !ok {
		return nil, errors.New("gateway lacks managed finite mapping lifecycle")
	}
	return newPortMapper(ctx, internalPort, config, g)
}

func newPortMapper(ctx context.Context, port int, config PortMapConfig, g gateway) (*PortMapper, error) {
	m := &PortMapper{gateway: g, internalPort: port, config: config}
	if _, err := m.Renew(ctx); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func (m *PortMapper) Renew(ctx context.Context) (bool, error) {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()
	m.mu.Lock()
	if m.sealed {
		m.mu.Unlock()
		return false, context.Canceled
	}
	opCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	m.opCancel = cancel
	lifetime := m.config.Lifetime
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.opCancel = nil
		m.mu.Unlock()
		cancel()
	}()
	grant, err := m.gateway.AddPortMappingGrant(opCtx, portMapProtocol, m.internalPort, portMapDescription, lifetime)
	if err != nil {
		return false, fmt.Errorf("add port mapping failed: %w", err)
	}
	if grant.Port <= 0 || grant.Port > 65535 || grant.Lifetime <= 0 {
		return false, errors.New("gateway returned invalid mapped port")
	}
	// Add succeeded: it is owned before lookup/validation/cancellation.
	m.mu.Lock()
	m.owned = true
	m.grant = grant
	m.mu.Unlock()
	if err := opCtx.Err(); err != nil {
		return false, err
	}
	ip, err := m.gateway.GetExternalAddressContext(opCtx)
	if err != nil {
		return false, fmt.Errorf("get external address failed: %w", err)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || addr.IsUnspecified() || addr.IsLoopback() {
		return false, fmt.Errorf("gateway returned unusable external address: %s", ip)
	}
	external := netip.AddrPortFrom(addr.Unmap(), uint16(grant.Port))
	m.mu.Lock()
	changed := external != m.externalAddr
	m.config.Lifetime = grant.Lifetime
	m.externalAddr = external
	m.mu.Unlock()
	return changed, nil
}

func (m *PortMapper) ExternalAddr() netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.externalAddr
}
func (m *PortMapper) InternalPort() int   { return m.internalPort }
func (m *PortMapper) GatewayType() string { return m.gateway.Type() }
func (m *PortMapper) Lifetime() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config.Lifetime
}
func (m *PortMapper) Receipt() PortMapReceipt { m.mu.Lock(); defer m.mu.Unlock(); return m.receipt }

func (m *PortMapper) Close() error {
	// Cancel an in-flight Add/lookup before contending for its serialization
	// lock. The in-tree NAT implementations bind their sockets to this context.
	m.mu.Lock()
	if m.closing {
		done := m.closeDone
		m.mu.Unlock()
		<-done
		return m.closeResult()
	}
	m.sealed, m.closing = true, true
	m.closeDone = make(chan struct{})
	cancel := m.opCancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Wait for the admitted Add/lookup to record its exact result before
	// snapshotting cleanup ownership.
	m.renewMu.Lock()
	m.renewMu.Unlock()
	m.mu.Lock()
	owned := m.owned
	grant := m.grant
	m.mu.Unlock()
	var err error
	if owned {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
		err = m.gateway.DeletePortMappingGrant(ctx, portMapProtocol, m.internalPort, grant)
		cancel()
	}
	m.mu.Lock()
	if !owned {
		m.receipt = PortMapUnreleased
	} else if err == nil {
		m.receipt = PortMapRemoteDeleteConfirmed
	} else {
		m.receipt = PortMapRemoteDeleteUnconfirmed
	}
	m.closeErr = err
	close(m.closeDone)
	m.mu.Unlock()
	return err
}

func (m *PortMapper) closeResult() error {
	return m.closeErr
}
