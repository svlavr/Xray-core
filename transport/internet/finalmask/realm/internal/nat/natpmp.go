// Adapted from github.com/libp2p/go-nat at
// 01afc089f138bf26b9f467ccba7f53ac34e0c679 (Apache-2.0).
package nat

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/realm/internal/natpmp"
)

func discoverNATPMP(ctx context.Context) <-chan NAT {
	result := make(chan NAT)
	go func() {
		defer close(result)
		gateway, err := getDefaultGateway()
		if err != nil {
			return
		}
		candidate := &pmpNAT{
			client:  natpmp.NewClient(gateway),
			gateway: gateway,
			grants:  make(map[mappingKey]Grant),
		}
		if _, err := candidate.GetExternalAddressContext(ctx); err != nil {
			return
		}
		publishNAT(ctx, result, candidate)
	}()
	return result
}

type pmpNAT struct {
	client  *natpmp.Client
	gateway net.IP
	grants  map[mappingKey]Grant
}

func (n *pmpNAT) Type() string { return "NAT-PMP" }

func (n *pmpNAT) GetDeviceAddress() (net.IP, error) { return n.gateway, nil }

func (n *pmpNAT) GetInternalAddress() (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.Contains(n.gateway) {
				return ipNet.IP, nil
			}
		}
	}
	return nil, ErrNoInternalAddress
}

func (n *pmpNAT) GetExternalAddress() (net.IP, error) {
	return n.GetExternalAddressContext(context.Background())
}

func (n *pmpNAT) GetExternalAddressContext(ctx context.Context) (net.IP, error) {
	result, err := n.client.GetExternalAddressContext(ctx)
	if err != nil {
		return nil, err
	}
	addr := result.ExternalIPAddress
	return net.IPv4(addr[0], addr[1], addr[2], addr[3]), nil
}

func (n *pmpNAT) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, lifetime time.Duration) (int, error) {
	grant, err := n.AddPortMappingGrant(ctx, protocol, internalPort, description, lifetime)
	return grant.Port, err
}

func (n *pmpNAT) AddPortMappingGrant(ctx context.Context, protocol string, internalPort int, _ string, lifetime time.Duration) (Grant, error) {
	if lifetime <= 0 || lifetime%time.Second != 0 || lifetime > time.Duration(^uint32(0))*time.Second {
		return Grant{}, fmt.Errorf("invalid mapping lifetime %s", lifetime)
	}
	key := mappingKey{protocol: protocol, internalPort: internalPort}
	requestedPort := n.grants[key].Port
	if requestedPort == 0 {
		requestedPort = randomPort()
	}
	result, err := n.client.AddPortMappingContext(ctx, protocol, internalPort, requestedPort, int(lifetime/time.Second))
	if err != nil {
		return Grant{}, err
	}
	if result.InternalPort != uint16(internalPort) || result.MappedExternalPort == 0 || result.PortMappingLifetimeInSeconds == 0 {
		return Grant{}, fmt.Errorf("invalid NAT-PMP mapping grant")
	}
	grant := Grant{Port: int(result.MappedExternalPort), Lifetime: time.Duration(result.PortMappingLifetimeInSeconds) * time.Second}
	n.grants[key] = grant
	return grant, nil
}

func (n *pmpNAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	key := mappingKey{protocol: protocol, internalPort: internalPort}
	grant := n.grants[key]
	if grant.Port == 0 {
		return nil
	}
	return n.DeletePortMappingGrant(ctx, protocol, internalPort, grant)
}

func (n *pmpNAT) DeletePortMappingGrant(ctx context.Context, protocol string, internalPort int, grant Grant) error {
	key := mappingKey{protocol: protocol, internalPort: internalPort}
	if n.grants[key] != grant {
		return fmt.Errorf("stale NAT-PMP mapping grant")
	}
	result, err := n.client.AddPortMappingContext(ctx, protocol, internalPort, 0, 0)
	if err != nil {
		return err
	}
	if result.InternalPort != uint16(internalPort) || result.PortMappingLifetimeInSeconds != 0 {
		return fmt.Errorf("invalid NAT-PMP delete receipt")
	}
	delete(n.grants, key)
	return nil
}
