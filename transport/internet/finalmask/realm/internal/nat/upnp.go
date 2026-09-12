// Adapted from github.com/libp2p/go-nat at
// 01afc089f138bf26b9f467ccba7f53ac34e0c679 (Apache-2.0).
package nat

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

type upnpClient interface {
	GetExternalIPAddress() (string, error)
	GetExternalIPAddressCtx(context.Context) (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
}

type upnpNAT struct {
	client     upnpClient
	typ        string
	rootDevice *goupnp.RootDevice
	grants     map[mappingKey]Grant
}

func discoverUPNPIG1(ctx context.Context) <-chan NAT {
	result := make(chan NAT)
	go func() {
		defer close(result)
		devices, err := goupnp.DiscoverDevicesCtx(ctx, internetgateway1.URN_WANConnectionDevice_1)
		if err != nil {
			return
		}
		for _, device := range devices {
			if device.Root == nil {
				continue
			}
			device.Root.Device.VisitServices(func(service *goupnp.Service) {
				if ctx.Err() != nil {
					return
				}
				switch service.ServiceType {
				case internetgateway1.URN_WANIPConnection_1:
					client := &internetgateway1.WANIPConnection1{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG1-IP1)", device.Root))
					}
				case internetgateway1.URN_WANPPPConnection_1:
					client := &internetgateway1.WANPPPConnection1{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG1-PPP1)", device.Root))
					}
				}
			})
		}
	}()
	return result
}

func discoverUPNPIG2(ctx context.Context) <-chan NAT {
	result := make(chan NAT)
	go func() {
		defer close(result)
		devices, err := goupnp.DiscoverDevicesCtx(ctx, internetgateway2.URN_WANConnectionDevice_2)
		if err != nil {
			return
		}
		for _, device := range devices {
			if device.Root == nil {
				continue
			}
			device.Root.Device.VisitServices(func(service *goupnp.Service) {
				if ctx.Err() != nil {
					return
				}
				switch service.ServiceType {
				case internetgateway2.URN_WANIPConnection_1:
					client := &internetgateway2.WANIPConnection1{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG2-IP1)", device.Root))
					}
				case internetgateway2.URN_WANIPConnection_2:
					client := &internetgateway2.WANIPConnection2{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG2-IP2)", device.Root))
					}
				case internetgateway2.URN_WANPPPConnection_1:
					client := &internetgateway2.WANPPPConnection1{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG2-PPP1)", device.Root))
					}
				}
			})
		}
	}()
	return result
}

// The pinned go-nat generic path used a contextless SSDP helper. Querying the
// same ssdp:all target through goupnp keeps that reachability while binding the
// multicast socket and device fetches to the setup context.
func discoverUPNPGeneric(ctx context.Context) <-chan NAT {
	result := make(chan NAT)
	go func() {
		defer close(result)
		devices, err := goupnp.DiscoverDevicesCtx(ctx, "ssdp:all")
		if err != nil {
			return
		}
		for _, device := range devices {
			if device.Root == nil {
				continue
			}
			device.Root.Device.VisitServices(func(service *goupnp.Service) {
				if ctx.Err() != nil {
					return
				}
				switch service.ServiceType {
				case internetgateway1.URN_WANIPConnection_1:
					client := &internetgateway1.WANIPConnection1{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG1-IP1)", device.Root))
					}
				case internetgateway1.URN_WANPPPConnection_1:
					client := &internetgateway1.WANPPPConnection1{ServiceClient: serviceClient(device.Root, service)}
					if _, isNAT, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNAT {
						publishNAT(ctx, result, newUPNPNAT(client, "UPNP (IG1-PPP1)", device.Root))
					}
				}
			})
		}
	}()
	return result
}

func serviceClient(root *goupnp.RootDevice, service *goupnp.Service) goupnp.ServiceClient {
	return goupnp.ServiceClient{
		SOAPClient: service.NewSOAPClient(),
		RootDevice: root,
		Service:    service,
	}
}

func publishNAT(ctx context.Context, result chan<- NAT, candidate NAT) {
	select {
	case result <- candidate:
	case <-ctx.Done():
	}
}

func newUPNPNAT(client upnpClient, typ string, root *goupnp.RootDevice) *upnpNAT {
	return &upnpNAT{client: client, typ: typ, rootDevice: root, grants: make(map[mappingKey]Grant)}
}

func (u *upnpNAT) Type() string { return u.typ }

func (u *upnpNAT) GetExternalAddress() (net.IP, error) {
	return u.GetExternalAddressContext(context.Background())
}

func (u *upnpNAT) GetExternalAddressContext(ctx context.Context) (net.IP, error) {
	ipString, err := u.client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, ErrNoExternalAddress
	}
	return ip, nil
}

func (u *upnpNAT) GetDeviceAddress() (net.IP, error) {
	addr, err := net.ResolveUDPAddr("udp4", u.rootDevice.URLBase.Host)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

func (u *upnpNAT) GetInternalAddress() (net.IP, error) {
	deviceAddr, err := u.GetDeviceAddress()
	if err != nil {
		return nil, err
	}
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
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.Contains(deviceAddr) {
				return ipNet.IP, nil
			}
		}
	}
	return nil, ErrNoInternalAddress
}

func mapProtocol(protocol string) (string, error) {
	switch protocol {
	case "udp":
		return "UDP", nil
	case "tcp":
		return "TCP", nil
	default:
		return "", fmt.Errorf("invalid protocol %q", protocol)
	}
}

func (u *upnpNAT) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, lifetime time.Duration) (int, error) {
	grant, err := u.AddPortMappingGrant(ctx, protocol, internalPort, description, lifetime)
	return grant.Port, err
}

func (u *upnpNAT) AddPortMappingGrant(ctx context.Context, protocol string, internalPort int, description string, lifetime time.Duration) (Grant, error) {
	internalAddr, err := u.GetInternalAddress()
	if err != nil {
		return Grant{}, err
	}
	if lifetime <= 0 || lifetime%time.Second != 0 || lifetime/time.Second > math.MaxUint32 {
		return Grant{}, fmt.Errorf("invalid mapping lifetime %s", lifetime)
	}
	wireProtocol, err := mapProtocol(protocol)
	if err != nil {
		return Grant{}, err
	}
	key := mappingKey{protocol: protocol, internalPort: internalPort}
	if existing := u.grants[key]; existing.Port > 0 {
		err := u.client.AddPortMappingCtx(ctx, "", uint16(existing.Port), wireProtocol, uint16(internalPort), internalAddr.String(), true, description, uint32(lifetime/time.Second))
		if err != nil {
			return Grant{}, err
		}
		existing.Lifetime = lifetime
		u.grants[key] = existing
		return existing, nil
	}
	var lastErr error
	for range 3 {
		externalPort := randomPort()
		lastErr = u.client.AddPortMappingCtx(ctx, "", uint16(externalPort), wireProtocol, uint16(internalPort), internalAddr.String(), true, description, uint32(lifetime/time.Second))
		if lastErr == nil {
			grant := Grant{Port: externalPort, Lifetime: lifetime}
			u.grants[key] = grant
			return grant, nil
		}
		if ctx.Err() != nil {
			return Grant{}, ctx.Err()
		}
	}
	return Grant{}, lastErr
}

func (u *upnpNAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	key := mappingKey{protocol: protocol, internalPort: internalPort}
	grant := u.grants[key]
	if grant.Port == 0 {
		return nil
	}
	return u.DeletePortMappingGrant(ctx, protocol, internalPort, grant)
}

func (u *upnpNAT) DeletePortMappingGrant(ctx context.Context, protocol string, internalPort int, grant Grant) error {
	wireProtocol, err := mapProtocol(protocol)
	if err != nil {
		return err
	}
	if grant.Port <= 0 || grant.Port > math.MaxUint16 {
		return fmt.Errorf("invalid mapped port %d", grant.Port)
	}
	if err := u.client.DeletePortMappingCtx(ctx, "", uint16(grant.Port), wireProtocol); err != nil {
		return err
	}
	key := mappingKey{protocol: protocol, internalPort: internalPort}
	if u.grants[key] == grant {
		delete(u.grants, key)
	}
	return nil
}
