// Package nat is an in-tree adaptation of github.com/libp2p/go-nat at
// 01afc089f138bf26b9f467ccba7f53ac34e0c679 (Apache-2.0).
package nat

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"
)

var (
	ErrNoExternalAddress = errors.New("no external address")
	ErrNoInternalAddress = errors.New("no internal address")
	ErrNoNATFound        = errors.New("no NAT found")
)

// NAT preserves the legacy go-nat API. Realm requires the additive ManagedNAT
// capability below so cancellation and exact grant cleanup cannot be lost.
type NAT interface {
	Type() string
	GetDeviceAddress() (net.IP, error)
	GetExternalAddress() (net.IP, error)
	GetInternalAddress() (net.IP, error)
	AddPortMapping(context.Context, string, int, string, time.Duration) (int, error)
	DeletePortMapping(context.Context, string, int) error
}

type Grant struct {
	Port     int
	Lifetime time.Duration
}

type ManagedNAT interface {
	NAT
	GetExternalAddressContext(context.Context) (net.IP, error)
	AddPortMappingGrant(context.Context, string, int, string, time.Duration) (Grant, error)
	DeletePortMappingGrant(context.Context, string, int, Grant) error
}

func DiscoverNATs(ctx context.Context) <-chan NAT {
	nats := make(chan NAT)
	go func() {
		defer close(nats)
		upnpIG1 := discoverUPNPIG1(ctx)
		upnpIG2 := discoverUPNPIG2(ctx)
		natpmp := discoverNATPMP(ctx)
		upnpGeneric := discoverUPNPGeneric(ctx)
		for upnpIG1 != nil || upnpIG2 != nil || natpmp != nil || upnpGeneric != nil {
			var candidate NAT
			var ok bool
			select {
			case candidate, ok = <-upnpIG1:
				if !ok {
					upnpIG1 = nil
				}
			case candidate, ok = <-upnpIG2:
				if !ok {
					upnpIG2 = nil
				}
			case candidate, ok = <-upnpGeneric:
				if !ok {
					upnpGeneric = nil
				}
			case candidate, ok = <-natpmp:
				if !ok {
					natpmp = nil
				}
			case <-ctx.Done():
				return
			}
			if ok {
				select {
				case nats <- candidate:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nats
}

func DiscoverGateway(ctx context.Context) (NAT, error) {
	var candidates []NAT
	for candidate := range DiscoverNATs(ctx) {
		candidates = append(candidates, candidate)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch len(candidates) {
	case 0:
		return nil, ErrNoNATFound
	case 1:
		return candidates[0], nil
	}

	gateway, _ := getDefaultGateway()
	best := candidates[0]
	bestAddr, _ := best.GetDeviceAddress()
	bestIsGateway := gateway != nil && bestAddr.Equal(gateway)
	for _, candidate := range candidates[1:] {
		addr, _ := candidate.GetDeviceAddress()
		isGateway := gateway != nil && addr.Equal(gateway)
		if bestIsGateway && !isGateway {
			continue
		}
		best = candidate
		bestIsGateway = isGateway
	}
	return best, nil
}

type mappingKey struct {
	protocol     string
	internalPort int
}

var randomPortSource = struct {
	sync.Mutex
	r *rand.Rand
}{r: rand.New(rand.NewSource(time.Now().UnixNano()))}

func randomPort() int {
	randomPortSource.Lock()
	port := randomPortSource.r.Intn(math.MaxUint16-10000) + 10000
	randomPortSource.Unlock()
	return port
}
