//go:build linux && !android

package tun

import (
	"context"
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
)

func TestSystemDNSCloseReleasesOnlyAbsentLink(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
			ctx := newRouteTestContext(t, true, udpNameServer([]byte{9, 9, 9, 9}), []*router.RoutingRule{port53Rule()})
			feature := core.FromContext(ctx).GetFeature(featuredns.ClientType()).(*appdns.DNS)
			tun := optedInTun()
			tun.tunLink.Attrs().Index = 2147483647
			if present {
				link, err := netlink.LinkByName("lo")
				if err != nil {
					t.Fatal(err)
				}
				tun.tunLink = link
			}
			var fds [2]int
			if err := unix.Pipe(fds[:]); err != nil {
				t.Fatal(err)
			}
			tun.tunFd = fds[0]
			defer unix.Close(fds[1])
			original := resolvectlRunner
			failRevert := true
			resolvectlRunner = func(_ string, args ...string) ([]byte, error) {
				if args[0] == "revert" && failRevert {
					return nil, errors.New("test revert failure")
				}
				return nil, nil
			}
			defer func() { failRevert = false; tun.unsetSystemDNS(); resolvectlRunner = original }()
			if err := tun.ConfigureSystemDNS(ctx, routeTestInboundTag); err != nil {
				t.Fatal(err)
			}
			if err := tun.Close(); err != nil {
				t.Fatal(err)
			}
			result := appdns.ApplyConfig(context.Background(), feature, &appdns.Config{NameServer: []*appdns.NameServer{localNameServer()}})
			if result.Applied == present {
				t.Fatalf("present=%v result=%+v", present, result)
			}
		})
	}
}

func TestSystemDNSTakeoverOrdersResolverApply(t *testing.T) {
	ctx := newRouteTestContext(t, true, udpNameServer([]byte{9, 9, 9, 9}), []*router.RoutingRule{port53Rule()})
	feature := core.FromContext(ctx).GetFeature(featuredns.ClientType()).(*appdns.DNS)
	tun := optedInTun()
	started := make(chan struct{})
	continueDNS := make(chan struct{})
	original := resolvectlRunner
	resolvectlRunner = func(_ string, args ...string) ([]byte, error) {
		if args[0] == "dns" {
			close(started)
			<-continueDNS
		}
		return nil, nil
	}
	t.Cleanup(func() { resolvectlRunner = original })
	done := make(chan error, 1)
	go func() { done <- tun.ConfigureSystemDNS(ctx, routeTestInboundTag) }()
	<-started
	local := &appdns.Config{NameServer: []*appdns.NameServer{localNameServer()}}
	if result := appdns.ApplyConfig(context.Background(), feature, local); result.Applied || result.Err == nil {
		t.Fatalf("local resolver published while takeover was active: %+v", result)
	}
	close(continueDNS)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result := appdns.ApplyConfig(context.Background(), feature, local); result.Applied || result.Err == nil {
		t.Fatalf("local resolver published while system DNS was installed: %+v", result)
	}
	tun.unsetSystemDNS()
	if result := appdns.ApplyConfig(context.Background(), feature, local); !result.Applied || result.Err != nil {
		t.Fatalf("local resolver after revert: %+v", result)
	}
}

func TestSystemDNSGuardRetainedAfterFailedRollback(t *testing.T) {
	ctx := newRouteTestContext(t, true, udpNameServer([]byte{9, 9, 9, 9}), []*router.RoutingRule{port53Rule()})
	feature := core.FromContext(ctx).GetFeature(featuredns.ClientType()).(*appdns.DNS)
	tun := optedInTun()
	original := resolvectlRunner
	failRevert := true
	resolvectlRunner = func(_ string, args ...string) ([]byte, error) {
		if args[0] == "domain" || (args[0] == "revert" && failRevert) {
			return nil, errors.New("test failure")
		}
		return nil, nil
	}
	t.Cleanup(func() { resolvectlRunner = original })
	if err := tun.ConfigureSystemDNS(ctx, routeTestInboundTag); err == nil || !tun.systemDNSDirty {
		t.Fatalf("failed rollback: err=%v dirty=%v", err, tun.systemDNSDirty)
	}
	local := &appdns.Config{NameServer: []*appdns.NameServer{localNameServer()}}
	if result := appdns.ApplyConfig(context.Background(), feature, local); result.Applied || result.Err == nil {
		t.Fatalf("local resolver published after failed rollback: %+v", result)
	}
	failRevert = false
	tun.unsetSystemDNS()
	if tun.systemDNSDirty {
		t.Fatal("successful revert left dirty system DNS")
	}
	if result := appdns.ApplyConfig(context.Background(), feature, local); !result.Applied || result.Err != nil {
		t.Fatalf("local resolver after successful retry: %+v", result)
	}
}
