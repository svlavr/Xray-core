//go:build linux && !android

package tun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

type systemDNSLeaseClient struct {
	featuredns.Client
	unsafe, noLease    bool
	acquired, released int
}

func (c *systemDNSLeaseClient) MayUseSystemResolver() bool { return c.unsafe }

func (c *systemDNSLeaseClient) AcquireSystemDNS() (func(), error) {
	if c.unsafe {
		return nil, errors.New("unsafe resolver path")
	}
	if c.noLease {
		return nil, nil
	}
	c.acquired++
	return func() { c.released++ }, nil
}

func systemDNSClientContext(t *testing.T, client featuredns.Client) context.Context {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.AddFeature(client); err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func TestSystemDNSGenericClientAdmission(t *testing.T) {
	for _, mode := range []string{"safe", "unsafe", "no-lease", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			client := &systemDNSLeaseClient{Client: localdns.New(), unsafe: mode == "unsafe", noLease: mode == "no-lease"}
			var selected featuredns.Client = client
			if mode == "unknown" {
				selected = &struct{ featuredns.Client }{Client: localdns.New()}
			}
			probes := stubDNSRouting(t, nil)
			commands := recorder(t, "")
			tun := optedInTun()
			err := tun.ConfigureSystemDNS(systemDNSClientContext(t, selected), "tun")
			if mode != "safe" {
				if err == nil || len(*probes) != 0 || len(*commands) != 0 || tun.systemDNSRelease != nil {
					t.Fatalf("unsupported client reached takeover: err=%v probes=%v commands=%v", err, *probes, *commands)
				}
				return
			}
			if err != nil || client.acquired != 1 || client.released != 0 {
				t.Fatalf("lease not held through takeover: err=%v client=%+v", err, client)
			}
			tun.unsetSystemDNS()
			tun.unsetSystemDNS()
			if client.released != 1 {
				t.Fatalf("release count=%d", client.released)
			}
		})
	}
}

func TestSystemDNSGenericLeaseFailedRevert(t *testing.T) {
	client := &systemDNSLeaseClient{Client: localdns.New()}
	ctx := systemDNSClientContext(t, client)
	stubDNSRouting(t, nil)
	commands := recorder(t, "revert")
	tun := optedInTun()
	if err := tun.ConfigureSystemDNS(ctx, "tun"); err != nil {
		t.Fatal(err)
	}
	tun.unsetSystemDNS()
	if !tun.systemDNSDirty || client.released != 0 || tun.systemDNSRelease == nil {
		t.Fatalf("failed revert lost lease: dirty=%v releases=%d", tun.systemDNSDirty, client.released)
	}
	original := resolvectlRunner
	resolvectlRunner = func(_ string, args ...string) ([]byte, error) { return nil, nil }
	tun.unsetSystemDNS()
	resolvectlRunner = original
	if tun.systemDNSDirty || client.released != 1 || len(*commands) != 4 {
		t.Fatalf("successful retry did not release: dirty=%v releases=%d commands=%v", tun.systemDNSDirty, client.released, *commands)
	}
}

func TestVerifyDNSRoutingGenericClientSafety(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		client := &systemDNSLeaseClient{Client: localdns.New(), unsafe: unsafe}
		err := verifyDNSRouting(systemDNSClientContext(t, client), "tun", routeTestSource, routeTestDNSAddress)
		want := "router feature unavailable"
		if unsafe {
			want = "system resolver"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("unsafe=%v err=%v, want %q", unsafe, err, want)
		}
	}
	unknown := &struct{ featuredns.Client }{Client: localdns.New()}
	if err := verifyDNSRouting(systemDNSClientContext(t, unknown), "tun", routeTestSource, routeTestDNSAddress); err == nil || !strings.Contains(err.Error(), "safe system DNS takeover") {
		t.Fatalf("unqualified client accepted: %v", err)
	}
}

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
			tun.fdTun = newFdTun(fds[0], 0)
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
