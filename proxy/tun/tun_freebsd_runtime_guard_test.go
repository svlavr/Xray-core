//go:build freebsd

package tun

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

type freeBSDLeaseClient struct {
	featuredns.Client
	unsafe, noLease    bool
	acquired, released int
}

func (c *freeBSDLeaseClient) MayUseSystemResolver() bool { return c.unsafe }
func (c *freeBSDLeaseClient) AcquireSystemDNS() (func(), error) {
	if c.unsafe {
		return nil, errors.New("unsafe resolver path")
	}
	if c.noLease {
		return nil, nil
	}
	c.acquired++
	return func() { c.released++ }, nil
}

func freeBSDClientContext(t *testing.T, client featuredns.Client) context.Context {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.AddFeature(client); err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func TestFreeBSDSystemDNSLeaseAdmission(t *testing.T) {
	for _, mode := range []string{"safe", "unsafe", "no-lease", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			client := &freeBSDLeaseClient{Client: localdns.New(), unsafe: mode == "unsafe", noLease: mode == "no-lease"}
			var selected featuredns.Client = client
			if mode == "unknown" {
				selected = &struct{ featuredns.Client }{Client: localdns.New()}
			}
			probes, commands := stubDNSRouting(t, nil), recorder(t, "")
			files(t, map[string]string{"/etc/resolv.conf": takenOver})
			tun := optedInTun()
			err := tun.ConfigureSystemDNS(freeBSDClientContext(t, selected), "tun")
			if mode != "safe" {
				if err == nil || len(*probes) != 0 || len(*commands) != 0 {
					t.Fatalf("unsafe admission: err=%v probes=%v commands=%v", err, *probes, *commands)
				}
				return
			}
			if err != nil || client.acquired != 1 || client.released != 0 {
				t.Fatalf("lease not held: err=%v client=%+v", err, client)
			}
			tun.unsetSystemDNS()
			tun.unsetSystemDNS()
			if client.released != 1 {
				t.Fatalf("release count=%d", client.released)
			}
		})
	}
}

func TestFreeBSDSystemDNSLeaseFailedRemoval(t *testing.T) {
	client := &freeBSDLeaseClient{Client: localdns.New()}
	ctx := freeBSDClientContext(t, client)
	stubDNSRouting(t, nil)
	commands := recorder(t, "-d")
	files(t, map[string]string{"/etc/resolv.conf": takenOver})
	tun := optedInTun()
	if err := tun.ConfigureSystemDNS(ctx, "tun"); err != nil {
		t.Fatal(err)
	}
	tun.unsetSystemDNS()
	if !tun.systemDNSDirty || client.released != 0 || tun.systemDNSRelease == nil {
		t.Fatalf("failed removal released lease: client=%+v", client)
	}
	resolvconfRunner = func(_ string, _ ...string) ([]byte, error) { return nil, nil }
	tun.unsetSystemDNS()
	if tun.systemDNSDirty || client.released != 1 || len(*commands) != 2 {
		t.Fatalf("retry did not release once: client=%+v commands=%v", client, *commands)
	}
}

func TestFreeBSDSystemDNSLeaseFirstCommandFailure(t *testing.T) {
	for _, removalFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "retained"}[removalFails], func(t *testing.T) {
			client := &freeBSDLeaseClient{Client: localdns.New()}
			stubDNSRouting(t, nil)
			var commands []string
			original := resolvconfRunner
			resolvconfRunner = func(_ string, args ...string) ([]byte, error) {
				commands = append(commands, args[0])
				if args[0] == "-a" || removalFails {
					return nil, errors.New("command failed")
				}
				return nil, nil
			}
			t.Cleanup(func() { resolvconfRunner = original })
			tun := optedInTun()
			if err := tun.ConfigureSystemDNS(freeBSDClientContext(t, client), "tun"); err == nil {
				t.Fatal("failed command accepted")
			}
			if len(commands) != 2 || commands[0] != "-a" || commands[1] != "-d" || tun.systemDNSDirty != removalFails {
				t.Fatalf("wrong rollback: commands=%v dirty=%v", commands, tun.systemDNSDirty)
			}
			if (client.released == 0) != removalFails {
				t.Fatalf("wrong lease retention: %+v", client)
			}
		})
	}
}
