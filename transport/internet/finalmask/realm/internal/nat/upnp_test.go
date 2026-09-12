package nat

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/huin/goupnp"
)

type testUPNPClient struct {
	external       string
	lookupStarted  chan struct{}
	addExternal    uint16
	deleteExternal uint16
	addLifetime    uint32
}

func (c *testUPNPClient) GetExternalIPAddress() (string, error) {
	return c.external, nil
}

func (c *testUPNPClient) GetExternalIPAddressCtx(ctx context.Context) (string, error) {
	if c.lookupStarted != nil {
		select {
		case <-c.lookupStarted:
		default:
			close(c.lookupStarted)
		}
		<-ctx.Done()
		return "", ctx.Err()
	}
	return c.external, nil
}

func (c *testUPNPClient) AddPortMappingCtx(_ context.Context, _ string, external uint16, _ string, _ uint16, _ string, _ bool, _ string, lifetime uint32) error {
	c.addExternal = external
	c.addLifetime = lifetime
	return nil
}

func (c *testUPNPClient) DeletePortMappingCtx(_ context.Context, _ string, external uint16, _ string) error {
	c.deleteExternal = external
	return nil
}

func testUPNPRoot(t *testing.T) *goupnp.RootDevice {
	t.Helper()
	u, err := url.Parse("http://127.0.0.1:1900/device.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := new(goupnp.RootDevice)
	root.SetURLBase(u)
	return root
}

func TestUPNPExternalAddressUsesContext(t *testing.T) {
	client := &testUPNPClient{lookupStarted: make(chan struct{})}
	gateway := newUPNPNAT(client, "test", testUPNPRoot(t))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := gateway.GetExternalAddressContext(ctx)
		done <- err
	}()
	<-client.lookupStarted
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not unblock lookup")
	}
}

func TestUPNPGrantAndExactDelete(t *testing.T) {
	client := &testUPNPClient{external: "203.0.113.9"}
	gateway := newUPNPNAT(client, "test", testUPNPRoot(t))
	grant, err := gateway.AddPortMappingGrant(context.Background(), "udp", 1234, "realm", 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Port == 0 || grant.Lifetime != 90*time.Second || client.addExternal != uint16(grant.Port) || client.addLifetime != 90 {
		t.Fatalf("grant=%+v external=%d lifetime=%d", grant, client.addExternal, client.addLifetime)
	}
	if err := gateway.DeletePortMappingGrant(context.Background(), "udp", 1234, grant); err != nil {
		t.Fatal(err)
	}
	if client.deleteExternal != uint16(grant.Port) {
		t.Fatalf("deleted port=%d, want %d", client.deleteExternal, grant.Port)
	}
}
