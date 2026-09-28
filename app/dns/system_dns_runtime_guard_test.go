package dns

import (
	"context"
	"testing"
)

func TestSystemDNSGuardFollowsPublishedResolver(t *testing.T) {
	feature, err := New(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = feature.Close() })
	if !feature.MayUseSystemResolver() {
		t.Fatal("initial local resolver was not reported")
	}
	remote := &Config{NameServer: []*NameServer{preparationServer("tcp+local://127.0.0.1:53", "remote")}}
	local := &Config{NameServer: []*NameServer{preparationServer("localhost", "local")}}
	if result := ApplyConfig(context.Background(), feature, remote); !result.Applied || result.Err != nil {
		t.Fatalf("remote apply: %+v", result)
	}
	if feature.MayUseSystemResolver() {
		t.Fatal("published remote resolver was reported as local")
	}
	release, err := feature.AcquireSystemDNS()
	if err != nil {
		t.Fatal(err)
	}
	if result := ApplyConfig(context.Background(), feature, local); result.Applied || result.Err == nil {
		t.Fatalf("local resolver published during takeover: %+v", result)
	}
	if result := ApplyConfig(context.Background(), feature, remote); !result.Applied || result.Err != nil {
		t.Fatalf("safe replacement during takeover: %+v", result)
	}
	release()
	if result := ApplyConfig(context.Background(), feature, local); !result.Applied || result.Err != nil {
		t.Fatalf("local resolver after release: %+v", result)
	}
	if !feature.MayUseSystemResolver() {
		t.Fatal("published local resolver was not reported")
	}
	if _, err := feature.AcquireSystemDNS(); err == nil {
		t.Fatal("takeover accepted a local resolver")
	}
}

func TestSystemDNSGuardRejectsClosingAndClosedResolver(t *testing.T) {
	feature, err := New(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	remote := &Config{NameServer: []*NameServer{preparationServer("tcp+local://127.0.0.1:53", "remote")}}
	if result := ApplyConfig(context.Background(), feature, remote); !result.Applied || result.Err != nil {
		t.Fatalf("remote apply: %+v", result)
	}
	feature.runtime.mu.Lock()
	feature.runtime.closing = newResolverOwner(&DNS{clients: []*Client{{server: NewLocalNameServer()}}})
	feature.runtime.mu.Unlock()
	if _, err := feature.AcquireSystemDNS(); err == nil {
		t.Fatal("takeover accepted an unfinished local resolver")
	}
	feature.runtime.mu.Lock()
	feature.runtime.closing = nil
	feature.runtime.mu.Unlock()
	if err := feature.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := feature.AcquireSystemDNS(); err == nil {
		t.Fatal("takeover accepted a closed resolver")
	}
}

func TestSystemDNSGuardLocalHostnameBootstrap(t *testing.T) {
	for _, scheme := range []string{"tcp+local", "https+local", "h2c+local", "quic+local"} {
		t.Run(scheme, func(t *testing.T) {
			feature, err := New(context.Background(), &Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer feature.Close()
			config := func(host string) *Config {
				return &Config{NameServer: []*NameServer{preparationServer(scheme+"://"+host+":443", "resolver")}}
			}
			for _, host := range []string{"resolver.example", "127.0.0.1"} {
				result := ApplyConfig(context.Background(), feature, config(host))
				if !result.Applied || result.Err != nil {
					t.Fatalf("apply %s: %+v", host, result)
				}
				release, err := feature.AcquireSystemDNS()
				if host == "resolver.example" {
					if err == nil {
						release()
						t.Fatal("system bootstrap allowed during takeover")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					result = ApplyConfig(context.Background(), feature, config("resolver.example"))
					release()
					if result.Applied || result.Err == nil {
						t.Fatalf("unsafe hostname update: %+v", result)
					}
				}
			}
		})
	}
}
