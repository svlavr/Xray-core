package dns

import (
	"context"
	"fmt"
)

// CacheReadyForTest captures one configured cache owner for an external test.
// This file is compiled only by go test; it adds no runtime API or query I/O.
func CacheReadyForTest(d *DNS, serverID, domain string) (func() (bool, error), error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.active
	if d.closed || r == nil || r.ctx.Err() != nil {
		return nil, context.Canceled
	}
	var cache *CacheController
	for _, client := range r.clients {
		if client.id == serverID {
			server, ok := client.server.(CachedNameserver)
			if !ok {
				return nil, fmt.Errorf("DNS server %q has no native cache", serverID)
			}
			cache = server.getCacheController()
			break
		}
	}
	if cache == nil {
		return nil, fmt.Errorf("DNS cache owner %q not found", serverID)
	}
	fqdn := Fqdn(domain)
	return func() (bool, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed || d.active != r || r.ctx.Err() != nil {
			return false, context.Canceled
		}
		cache.RLock()
		defer cache.RUnlock()
		if err := cache.ctx.Err(); err != nil {
			return false, err
		}
		if cache.disableCache {
			return false, nil
		}
		rec := cache.ips[fqdn]
		if rec == nil {
			rec = cache.dirtyips[fqdn]
		}
		if rec == nil || rec.A == nil {
			return false, nil
		}
		ips, ttl, err := rec.A.getIPs()
		return len(ips) != 0 && ttl > 0 && err == nil, err
	}, nil
}
