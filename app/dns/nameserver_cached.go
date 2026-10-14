package dns

import (
	"context"
	go_errors "errors"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/features/dns"
)

type CachedNameserver interface {
	getCacheController() *CacheController

	sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns.IPOption)
}

// queryIP is called from dns.Server->queryIPTimeout
func queryIP(ctx context.Context, s CachedNameserver, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	cache := s.getCacheController()
	if !cache.disableCache {
		if rec := cache.findRecords(fqdn); rec != nil {
			ips, ttl, err := merge(option, rec.A, rec.AAAA)
			if !go_errors.Is(err, errRecordNotFound) {
				if ttl > 0 {
					errors.LogDebugInner(ctx, err, cache.name, " cache HIT ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
					return ips, uint32(ttl), err
				}
				if cache.serveStale && (cache.serveExpiredTTL == 0 || cache.serveExpiredTTL < ttl) {
					errors.LogDebugInner(ctx, err, cache.name, " cache OPTIMISTE ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheOptimiste, Elapsed: 0, Error: err})
					cache.startPull(ctx, s, fqdn, option)
					return ips, 1, err
				}
			}
		}
	} else {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", fqdn, " at ", cache.name)
	}

	return fetch(ctx, s, fqdn, option)
}

func pull(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) {
	nctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	fetch(nctx, s, fqdn, option)
}

// fetch preserves native coalescing, but each waiter can cancel independently.
// Shared work follows its native leader deadline and the cache owner. A live
// sibling retries only an empty flight interrupted by that leader's expiry.
func fetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) ([]net.IP, uint32, error) {
	cache := s.getCacheController()
	key := fqdn
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		key += "46"
	case option.IPv4Enable:
		key += "4"
	case option.IPv6Enable:
		key += "6"
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return nil, 0, context.DeadlineExceeded
		}
		// DoChan registers the native waiter synchronously before its Done
		// channel is observed. Only the one fresh flight callback owns work.
		ch := cache.requestGroup.DoChan(key, func() (any, error) {
			if err := ctx.Err(); err != nil {
				return result{error: err, interrupted: true, retryableLeaderExpiry: true}, nil
			}
			if !cache.begin() {
				return result{error: context.Canceled}, nil
			}
			defer cache.workers.Done()
			deadline, hasDeadline := ctx.Deadline()
			if hasDeadline && !time.Now().Before(deadline) {
				return result{error: context.DeadlineExceeded, interrupted: true, retryableLeaderExpiry: true}, nil
			}
			if !hasDeadline {
				deadline = time.Now().Add(8 * time.Second)
			}
			base := context.Context(&dnsRequestContext{Context: context.WithoutCancel(ctx), caller: cache.ctx})
			if cache.disableCache {
				base = ctx
			}
			fetchCtx, cancel := context.WithDeadline(base, deadline)
			stop := context.AfterFunc(cache.ctx, cancel)
			defer stop()
			defer cancel()
			ret := doFetch(fetchCtx, s, fqdn, option)
			leaderExpired := ctx.Err() != nil || (hasDeadline && !time.Now().Before(deadline))
			ret.retryableLeaderExpiry = len(ret.ips) == 0 && ret.interrupted && leaderExpired
			return ret, nil
		})
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-cache.ctx.Done():
			return nil, 0, cache.ctx.Err()
		case response := <-ch:
			ret := response.Val.(result)
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			if err := cache.ctx.Err(); err != nil {
				return nil, 0, err
			}
			if ret.retryableLeaderExpiry {
				continue
			}
			return ret.ips, ret.ttl, ret.error
		}
	}
}

type result struct {
	ips []net.IP
	ttl uint32
	error
	retryableLeaderExpiry bool
	interrupted           bool
}

func doFetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) result {
	sub4, sub6 := s.getCacheController().registerSubscribers(fqdn, option)
	defer closeSubscribers(sub4, sub6)

	noResponseErrCh := make(chan error, 2)
	var interruption, terminal error
	recordTerminal := func(err error) {
		if terminal == nil {
			terminal = err
		} else {
			terminal = errors.Combine(terminal, err)
		}
	}
	onEvent := func(sub *pubsub.Subscriber) (*IPRecord, error) {
		if sub == nil {
			return nil, nil
		}
		if err := ctx.Err(); err != nil {
			interruption = err
			return nil, err
		}
		select {
		case <-ctx.Done():
			interruption = ctx.Err()
			return nil, interruption
		case err := <-noResponseErrCh:
			if (go_errors.Is(err, context.Canceled) || go_errors.Is(err, context.DeadlineExceeded)) && ctx.Err() != nil {
				interruption = ctx.Err()
			} else {
				recordTerminal(err)
			}
			return nil, err
		case msg := <-sub.Wait():
			rec := msg.(*IPRecord)
			if _, _, err := rec.getIPs(); err != nil && !go_errors.Is(err, dns.ErrEmptyResponse) {
				recordTerminal(err)
			}
			sub.Close()
			return rec, nil
		}
	}

	start := time.Now()
	s.sendQuery(ctx, noResponseErrCh, fqdn, option)

	rec4, err4 := onEvent(sub4)
	rec6, err6 := onEvent(sub6)

	var errs []error
	if err4 != nil {
		errs = append(errs, err4)
	}
	if err6 != nil {
		errs = append(errs, err6)
	}

	ips, ttl, err := merge(option, rec4, rec6, errs...)
	if len(ips) == 0 {
		if terminal != nil && go_errors.Is(err, errRecordNotFound) {
			// Native merge can stop at the missing family. Keep a definitive
			// outcome already selected before the other family was interrupted.
			err = terminal
		} else if terminal == nil && interruption != nil {
			err = interruption
		}
	}
	var rTTL uint32
	if ttl > 0 {
		rTTL = uint32(ttl)
	} else if ttl == 0 && go_errors.Is(err, errRecordNotFound) {
		rTTL = 0
	} else { // edge case: where a fast rep's ttl expires during the rtt of a slower, parallel query
		rTTL = 1
	}

	log.Record(&log.DNSLog{Server: s.getCacheController().name, Domain: fqdn, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	// Preserve any selected native response/error, including negative records
	// and mixed-family outcomes. Only a context-only empty flight is retryable.
	return result{ips: ips, ttl: rTTL, error: err, interrupted: len(ips) == 0 && interruption != nil && terminal == nil}
}

func merge(option dns.IPOption, rec4 *IPRecord, rec6 *IPRecord, errs ...error) ([]net.IP, int32, error) {
	var allIPs []net.IP
	var rTTL int32 = dns.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable {
		ips, ttl, err := rec4.getIPs() // it's safe
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if option.IPv6Enable {
		ips, ttl, err := rec6.getIPs() // it's safe
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if len(allIPs) > 0 {
		return allIPs, rTTL, nil
	}
	if len(errs) == 2 && go_errors.Is(errs[0], errs[1]) {
		return nil, rTTL, errs[0]
	}
	return nil, rTTL, errors.Combine(errs...)
}
