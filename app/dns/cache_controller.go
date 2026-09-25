package dns

import (
	"context"
	go_errors "errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	dns_feature "github.com/xtls/xray-core/features/dns"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	minSizeForEmptyRebuild  = 512
	shrinkAbsoluteThreshold = 10240
	shrinkRatioThreshold    = 0.65
	migrationBatchSize      = 4096
)

type CacheController struct {
	name            string
	disableCache    bool
	serveStale      bool
	serveExpiredTTL int32

	ips      map[string]*record
	dirtyips map[string]*record

	sync.RWMutex
	subs          map[string][]*cacheSubscriber
	cacheCleanup  *ownedPeriodic
	highWatermark int
	requestGroup  singleflight.Group
	migrations    sync.WaitGroup
	closed        atomic.Bool
	sealed        atomic.Bool
}

type cacheSubscriber struct {
	buffer chan *IPRecord
	done   chan struct{}
	once   sync.Once
	owner  *CacheController
	key    string
}

func (s *cacheSubscriber) close() {
	s.once.Do(func() {
		s.owner.Lock()
		group := s.owner.subs[s.key]
		for i, candidate := range group {
			if candidate == s {
				group = append(group[:i], group[i+1:]...)
				break
			}
		}
		if len(group) == 0 {
			delete(s.owner.subs, s.key)
		} else {
			s.owner.subs[s.key] = group
		}
		close(s.done)
		s.owner.Unlock()
	})
}

func NewCacheController(name string, disableCache bool, serveStale bool, serveExpiredTTL uint32) *CacheController {
	c := &CacheController{
		name:            name,
		disableCache:    disableCache,
		serveStale:      serveStale,
		serveExpiredTTL: -int32(serveExpiredTTL),
		ips:             make(map[string]*record),
		subs:            make(map[string][]*cacheSubscriber),
	}

	c.cacheCleanup = newOwnedPeriodic(300*time.Second, c.CacheCleanup)
	return c
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
	expiredKeys, err := c.collectExpiredKeys()
	if err != nil {
		return err
	}
	if len(expiredKeys) == 0 {
		return nil
	}
	c.writeAndShrink(expiredKeys)
	return nil
}

// Seal stops speculative cache scheduling while admitted requests may still
// publish their required response to existing subscribers.
func (c *CacheController) Seal() {
	if c.sealed.Swap(true) {
		return
	}
	_ = c.cacheCleanup.Close()
}

func (c *CacheController) collectExpiredKeys() ([]string, error) {
	c.RLock()
	defer c.RUnlock()

	if len(c.ips) == 0 {
		return nil, errors.New("nothing to do. stopping...")
	}

	// skip collection if a migration is in progress
	if c.dirtyips != nil {
		return nil, nil
	}

	now := time.Now()
	if c.serveStale && c.serveExpiredTTL != 0 {
		now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
	}

	expiredKeys := make([]string, 0, len(c.ips)/4) // pre-allocate

	for domain, rec := range c.ips {
		if (rec.A != nil && rec.A.Expire.Before(now)) ||
			(rec.AAAA != nil && rec.AAAA.Expire.Before(now)) {
			expiredKeys = append(expiredKeys, domain)
		}
	}

	return expiredKeys, nil
}

func (c *CacheController) writeAndShrink(expiredKeys []string) {
	c.Lock()
	defer c.Unlock()

	// double check to prevent upper call multiple cleanup tasks
	if c.dirtyips != nil {
		return
	}

	lenBefore := len(c.ips)
	if lenBefore > c.highWatermark {
		c.highWatermark = lenBefore
	}

	now := time.Now()
	if c.serveStale && c.serveExpiredTTL != 0 {
		now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
	}

	for _, domain := range expiredKeys {
		rec := c.ips[domain]
		if rec == nil {
			continue
		}
		if rec.A != nil && rec.A.Expire.Before(now) {
			rec.A = nil
		}
		if rec.AAAA != nil && rec.AAAA.Expire.Before(now) {
			rec.AAAA = nil
		}
		if rec.A == nil && rec.AAAA == nil {
			delete(c.ips, domain)
		}
	}

	lenAfter := len(c.ips)

	if lenAfter == 0 {
		if c.highWatermark >= minSizeForEmptyRebuild {
			errors.LogDebug(
				context.Background(), c.name,
				" rebuilding empty cache map to reclaim memory.",
				" size_before_cleanup=", lenBefore,
				" peak_size_before_rebuild=", c.highWatermark,
			)

			c.ips = make(map[string]*record)
			c.highWatermark = 0
		}
		return
	}

	if reductionFromPeak := c.highWatermark - lenAfter; reductionFromPeak > shrinkAbsoluteThreshold &&
		float64(reductionFromPeak) > float64(c.highWatermark)*shrinkRatioThreshold {
		errors.LogDebug(
			context.Background(), c.name,
			" shrinking cache map to reclaim memory.",
			" new_size=", lenAfter,
			" peak_size_before_shrink=", c.highWatermark,
			" reduction_since_peak=", reductionFromPeak,
		)

		c.dirtyips = c.ips
		c.ips = make(map[string]*record, int(float64(lenAfter)*1.1))
		c.highWatermark = lenAfter
		c.migrations.Add(1)
		go func() {
			defer c.migrations.Done()
			c.migrate()
		}()
	}
}

type migrationEntry struct {
	key   string
	value *record
}

func (c *CacheController) migrate() {
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), c.name, " panic during cache migration: ", r)
			c.Lock()
			c.dirtyips = nil
			// c.ips = make(map[string]*record)
			// c.highWatermark = 0
			c.Unlock()
		}
	}()

	c.RLock()
	dirtyips := c.dirtyips
	c.RUnlock()

	// double check to prevent upper call multiple cleanup tasks
	if dirtyips == nil {
		return
	}

	errors.LogDebug(context.Background(), c.name, " starting background cache migration for ", len(dirtyips), " items")

	batch := make([]migrationEntry, 0, migrationBatchSize)
	for domain, recD := range dirtyips {
		batch = append(batch, migrationEntry{domain, recD})

		if len(batch) >= migrationBatchSize {
			c.flush(batch)
			batch = batch[:0]
			runtime.Gosched()
		}
	}
	if len(batch) > 0 {
		c.flush(batch)
	}

	c.Lock()
	c.dirtyips = nil
	c.Unlock()

	errors.LogDebug(context.Background(), c.name, " cache migration completed")
}

func (c *CacheController) flush(batch []migrationEntry) {
	c.Lock()
	defer c.Unlock()

	for _, dirty := range batch {
		if cur := c.ips[dirty.key]; cur != nil {
			merge := &record{}
			if cur.A == nil {
				merge.A = dirty.value.A
			} else {
				merge.A = cur.A
			}
			if cur.AAAA == nil {
				merge.AAAA = dirty.value.AAAA
			} else {
				merge.AAAA = cur.AAAA
			}
			c.ips[dirty.key] = merge
		} else {
			c.ips[dirty.key] = dirty.value
		}
	}
}

func (c *CacheController) updateRecord(req *dnsRequest, rep *IPRecord) {
	if c.closed.Load() {
		return
	}
	rtt := time.Since(req.start)

	switch req.reqType {
	case dnsmessage.TypeA:
		c.publish(req.domain+"4", rep)
	case dnsmessage.TypeAAAA:
		c.publish(req.domain+"6", rep)
	}

	if c.disableCache {
		errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt)
		return
	}

	c.Lock()
	lockWait := time.Since(req.start) - rtt

	newRec := &record{}
	oldRec := c.ips[req.domain]
	var dirtyRec *record
	if c.dirtyips != nil {
		dirtyRec = c.dirtyips[req.domain]
	}

	var pubRecord *IPRecord
	var pubSuffix string

	switch req.reqType {
	case dnsmessage.TypeA:
		newRec.A = rep
		if oldRec != nil && oldRec.AAAA != nil {
			newRec.AAAA = oldRec.AAAA
			pubRecord = oldRec.AAAA
		} else if dirtyRec != nil && dirtyRec.AAAA != nil {
			pubRecord = dirtyRec.AAAA
		}
		pubSuffix = "6"
	case dnsmessage.TypeAAAA:
		newRec.AAAA = rep
		if oldRec != nil && oldRec.A != nil {
			newRec.A = oldRec.A
			pubRecord = oldRec.A
		} else if dirtyRec != nil && dirtyRec.A != nil {
			pubRecord = dirtyRec.A
		}
		pubSuffix = "4"
	}

	c.ips[req.domain] = newRec
	c.Unlock()

	if pubRecord != nil {
		_, ttl, err := pubRecord.getIPs()
		if ttl > 0 && !go_errors.Is(err, errRecordNotFound) {
			c.publish(req.domain+pubSuffix, pubRecord)
		}
	}

	errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt, ", lock: ", lockWait)

	if !c.sealed.Load() && (!c.serveStale || c.serveExpiredTTL != 0) {
		common.Must(c.cacheCleanup.Start())
	}
}

func (c *CacheController) findRecords(domain string) *record {
	c.RLock()
	defer c.RUnlock()

	rec := c.ips[domain]
	if rec == nil && c.dirtyips != nil {
		rec = c.dirtyips[domain]
	}
	return rec
}

func (c *CacheController) subscribe(key string) *cacheSubscriber {
	sub := &cacheSubscriber{buffer: make(chan *IPRecord, 16), done: make(chan struct{}), owner: c, key: key}
	c.Lock()
	if c.closed.Load() {
		close(sub.done)
		c.Unlock()
		return sub
	}
	c.subs[key] = append(c.subs[key], sub)
	c.Unlock()
	return sub
}

func (c *CacheController) publish(key string, record *IPRecord) {
	c.RLock()
	defer c.RUnlock()
	for _, sub := range c.subs[key] {
		select {
		case sub.buffer <- record:
		default:
		}
	}
}

func (c *CacheController) registerSubscribers(domain string, option dns_feature.IPOption) (sub4 *cacheSubscriber, sub6 *cacheSubscriber) {
	// ipv4 and ipv6 belong to different subscription groups
	if option.IPv4Enable {
		sub4 = c.subscribe(domain + "4")
	}
	if option.IPv6Enable {
		sub6 = c.subscribe(domain + "6")
	}
	return
}

func closeSubscribers(sub4 *cacheSubscriber, sub6 *cacheSubscriber) {
	if sub4 != nil {
		sub4.close()
	}
	if sub6 != nil {
		sub6.close()
	}
}

func (c *CacheController) Close() error {
	c.closed.Store(true)
	_ = c.cacheCleanup.Close()
	c.Lock()
	var subscribers []*cacheSubscriber
	for _, group := range c.subs {
		for _, sub := range group {
			subscribers = append(subscribers, sub)
		}
	}
	c.Unlock()
	for _, sub := range subscribers {
		sub.close()
	}
	c.migrations.Wait()
	return nil
}
