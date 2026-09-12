package observatory

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
	"google.golang.org/protobuf/proto"
)

type Observer struct {
	config *Config
	ctx    context.Context

	statusLock sync.Mutex
	status     []*OutboundStatus

	lifecycleMu sync.Mutex
	lifecycle   task.Lifecycle
	cancel      context.CancelFunc
	started     bool

	ohm        outbound.Manager
	dispatcher routing.Dispatcher
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	status := make([]*OutboundStatus, len(o.status))
	for i, current := range o.status {
		if current != nil {
			status[i] = proto.Clone(current).(*OutboundStatus)
		}
	}
	return &ObservationResult{Status: status}, nil
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	o.lifecycleMu.Lock()
	defer o.lifecycleMu.Unlock()
	if o.started || o.lifecycle.Sealed() {
		return nil
	}
	o.started = true
	if o.config == nil || len(o.config.SubjectSelector) == 0 || !o.lifecycle.Acquire() {
		return nil
	}
	o.ctx, o.cancel = context.WithCancel(o.ctx)
	go func() {
		defer o.lifecycle.Release()
		o.background()
	}()
	return nil
}

func (o *Observer) Close() error {
	o.lifecycleMu.Lock()
	o.lifecycle.Seal()
	cancel := o.cancel
	o.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	o.lifecycle.Wait()
	return nil
}

func (o *Observer) background() {
	for o.ctx.Err() == nil {
		hs, ok := o.ohm.(outbound.HandlerSelector)
		if !ok {
			errors.LogInfo(o.ctx, "outbound.Manager is not a HandlerSelector")
			return
		}

		outbounds := hs.Select(o.config.SubjectSelector)

		if !o.clearRemovedOutbounds(outbounds) {
			return
		}

		sleepTime := time.Second * 10
		if o.config.ProbeInterval != 0 {
			sleepTime = time.Duration(o.config.ProbeInterval)
		}

		if len(outbounds) == 0 {
			errors.LogWarning(o.ctx, "no outbound matches subjectSelector ", o.config.SubjectSelector)
			if !o.wait(o.ctx, sleepTime) {
				return
			}
			continue
		}

		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
			for _, v := range outbounds {
				result := o.probe(o.ctx, v)
				if !o.updateStatusForResult(v, &result) {
					return
				}
				if !o.wait(o.ctx, sleepTime) {
					return
				}
			}
			continue
		}

		ch := make(chan struct{}, len(outbounds))

		for _, v := range outbounds {
			o.lifecycleMu.Lock()
			admitted := o.lifecycle.Acquire()
			o.lifecycleMu.Unlock()
			if !admitted {
				return
			}
			go func(v string) {
				defer o.lifecycle.Release()
				result := o.probe(o.ctx, v)
				o.updateStatusForResult(v, &result)
				ch <- struct{}{}
			}(v)
		}

		for range outbounds {
			select {
			case <-ch:
			case <-o.ctx.Done():
				return
			}
		}
		if !o.wait(o.ctx, sleepTime) {
			return
		}
	}
}

func (o *Observer) wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (o *Observer) clearRemovedOutbounds(outbounds []string) bool {
	o.lifecycleMu.Lock()
	defer o.lifecycleMu.Unlock()
	if o.lifecycle.Sealed() {
		return false
	}
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	if len(o.status) == 0 {
		return true
	}
	var pruned []*OutboundStatus
	for _, status := range o.status {
		if slices.Contains(outbounds, status.OutboundTag) {
			pruned = append(pruned, status)
		}
	}
	o.status = pruned
	return true
}

func (o *Observer) probe(ctx context.Context, outbound string) ProbeResult {
	errorCollectorForRequest := newErrorCollector()
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	httpTransport := http.Transport{
		DisableKeepAlives: true,
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, nil
		},
		DialContext: func(requestCtx context.Context, network string, addr string) (net.Conn, error) {
			if !o.lifecycle.Acquire() {
				return nil, context.Canceled
			}
			defer o.lifecycle.Release()
			// MUST use Xray's built in context system
			dest, err := v2net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, errors.New("cannot understand address").Base(err)
			}
			dialCtx, cancelDial := context.WithCancel(probeCtx)
			stopRequestCancel := context.AfterFunc(requestCtx, cancelDial)
			defer func() {
				stopRequestCancel()
				cancelDial()
			}()
			trackedCtx := session.TrackedConnectionError(dialCtx, errorCollectorForRequest)
			conn, err := tagged.Dialer(trackedCtx, o.dispatcher, dest, outbound)
			if err != nil {
				return nil, errors.New("cannot dial remote address ", dest).Base(err)
			}
			return conn, nil
		},
		TLSHandshakeTimeout: time.Second * 5,
	}
	httpClient := &http.Client{
		Transport: &httpTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: time.Second * 5,
	}
	var GETTime time.Duration
	err := func() error {
		startTime := time.Now()
		probeURL := "https://www.google.com/generate_204"
		if o.config.ProbeUrl != "" {
			probeURL = o.config.ProbeUrl
		}
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
		if err != nil {
			return err
		}
		utils.TryDefaultHeadersWith(req.Header, "nav")
		response, err := httpClient.Do(req)
		if err != nil {
			return errors.New("outbound failed to relay connection").Base(err)
		}
		if response.Body != nil {
			defer response.Body.Close()
		}
		endTime := time.Now()
		GETTime = endTime.Sub(startTime)
		return nil
	}()
	if err != nil {
		errorMessage := "the outbound " + outbound + " is dead: GET request failed:" + err.Error() + "with outbound handler report underlying connection failed"
		errors.LogInfoInner(o.ctx, errorCollectorForRequest.UnderlyingError(), errorMessage)
		return ProbeResult{Alive: false, LastErrorReason: errorMessage}
	}
	errors.LogInfo(o.ctx, "the outbound ", outbound, " is alive:", GETTime.Seconds())
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}
}

func (o *Observer) updateStatusForResult(outbound string, result *ProbeResult) bool {
	o.lifecycleMu.Lock()
	defer o.lifecycleMu.Unlock()
	if o.lifecycle.Sealed() {
		return false
	}
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	var status *OutboundStatus
	if location := o.findStatusLocationLockHolderOnly(outbound); location != -1 {
		status = o.status[location]
	} else {
		status = &OutboundStatus{}
		o.status = append(o.status, status)
	}

	status.LastTryTime = time.Now().Unix()
	status.OutboundTag = outbound
	status.Alive = result.Alive
	if result.Alive {
		status.Delay = result.Delay
		status.LastSeenTime = status.LastTryTime
		status.LastErrorReason = ""
	} else {
		status.LastErrorReason = result.LastErrorReason
		status.Delay = 99999999
	}
	return true
}

func (o *Observer) findStatusLocationLockHolderOnly(outbound string) int {
	for i, v := range o.status {
		if v.OutboundTag == outbound {
			return i
		}
	}
	return -1
}

func New(ctx context.Context, config *Config) (*Observer, error) {
	var outboundManager outbound.Manager
	var dispatcher routing.Dispatcher
	err := core.RequireFeatures(ctx, func(om outbound.Manager, rd routing.Dispatcher) {
		outboundManager = om
		dispatcher = rd
	})
	if err != nil {
		return nil, errors.New("Cannot get depended features").Base(err)
	}
	return &Observer{
		config:     config,
		ctx:        ctx,
		ohm:        outboundManager,
		dispatcher: dispatcher,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
