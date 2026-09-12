package reverse

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

const (
	internalDomain = "reverse"
)

func isDomain(dest net.Destination, domain string) bool {
	return dest.Address.Family().IsDomain() && dest.Address.Domain() == domain
}

func isInternalDomain(dest net.Destination) bool {
	return isDomain(dest, internalDomain)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Reverse)
		if err := core.RequireFeatures(ctx, func(d routing.Dispatcher, om outbound.Manager) error {
			return r.init(ctx, config.(*Config), d, om)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}

type Reverse struct {
	access    sync.Mutex
	bridges   []*Bridge
	portals   []*Portal
	stopped   bool
	stopOnce  sync.Once
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func (r *Reverse) Init(config *Config, d routing.Dispatcher, ohm outbound.Manager) error {
	return r.init(context.Background(), config, d, ohm)
}

func (r *Reverse) init(ctx context.Context, config *Config, d routing.Dispatcher, ohm outbound.Manager) error {
	r.access.Lock()
	if r.stopped {
		r.access.Unlock()
		return errors.New("reverse is closed")
	}
	r.access.Unlock()
	for _, bConfig := range config.BridgeConfig {
		b, err := newBridge(ctx, bConfig, d)
		if err != nil {
			_ = r.Close()
			return err
		}
		r.access.Lock()
		if r.stopped {
			r.access.Unlock()
			_ = b.Close()
			return errors.New("reverse is closed")
		}
		r.bridges = append(r.bridges, b)
		r.access.Unlock()
	}

	for _, pConfig := range config.PortalConfig {
		p, err := NewPortal(pConfig, ohm)
		if err != nil {
			r.Close()
			return err
		}
		r.access.Lock()
		if r.stopped {
			r.access.Unlock()
			_ = p.Close()
			return errors.New("reverse is closed")
		}
		r.portals = append(r.portals, p)
		r.access.Unlock()
	}

	return nil
}

func (r *Reverse) Type() interface{} {
	return (*Reverse)(nil)
}

func (*Reverse) ShutdownPhase() features.ShutdownPhase {
	return features.ShutdownPhasePreOwner
}

func (r *Reverse) Start() error {
	r.access.Lock()
	if r.stopped {
		r.access.Unlock()
		return errors.New("reverse is closed")
	}
	bridges := append([]*Bridge(nil), r.bridges...)
	portals := append([]*Portal(nil), r.portals...)
	r.access.Unlock()
	for _, b := range bridges {
		if err := b.Start(); err != nil {
			return errors.Combine(err, r.Close())
		}
	}

	for _, p := range portals {
		if err := p.Start(); err != nil {
			return errors.Combine(err, r.Close())
		}
	}

	return nil
}

// SignalStop prevents reverse producers from publishing new workers before
// their dependencies are closed. It intentionally does not wait.
func (r *Reverse) SignalStop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		r.access.Lock()
		r.stopped = true
		bridges := append([]*Bridge(nil), r.bridges...)
		portals := append([]*Portal(nil), r.portals...)
		r.access.Unlock()
		for _, b := range bridges {
			b.SignalStop()
		}
		for _, p := range portals {
			p.SignalStop()
		}
	})
}

func (r *Reverse) Close() error {
	if r == nil {
		return nil
	}
	r.access.Lock()
	portals := append([]*Portal(nil), r.portals...)
	r.access.Unlock()
	for _, portal := range portals {
		portal.startMu.Lock()
	}
	var removeErr error
	for _, portal := range portals {
		if err := portal.removeHandlerLocked(); err != nil {
			removeErr = err
			break
		}
	}
	if removeErr == nil {
		r.SignalStop()
	}
	for i := len(portals) - 1; i >= 0; i-- {
		portals[i].startMu.Unlock()
	}
	if removeErr != nil {
		return removeErr
	}
	r.closeOnce.Do(func() {
		r.access.Lock()
		bridges := append([]*Bridge(nil), r.bridges...)
		portals := append([]*Portal(nil), r.portals...)
		r.closeDone = make(chan struct{})
		r.access.Unlock()
		var errs []error
		for _, b := range bridges {
			errs = append(errs, b.Close())
		}
		for _, p := range portals {
			errs = append(errs, p.closeOwned())
		}
		r.access.Lock()
		r.closeErr = errors.Combine(errs...)
		close(r.closeDone)
		r.access.Unlock()
	})
	r.access.Lock()
	done := r.closeDone
	r.access.Unlock()
	<-done
	r.access.Lock()
	defer r.access.Unlock()
	return r.closeErr
}
