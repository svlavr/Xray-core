package splithttp

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	Running      atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
	NotUsed      atomic.Bool
	manager      *XmuxManager
}

func (c *XmuxClient) AddRunning() {
	c.Running.Add(1)
}

func (c *XmuxClient) DoneRunning() {
	c.Running.Add(-1)
	c.maybeClose()
	if c.manager != nil {
		if c.NotUsed.Load() && c.Running.Load() <= 0 {
			c.manager.removeRetiring(c)
		}
		select {
		case c.manager.notify <- struct{}{}:
		default:
		}
	}
}

func (m *XmuxManager) removeRetiring(expected *XmuxClient) {
	globalDialerAccess.Lock()
	for i, client := range m.retiring {
		if client == expected {
			m.retiring = append(m.retiring[:i], m.retiring[i+1:]...)
			break
		}
	}
	globalDialerAccess.Unlock()
}

// close the XmuxConn if it is not used and has no running requests
func (c *XmuxClient) maybeClose() {
	if c.NotUsed.Load() && c.Running.Load() <= 0 {
		common.Close(c.XmuxConn)
	}
}

type XmuxManager struct {
	xmuxConfig  XmuxConfig
	concurrency int32
	connections int32 // selectable XmuxClient domains, not a physical carrier bound
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	retiring    []*XmuxClient
	sealed      atomic.Bool
	lifecycle   *internet.ResourceLifecycle
	unregister  func()
	key         dialerConf
	notify      chan struct{}
	closeOnce   sync.Once
	closeDone   chan struct{}
	closeErr    error
}

func NewXmuxManager(xmuxConfig XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
		notify:      make(chan struct{}, 1),
		closeDone:   make(chan struct{}),
	}
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
		manager:   m,
	}
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient { // when locking
	if m.sealed.Load() {
		return nil
	}
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			errors.LogDebug(ctx, "XMUX: removing xmuxClient, IsClosed() = ", xmuxClient.XmuxConn.IsClosed(),
				", Running = ", xmuxClient.Running.Load(),
				", leftUsage = ", xmuxClient.leftUsage,
				", LeftRequests = ", xmuxClient.LeftRequests.Load(),
				", UnreusableAt = ", xmuxClient.UnreusableAt)
			xmuxClient.NotUsed.Store(true)
			xmuxClient.maybeClose()
			if xmuxClient.Running.Load() > 0 {
				m.retiring = append(m.retiring, xmuxClient)
			}
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
		} else {
			i++
		}
	}

	if len(m.xmuxClients) == 0 {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because xmuxClients is empty")
		return m.newXmuxClient()
	}

	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because maxConnections was not hit, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClient()
	}

	xmuxClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.Running.Load() < m.concurrency {
				xmuxClients = append(xmuxClients, xmuxClient)
			}
		}
	} else {
		xmuxClients = m.xmuxClients
	}

	if len(xmuxClients) == 0 {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because maxConcurrency was hit, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClient()
	}

	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(xmuxClients))))
	xmuxClient := xmuxClients[i.Int64()]
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	return xmuxClient
}

func (m *XmuxManager) SignalStop() {
	if m == nil || !m.sealed.CompareAndSwap(false, true) {
		return
	}
	globalDialerAccess.Lock()
	clients := append(append([]*XmuxClient(nil), m.xmuxClients...), m.retiring...)
	for _, client := range clients {
		client.NotUsed.Store(true)
	}
	globalDialerAccess.Unlock()
	var stopWG sync.WaitGroup
	for _, client := range clients {
		if signaler, ok := client.XmuxConn.(interface{ SignalStop() }); ok {
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				signaler.SignalStop()
			}()
		}
	}
	stopWG.Wait()
	for _, client := range clients {
		client.maybeClose()
	}
}

func (m *XmuxManager) Close() error {
	if m == nil {
		return nil
	}
	m.SignalStop()
	m.closeOnce.Do(func() {
		globalDialerAccess.Lock()
		clients := append(append([]*XmuxClient(nil), m.xmuxClients...), m.retiring...)
		m.xmuxClients = nil
		m.retiring = nil
		globalDialerAccess.Unlock()
		results := make(chan error, len(clients))
		for _, client := range clients {
			go func() { results <- common.Close(client.XmuxConn) }()
		}
		var closeErrors []error
		for range clients {
			closeErrors = append(closeErrors, <-results)
		}
		for {
			active := false
			for _, client := range clients {
				if client.Running.Load() > 0 {
					active = true
					break
				}
			}
			if !active {
				break
			}
			<-m.notify
		}
		globalDialerAccess.Lock()
		if globalDialerMap[m.key] == m {
			delete(globalDialerMap, m.key)
		}
		globalDialerAccess.Unlock()
		if m.unregister != nil {
			m.unregister()
			m.unregister = nil
		}
		m.closeErr = errors.Combine(closeErrors...)
		close(m.closeDone)
	})
	<-m.closeDone
	return m.closeErr
}
