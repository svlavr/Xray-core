package mux

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

const (
	Initializing = 0
	Active       = 1
	Expiring     = 2
)

type XUDP struct {
	GlobalID   [8]byte
	Status     uint64
	Expire     time.Time
	Mux        *Session
	link       *transport.Link // retained endpoints, not a carrier binding
	inspection stats.Exchange
	cancel     context.CancelFunc
	retired    bool
}

type xudpBinding struct {
	ioGate sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	flow   stats.Exchange
	reader interface {
		ReadMultiBufferContext(context.Context) (buf.MultiBuffer, error)
	}
	writer interface {
		WriteMultiBufferContext(context.Context, buf.MultiBuffer) error
	}
}

func newXUDPBinding(link *transport.Link) (*xudpBinding, error) {
	reader, readOK := link.Reader.(interface {
		ReadMultiBufferContext(context.Context) (buf.MultiBuffer, error)
	})
	writer, writeOK := link.Writer.(interface {
		WriteMultiBufferContext(context.Context, buf.MultiBuffer) error
	})
	if !readOK || !writeOK {
		return nil, errors.New("XUDP endpoints do not support binding cancellation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &xudpBinding{ctx: ctx, cancel: cancel, reader: reader, writer: writer}, nil
}

func (b *xudpBinding) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b.ioGate.RLock()
	defer b.ioGate.RUnlock()
	if b.ctx.Err() != nil {
		return nil, io.EOF
	}
	mb, err := b.reader.ReadMultiBufferContext(b.ctx)
	if err == context.Canceled {
		err = io.EOF // a normal detach keeps the native non-error END
	}
	return mb, err
}

func (b *xudpBinding) WriteMultiBuffer(mb buf.MultiBuffer) error {
	b.ioGate.RLock()
	defer b.ioGate.RUnlock()
	if err := b.ctx.Err(); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	if b.flow != nil {
		for _, packet := range mb {
			if packet != nil && packet.UDP != nil {
				b.flow.PacketDestination(*packet.UDP)
			}
		}
	}
	size := uint64(mb.Len())
	err := b.writer.WriteMultiBufferContext(b.ctx, mb)
	if err == nil && b.flow != nil {
		b.flow.AddUplink(size)
	}
	return err
}

// detach revokes only retained pipe access. A packet already returned to the
// old handle still belongs to its old carrier writer, which is never joined here.
func (b *xudpBinding) detach() {
	b.cancel()
	b.ioGate.Lock()
	b.ioGate.Unlock()
}

var XUDPManager struct {
	sync.Mutex
	Map map[[8]byte]*XUDP
}

// Interrupt seals/removes only this retained object before touching endpoints.
// Neither a slow endpoint nor a carrier session can block the global map lock.
func (x *XUDP) Interrupt() {
	XUDPManager.Lock()
	x.retired = true
	if XUDPManager.Map[x.GlobalID] == x {
		delete(XUDPManager.Map, x.GlobalID)
	}
	link, s, flow, cancel := x.link, x.Mux, x.inspection, x.cancel
	preparing := x.Status == Initializing
	XUDPManager.Unlock()
	if cancel != nil {
		cancel()
	}
	if s != nil {
		s.Close(false)
	}
	if link != nil {
		common.Interrupt(link.Reader)
		common.Close(link.Writer)
	}
	if flow != nil && !preparing {
		flow.Finish()
	}
}

func expireXUDP(now time.Time) {
	var expired []*XUDP
	XUDPManager.Lock()
	for id, x := range XUDPManager.Map {
		if x.Status == Expiring && now.After(x.Expire) {
			delete(XUDPManager.Map, id)
			expired = append(expired, x)
		}
	}
	XUDPManager.Unlock()
	for _, x := range expired {
		x.Interrupt()
	}
}

func init() {
	XUDPManager.Map = make(map[[8]byte]*XUDP)
	go func() {
		for {
			time.Sleep(time.Minute)
			expireXUDP(time.Now())
		}
	}()
}

func (w *ServerWorker) handleXUDP(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	mb, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
	if err != nil {
		return err
	}

	XUDPManager.Lock()
	x := XUDPManager.Map[meta.GlobalID]
	if x != nil && x.Status == Initializing {
		XUDPManager.Unlock()
		buf.ReleaseMulti(mb)
		return nil // another carrier owns preparation; release this packet
	}
	if x == nil {
		x = &XUDP{GlobalID: meta.GlobalID}
		XUDPManager.Map[meta.GlobalID] = x
	}
	x.Status = Initializing
	old, link, flow := x.Mux, x.link, x.inspection
	XUDPManager.Unlock()
	var finishAdmission func()
	if flow != nil {
		flow.Rebind(w.runtime, session.TrafficOriginFromContext(ctx))
	}
	// Failed preparation leaves a retained endpoint rebindable, never stuck in
	// Initializing. A fresh dispatch failure has no endpoint to retain.
	defer func() {
		buf.ReleaseMulti(mb)
		XUDPManager.Lock()
		if XUDPManager.Map[x.GlobalID] == x && x.Status == Initializing {
			if x.link == nil {
				delete(XUDPManager.Map, x.GlobalID)
			} else {
				x.Status, x.Expire = Expiring, time.Now().Add(time.Minute)
			}
		}
		retired, flow := x.retired, x.inspection
		XUDPManager.Unlock()
		if finishAdmission != nil {
			finishAdmission()
		} else if retired && flow != nil {
			flow.Finish()
		}
	}()
	if old != nil {
		old.Close(false)
		old.xudp.detach()
	}
	cancelAdmission := func() {
		s := &Session{parent: w.sessionManager, ID: meta.SessionID, server: true, initializing: true, inspection: x.inspection}
		if x.inspection != nil {
			s.cleanup = x.inspection.Finish
		}
		finishAdmission = s.finishAdmission
		s.cancelAdmission(ctx, w.link.Writer)
	}

	for {
		reused := link != nil
		var saved buf.MultiBuffer
		if reused {
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			saved = buf.MultiBuffer{b}
		} else {
			ctx, err = w.observeRetained(ctx, meta.Target, x)
			if err != nil {
				// A local stop won before a child endpoint was published.
				cancelAdmission()
				return nil
			}
			link, err = w.dispatcher.Dispatch(session.ContextWithTimeoutOnly(ctx, true), meta.Target)
			if err != nil {
				XUDPManager.Lock()
				stopped := x.retired
				XUDPManager.Unlock()
				x.Interrupt()
				if stopped {
					cancelAdmission()
					return nil
				}
				return errors.New("failed to dispatch XUDP request").Base(err)
			}
		}
		binding, err := newXUDPBinding(link)
		if err != nil {
			buf.ReleaseMulti(saved)
			common.Interrupt(link.Reader)
			common.Close(link.Writer)
			x.Interrupt()
			return err
		}
		binding.flow = x.inspection
		s := &Session{
			input: binding, output: binding, parent: w.sessionManager, ID: meta.SessionID,
			transferType: protocol.TransferTypePacket, XUDP: x, xudp: binding, server: true, inspection: x.inspection,
		}

		// Match Session.Close's parent -> retained-map lock order. Publish before
		// the first packet write so worker shutdown can cancel a full-pipe wait.
		m := w.sessionManager
		m.Lock()
		XUDPManager.Lock()
		current := XUDPManager.Map[x.GlobalID] == x
		if current && !reused {
			x.link = link
		}
		published := current && !m.closed && m.sessions[s.ID] == nil
		stopped := x.retired
		published = published && !stopped
		if published {
			x.Mux = s
			m.count++
			m.sessions[s.ID] = s
			m.active++
			m.markSeenLocked(s.ID)
		}
		XUDPManager.Unlock()
		m.Unlock()
		if !published {
			binding.cancel()
			buf.ReleaseMulti(saved)
			if !reused {
				if current {
					x.Interrupt()
				} else {
					common.Interrupt(link.Reader)
					common.Close(link.Writer)
				}
			}
			if stopped {
				x.Interrupt()
				cancelAdmission()
				return nil
			}
			return errors.New("failed to add XUDP session")
		}

		payload := mb
		mb = nil // the native writer owns/release-consumes this batch
		err = binding.WriteMultiBuffer(payload)
		if err != nil {
			canceled := binding.ctx.Err() != nil
			if canceled && s.inspection != nil {
				buf.ReleaseMulti(saved)
				go handle(ctx, s, w.link.Writer) // canceled pipe returns EOF; retains its END owner
				return nil
			}
			s.finishServer() // no response task was launched
			if canceled || !reused {
				buf.ReleaseMulti(saved)
				if !reused && !canceled {
					x.Interrupt()
				}
				return err
			}
			// Native retry on a dead retained endpoint, once. Replace the map
			// identity before closing the old endpoint; stale cleanup is inert.
			XUDPManager.Lock()
			if XUDPManager.Map[x.GlobalID] != x {
				XUDPManager.Unlock()
				buf.ReleaseMulti(saved)
				return io.ErrClosedPipe
			}
			next := &XUDP{GlobalID: x.GlobalID}
			XUDPManager.Map[x.GlobalID] = next
			XUDPManager.Unlock()
			x.Interrupt()
			if x.inspection != nil {
				x.inspection.Finish()
			}
			x, link, mb = next, nil, saved
			continue
		}
		buf.ReleaseMulti(saved)
		m.Lock()
		XUDPManager.Lock()
		if !s.closed && XUDPManager.Map[x.GlobalID] == x {
			x.Status = Active
		}
		XUDPManager.Unlock()
		m.Unlock()
		go handle(ctx, s, w.link.Writer)
		return nil
	}
}
