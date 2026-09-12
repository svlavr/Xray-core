package flow

import (
	"context"
	"errors"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

// BindExternalLinkIO installs one exact-link write boundary below the
// dispatcher's stock stats wrapper and returns the read lifecycle used by its
// stock timeout wrapper. It never creates a second root or owner.
func BindExternalLinkIO(ctx context.Context, link *transport.Link) (buf.ReadLifecycle, bool) {
	if ctx == nil || link == nil || link.Reader == nil || link.Writer == nil {
		return nil, false
	}
	scope, _ := ctx.Value(externalOwnerContextKey{}).(*ExternalOwnerScope)
	if scope == nil {
		return nil, false
	}
	handle := scope.bindAccounting(link)
	if handle == nil {
		return nil, false
	}
	root := handle.LogicalRoot()
	link.Writer = &externalLinkWriter{writer: link.Writer, gate: root.Downlink(), handle: handle}
	return &externalLinkReadLifecycle{gate: root.Uplink()}, true
}

type externalLinkReadLifecycle struct {
	gate *DirectionGate
}

func (l *externalLinkReadLifecycle) BeginRead() bool {
	return l != nil && l.gate != nil && l.gate.reserve()
}

func (l *externalLinkReadLifecycle) CompleteRead(reserved bool, bytes uint64, err error) {
	if l == nil || l.gate == nil {
		return
	}
	if errors.Is(err, io.EOF) {
		l.gate.HalfClose()
	}
	l.gate.complete(reserved, l.gate.byteScope, bytes)
}

type externalLinkWriter struct {
	writer buf.Writer
	gate   *DirectionGate
	handle *Handle
}

func (w *externalLinkWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return w.writer.WriteMultiBuffer(mb)
	}
	acceptedBytes := uint64(mb.Len())
	operation := w.gate.Reserve()
	err := w.writer.WriteMultiBuffer(mb)
	if err != nil {
		w.handle.MarkDirectionAccountingBoundaryUnproven(DirectionDownlink)
		operation.Complete(0)
		return err
	}
	operation.Complete(acceptedBytes)
	return nil
}

func (w *externalLinkWriter) Close() error {
	err := common.Close(w.writer)
	w.gate.HalfClose()
	return err
}

func (w *externalLinkWriter) Interrupt() {
	common.Interrupt(w.writer)
}

var (
	_ buf.ReadLifecycle    = (*externalLinkReadLifecycle)(nil)
	_ buf.Writer           = (*externalLinkWriter)(nil)
	_ common.Closable      = (*externalLinkWriter)(nil)
	_ common.Interruptible = (*externalLinkWriter)(nil)
)
