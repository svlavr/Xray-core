package pipe

import (
	"context"

	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/policy"
)

// Option for creating new Pipes.
type Option func(*pipeOption)

// WriteLifecycle is the internal dispatcher lifecycle seam for one pipe
// direction. Implementations must be bounded and non-blocking. It is not a
// general traffic callback API.
type WriteLifecycle interface {
	BeginWrite() bool
	CompleteWrite(bool, uint64)
	HalfClose()
	Seal()
	MarkDrained()
}

// WithoutSizeLimit returns an Option for Pipe to have no size limit.
func WithoutSizeLimit() Option {
	return func(opt *pipeOption) {
		opt.limit = -1
	}
}

// WithSizeLimit returns an Option for Pipe to have the given size limit.
func WithSizeLimit(limit int32) Option {
	return func(opt *pipeOption) {
		opt.limit = limit
	}
}

// DiscardOverflow returns an Option for Pipe to discard writes if full.
func DiscardOverflow() Option {
	return func(opt *pipeOption) {
		opt.discardOverflow = true
	}
}

// WithWriteLifecycle binds one dispatcher-owned lifecycle gate to this pipe.
// It preserves the native Reader and Writer endpoint types.
func WithWriteLifecycle(lifecycle WriteLifecycle) Option {
	return func(opt *pipeOption) {
		opt.lifecycle = lifecycle
	}
}

// OptionsFromContext returns a list of Options from context.
func OptionsFromContext(ctx context.Context) []Option {
	var opt []Option

	bp := policy.BufferPolicyFromContext(ctx)
	if bp.PerConnection >= 0 {
		opt = append(opt, WithSizeLimit(bp.PerConnection))
	} else {
		opt = append(opt, WithoutSizeLimit())
	}

	return opt
}

// New creates a new Reader and Writer that connects to each other.
func New(opts ...Option) (*Reader, *Writer) {
	p := &pipe{
		readSignal:  signal.NewNotifier(),
		writeSignal: signal.NewNotifier(),
		done:        done.New(),
		errChan:     make(chan error, 1),
		option: pipeOption{
			limit: -1,
		},
	}

	for _, opt := range opts {
		opt(&p.option)
	}

	return &Reader{
		pipe: p,
	}, &Writer{
		pipe: p,
	}
}
