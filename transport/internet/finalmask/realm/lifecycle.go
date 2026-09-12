package realm

import (
	"context"
	"io"
	"sync"
)

// contextCloser gives the provisional and published lower resource one exact
// close result even when owner cancellation races explicit Close.
type contextCloser struct {
	closer       io.Closer
	once         sync.Once
	done         chan struct{}
	err          error
	stopCallback func() bool
	callbackDone chan struct{}
}

func newContextCloser(ctx context.Context, closer io.Closer) *contextCloser {
	c := &contextCloser{
		closer:       closer,
		done:         make(chan struct{}),
		callbackDone: make(chan struct{}),
	}
	c.stopCallback = context.AfterFunc(ctx, func() {
		defer close(c.callbackDone)
		_ = c.Close()
	})
	return c
}

func (c *contextCloser) Close() error {
	c.once.Do(func() {
		c.err = c.closer.Close()
		close(c.done)
	})
	<-c.done
	return c.err
}

func (c *contextCloser) StopAndJoin() {
	if !c.stopCallback() {
		<-c.callbackDone
	}
}
