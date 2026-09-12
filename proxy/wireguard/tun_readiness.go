package wireguard

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// readinessTun prevents a TUN EventUp from racing ahead of configuration,
// bind callback installation and the explicit initial Device.Up.
type readinessTun struct {
	tun.Device

	events chan tun.Event
	ready  chan struct{}
	stop   chan struct{}
	done   chan struct{}

	readyOnce sync.Once
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func newReadinessTun(device tun.Device) *readinessTun {
	t := &readinessTun{
		Device:    device,
		events:    make(chan tun.Event, 5),
		ready:     make(chan struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	go t.relay(device.Events())
	return t
}

func (t *readinessTun) relay(source <-chan tun.Event) {
	defer close(t.done)
	defer close(t.events)
	for {
		var event tun.Event
		var ok bool
		select {
		case <-t.stop:
			return
		case event, ok = <-source:
			if !ok {
				return
			}
		}
		select {
		case <-t.stop:
			return
		case <-t.ready:
		}
		select {
		case <-t.stop:
			return
		case t.events <- event:
		}
	}
}

func (t *readinessTun) Events() <-chan tun.Event { return t.events }

func (t *readinessTun) markReady() { t.readyOnce.Do(func() { close(t.ready) }) }

func (t *readinessTun) markDeviceOwned() {
	if owned, ok := t.Device.(interface{ markDeviceOwned() }); ok {
		owned.markDeviceOwned()
	}
}

func (t *readinessTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.stop)
		t.closeErr = t.Device.Close()
		<-t.done
		close(t.closeDone)
	})
	<-t.closeDone
	return t.closeErr
}

func (t *readinessTun) closeOutcome() error {
	closeErr := t.Close()
	if outcome, ok := t.Device.(interface{ closeOutcome() error }); ok {
		return outcome.closeOutcome()
	}
	return closeErr
}
