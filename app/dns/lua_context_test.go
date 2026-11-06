package dns

import (
	"context"
	"testing"
	"time"
)

// Delay the notification goroutine after owner cancellation has become visible.
type delayedLuaDNSOwner struct {
	context.Context
	entered chan struct{}
	release chan struct{}
}

func (c *delayedLuaDNSOwner) Value(any) any { return nil }

func (c *delayedLuaDNSOwner) AfterFunc(f func()) func() bool {
	return context.AfterFunc(c.Context, func() {
		close(c.entered)
		<-c.release
		f()
	})
}

func TestLuaDNSOwnerTerminalErrorPrecedesNotification(t *testing.T) {
	root, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &delayedLuaDNSOwner{Context: root, entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-owner.release:
		default:
			close(owner.release)
		}
	}()
	service := new(DNS)
	exact := &resolver{owner: service, ctx: owner}
	service.active = exact
	type callerKey struct{}
	caller := context.WithValue(context.Background(), callerKey{}, "retained")
	err := WithLuaDNS(caller, service, func(bound context.Context, identity any) error {
		if identity != exact || bound.Value(callerKey{}) != "retained" {
			t.Fatal("owner identity or caller values changed")
		}
		terminal, ok := identity.(interface{ Err() error })
		if !ok || terminal.Err() != nil {
			t.Fatal("live resolver owner must expose its terminal status")
		}
		cancel()
		select {
		case <-owner.entered:
		case <-time.After(time.Second):
			t.Fatal("owner notification did not enter the delay barrier")
		}
		if bound.Err() != nil {
			t.Fatal("notification escaped the owned barrier")
		}
		if terminal.Err() != context.Canceled {
			t.Fatal("owner cancellation was hidden by delayed notification")
		}
		close(owner.release)
		select {
		case <-bound.Done():
		case <-time.After(time.Second):
			t.Fatal("released notification did not cancel admitted work")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
