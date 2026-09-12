package stat

import (
	"net"
	"testing"
	"time"
)

type unwrapConn struct {
	net.Conn
	next net.Conn
}

type uncomparableConn struct {
	net.Conn
	bytes []byte
}

func (c uncomparableConn) UnwrapConnection() net.Conn { return c.Conn }

func (c *unwrapConn) UnwrapConnection() net.Conn { return c.next }

func TestTryUnwrapStatsConnPreservesCounterConnectionSemantics(t *testing.T) {
	underlying, peer := net.Pipe()
	defer underlying.Close()
	defer peer.Close()
	counter := &CounterConnection{Connection: underlying}
	if got := TryUnwrapStatsConn(counter); got != underlying {
		t.Fatalf("got %T, want underlying connection", got)
	}
}

func TestTryUnwrapStatsConnRecursesThroughNestedWrappers(t *testing.T) {
	underlying, peer := net.Pipe()
	defer underlying.Close()
	defer peer.Close()
	inner := &unwrapConn{Conn: underlying, next: underlying}
	outer := &CounterConnection{Connection: &unwrapConn{Conn: inner, next: inner}}
	if got := TryUnwrapStatsConn(outer); got != underlying {
		t.Fatalf("got %T, want underlying connection", got)
	}
}

func TestTryUnwrapStatsConnStopsOnSelfCycle(t *testing.T) {
	cycle := new(unwrapConn)
	cycle.Conn = cycle
	cycle.next = cycle
	result := make(chan net.Conn, 1)
	go func() { result <- TryUnwrapStatsConn(cycle) }()
	select {
	case got := <-result:
		if got != cycle {
			t.Fatalf("got %T, want cycle boundary", got)
		}
	case <-time.After(time.Second):
		t.Fatal("self-cycle did not terminate")
	}
}

func TestTryUnwrapStatsConnStopsOnTwoNodeCycle(t *testing.T) {
	first := new(unwrapConn)
	second := new(unwrapConn)
	first.Conn, first.next = second, second
	second.Conn, second.next = first, first
	if got := TryUnwrapStatsConn(first); got != first {
		t.Fatalf("got %T, want repeated cycle boundary", got)
	}
}

func TestTryUnwrapStatsConnFailsClosedForUncomparableWrapper(t *testing.T) {
	underlying, peer := net.Pipe()
	defer underlying.Close()
	defer peer.Close()
	wrapper := uncomparableConn{Conn: underlying, bytes: []byte{1}}
	if got := TryUnwrapStatsConn(wrapper); got == underlying {
		t.Fatal("uncomparable wrapper was traversed without a cycle identity")
	}
}
