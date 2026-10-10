package xdns

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type directSendSocket struct {
	*shutdownSocket
	writes  atomic.Int32
	block   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *directSendSocket) Write(p []byte) (int, error) {
	if s.block.Load() {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	select {
	case <-s.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	s.writes.Add(1)
	return len(p), nil
}

func (s *directSendSocket) WriteTo(p []byte, _ net.Addr) (int, error) { return s.Write(p) }

func TestXDNSDirectSendAndConcurrentClose(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			s := &directSendSocket{shutdownSocket: &shutdownSocket{started: make(chan struct{}), closed: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			unblock := func() { release.Do(func() { close(s.release) }) }
			t.Cleanup(unblock)
			t.Cleanup(func() { s.Close() })
			dialer := &finalmask.Dialer{}
			resolver := &ResolverProto{Addr: "127.0.0.1:53"}
			if tcp {
				resolver.Type = "tcp"
				s.addr = &net.TCPAddr{IP: net.LocalHostIP.IP(), Port: 53}
				dialer.DialTCP = func(net.Destination) (net.Conn, error) { return s, nil }
			} else {
				resolver.Type = "udp"
				s.addr = &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: 53}
				dialer.DialUDP = func(net.Destination) (net.Conn, error) {
					return &net.PacketConnWrapper{PacketConn: s, Dest: s.addr}, nil
				}
			}
			client, err := NewClient(&Config{Domains: []*DomainProto{{Name: "example.com", LenLimit: 200, LabelLimit: 63}}, Resolvers: []*ResolverProto{resolver}, ExtraPoll: 2}, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { unblock(); client.Close() })
			payload := []byte("direct payload")
			for range 2 {
				before := s.writes.Load()
				if n, err := client.WriteTo(payload, s.addr); err != nil || n != len(payload) {
					t.Fatalf("send: %d %v", n, err)
				}
				if s.writes.Load()-before < 3 {
					t.Fatal("WriteTo returned before data and extra polls reached resolver")
				}
			}
			s.block.Store(true)
			writeDone := make(chan error, 1)
			go func() { _, err := client.WriteTo(payload, s.addr); writeDone <- err }()
			select {
			case <-s.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("send did not reach blocked resolver")
			}
			select {
			case <-writeDone:
				t.Fatal("WriteTo detached a still-blocked send")
			default:
			}
			closeDone := make(chan error, 1)
			go func() { closeDone <- client.Close() }()
			// Close retains the native lower-write dependency. Once it returns,
			// both operations must complete and subsequent writes must be rejected.
			unblock()
			for _, done := range []<-chan error{writeDone, closeDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("send/close did not finish after lower write returned")
				}
			}
			before := s.writes.Load()
			if n, err := client.WriteTo(payload, s.addr); n != 0 || err != io.ErrClosedPipe || s.writes.Load() != before {
				t.Fatalf("post-close send: %d %v", n, err)
			}
		})
	}
}

func TestXDNSFragmentBoundsAfterUploadRefinement(t *testing.T) {
	m := NewFragManager()
	defer m.Close()
	out := make([]byte, fragSize)
	data := make([]byte, fragSize/2)
	clientID := ClientID{1}
	// One client can retain more than the former 16 KiB total, but each
	// reassembly remains bounded and a completed entry is immediately retired.
	for i := range 9 {
		key := FragKey{clientID: clientID, fragID: byte(i)}
		if n := m.Feed(out, key, 0, 2, data); n != 0 {
			t.Fatal("incomplete fragment was emitted")
		}
	}
	m.mu.Lock()
	retainedBytes := 0
	for _, entry := range m.m {
		retainedBytes += entry.size
	}
	retainedEntries := len(m.m)
	m.mu.Unlock()
	if retainedEntries != 9 || retainedBytes != 9*len(data) {
		t.Fatalf("same-client fragments: %d entries, %d bytes", retainedEntries, retainedBytes)
	}
	key := FragKey{clientID: clientID}
	if n := m.Feed(out, key, 1, 2, make([]byte, fragSize)); n != 0 {
		t.Fatal("oversized reassembly accepted")
	}
	if n := m.Feed(out, key, 1, 2, data); n != fragSize {
		t.Fatalf("bounded reassembly lost: %d", n)
	}
	expiredKey := FragKey{clientID: clientID, fragID: 1}
	m.mu.Lock()
	m.m[expiredKey].deadline = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if n := m.Feed(out, expiredKey, 1, 2, data); n != 0 {
		t.Fatal("expired prefix was reused")
	}
	if n := m.Feed(out, expiredKey, 0, 2, data); n != fragSize {
		t.Fatal("new fragments did not replace expired entry")
	}
	// Pin distinct deadlines to test eviction without relying on sleeps.
	m.mu.Lock()
	clear(m.m)
	oldest := FragKey{clientID: ClientID{255}, fragID: 255}
	m.m[oldest] = &FragEntry{deadline: time.Now().Add(time.Second)}
	for i := 1; i < fragCount; i++ {
		k := FragKey{clientID: ClientID{byte(i), byte(i >> 8)}}
		m.m[k] = &FragEntry{deadline: time.Now().Add(fragTTL)}
	}
	m.mu.Unlock()
	newKey := FragKey{clientID: ClientID{254, 254}}
	m.Feed(out, newKey, 0, 2, data)
	m.mu.Lock()
	_, retained := m.m[oldest]
	count := len(m.m)
	m.mu.Unlock()
	if retained || count != fragCount {
		t.Fatalf("global eviction: retained=%v count=%d", retained, count)
	}
	m.Close()
	m.mu.Lock()
	count = len(m.m)
	m.mu.Unlock()
	if count != 0 || m.Feed(out, newKey, 1, 2, data) != 0 {
		t.Fatal("closed fragment manager retained or accepted data")
	}
}
