package masque

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/http2"
)

// Handshake with the actual constructor and readLoop. Only the automatic
// keepAlive launch is disabled so each test can start it at fake t=0.
func newPR7121H2Conn(t *testing.T, wrap func(net.Conn) net.Conn) (*http2ClientConn, net.Conn, *http2.Framer) {
	t.Helper()
	cli, srv := net.Pipe()
	if wrap != nil {
		cli = wrap(cli)
	}
	type result struct {
		cc  *http2ClientConn
		err error
	}
	ready := make(chan result, 1)
	go func() {
		cc, err := newHTTP2ClientConn(cli, 0)
		ready <- result{cc, err}
	}()
	peer := http2.NewFramer(srv, srv)
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(srv, preface); err != nil {
		t.Fatal(err)
	}
	if string(preface) != http2.ClientPreface {
		t.Fatalf("preface = %q", preface)
	}
	f, err := peer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.(*http2.SettingsFrame); !ok {
		t.Fatalf("first frame = %T", f)
	}
	f, err = peer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.(*http2.WindowUpdateFrame); !ok {
		t.Fatalf("second frame = %T", f)
	}
	got := <-ready
	if got.err != nil {
		t.Fatal(got.err)
	}
	if err := peer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	f, err = peer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := f.(*http2.SettingsFrame)
	if !ok || !settings.IsAck() {
		t.Fatalf("settings reply = %T", f)
	}
	return got.cc, srv, peer
}

func startPR7121H2KeepAlive(cc *http2ClientConn, period time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		cc.keepAlive(period)
	}()
	return done
}

func TestPR7121H2KeepAliveActual(t *testing.T) {
	for _, tc := range []struct {
		name          string
		period, phase time.Duration
		wantPing      time.Duration
	}{
		{"60s_phase2_ping_ack", 60 * time.Second, 2 * time.Second, 80 * time.Second},
		{"45s_phase2_ping_ack_control", 45 * time.Second, 2 * time.Second, 60 * time.Second},
		{"60s_phase0_ping_ack_control", 60 * time.Second, 0, 60 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				cc, srv, peer := newPR7121H2Conn(t, nil)
				if !time.Now().Equal(start) {
					t.Fatal("handshake advanced fake time")
				}
				var pings, acks, firstPing atomic.Int64
				keepDone := startPR7121H2KeepAlive(cc, tc.period)
				go func() {
					if tc.phase > 0 {
						time.Sleep(tc.phase)
						if err := peer.WriteWindowUpdate(0, 1); err != nil {
							t.Errorf("phase frame: %v", err)
							return
						}
					}
					for {
						f, err := peer.ReadFrame()
						if err != nil {
							return
						}
						p, ok := f.(*http2.PingFrame)
						if !ok || p.IsAck() {
							t.Errorf("unexpected frame %T", f)
							return
						}
						if pings.Add(1) == 1 {
							firstPing.Store(time.Since(start).Nanoseconds())
						}
						if err := peer.WritePing(true, p.Data); err != nil {
							t.Errorf("PING ACK: %v", err)
							return
						}
						acks.Add(1)
					}
				}()
				defer func() { cc.Close(); srv.Close(); synctest.Wait(); <-keepDone }()
				synctest.Wait()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if cc.lastFrame.Load() != start.Add(tc.phase).UnixNano() {
					t.Fatalf("lastFrame = %v, want fake t=%v", time.Unix(0, cc.lastFrame.Load()), tc.phase)
				}
				for _, at := range []time.Duration{20 * time.Second, 40 * time.Second, 60 * time.Second, 80*time.Second - time.Nanosecond, 80 * time.Second} {
					time.Sleep(at - time.Since(start))
					synctest.Wait()
					if err := cc.connErr(); err != nil {
						t.Fatalf("at %v: premature error %v", at, err)
					}
					if at < tc.wantPing && pings.Load() != 0 {
						t.Fatalf("at %v: premature PING count %d", at, pings.Load())
					}
				}
				if pings.Load() != 1 || acks.Load() != 1 {
					t.Fatalf("PING/ACK = %d/%d, want 1/1", pings.Load(), acks.Load())
				}
				if firstPing.Load() != int64(tc.wantPing) {
					t.Fatalf("first PING at %v, want %v", time.Duration(firstPing.Load()), tc.wantPing)
				}
				if cc.lastFrame.Load() != start.Add(tc.wantPing).UnixNano() {
					t.Fatal("real PING ACK did not update lastFrame")
				}
			})
		})
	}
}

func TestPR7121H2KeepAliveSilentPeer(t *testing.T) {
	for _, delay := range []time.Duration{0, 10 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				cc, srv, peer := newPR7121H2Conn(t, nil)
				keepDone := startPR7121H2KeepAlive(cc, 60*time.Second)
				defer func() { cc.Close(); srv.Close(); synctest.Wait(); <-keepDone }()
				sent := make(chan time.Duration, 1)
				go func() {
					time.Sleep(2 * time.Second)
					if err := peer.WriteWindowUpdate(0, 1); err != nil {
						t.Errorf("phase frame: %v", err)
						return
					}
					// No read before this point: net.Pipe keeps the actual flush
					// blocked, even though the PING write starts at fake t=80s.
					time.Sleep(80*time.Second + delay - time.Since(start))
					f, err := peer.ReadFrame()
					if err != nil {
						t.Errorf("PING read: %v", err)
						return
					}
					p, ok := f.(*http2.PingFrame)
					if !ok || p.IsAck() {
						t.Errorf("unexpected frame %T", f)
						return
					}
					sent <- time.Since(start)
				}()
				synctest.Wait()
				wantSent := 80*time.Second + delay
				time.Sleep(wantSent)
				synctest.Wait()
				select {
				case at := <-sent:
					if at != wantSent {
						t.Fatalf("PING at %v, want %v", at, wantSent)
					}
				default:
					t.Fatal("PING did not physically complete")
				}
				time.Sleep(http2PingTimeout - time.Nanosecond)
				synctest.Wait()
				if err := cc.connErr(); err != nil {
					t.Fatalf("closed before full receive window: %v", err)
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if !errors.Is(cc.connErr(), errHTTP2IdleTimeout) {
					t.Fatalf("after 15s receive window: %v", cc.connErr())
				}
				select {
				case <-cc.done:
				default:
					t.Fatal("timed-out readLoop remains open")
				}
			})
		})
	}
}

type pr7121H2WriteConn struct {
	net.Conn
	pingWrites atomic.Int64
	finished   chan struct{}
	release    chan struct{}
	writeErr   error
}

func (c *pr7121H2WriteConn) Write(p []byte) (int, error) {
	// HTTP/2 frame type is byte 3 of its nine-byte header. Handshake
	// SETTINGS/WINDOW_UPDATE writes pass through unchanged.
	if len(p) >= 9 && p[3] == byte(http2.FramePing) {
		c.pingWrites.Add(1)
		defer close(c.finished)
		if c.writeErr != nil {
			return 0, c.writeErr
		}
		n, err := c.Conn.Write(p)
		if c.release != nil && err == nil {
			<-c.release
		}
		return n, err
	}
	return c.Conn.Write(p)
}

func TestPR7121H2KeepAliveStalledWrite(t *testing.T) {
	for _, closeEarly := range []bool{false, true} {
		name := "write_timeout"
		if closeEarly {
			name = "close_during_write"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var tracked *pr7121H2WriteConn
				cc, srv, _ := newPR7121H2Conn(t, func(c net.Conn) net.Conn {
					tracked = &pr7121H2WriteConn{Conn: c, finished: make(chan struct{})}
					return tracked
				})
				keepDone := startPR7121H2KeepAlive(cc, 60*time.Second)
				defer func() { cc.Close(); srv.Close(); synctest.Wait(); <-keepDone }()
				synctest.Wait()
				time.Sleep(60 * time.Second)
				synctest.Wait()
				if tracked.pingWrites.Load() != 1 {
					t.Fatalf("pending PING writes = %d, want 1", tracked.pingWrites.Load())
				}
				select {
				case <-tracked.finished:
					t.Fatal("PING write unexpectedly completed without peer reading")
				default:
				}
				wantErr := errHTTP2IdleTimeout
				if closeEarly {
					cc.Close()
					wantErr = net.ErrClosed
				} else {
					time.Sleep(http2PingTimeout - time.Nanosecond)
					synctest.Wait()
					if err := cc.connErr(); err != nil {
						t.Fatalf("premature write timeout: %v", err)
					}
					time.Sleep(time.Nanosecond)
				}
				synctest.Wait()
				if !errors.Is(cc.connErr(), wantErr) {
					t.Fatalf("error = %v, want %v", cc.connErr(), wantErr)
				}
				select {
				case <-tracked.finished:
				default:
					t.Fatal("PING writer did not exit after connection close")
				}
				select {
				case <-keepDone:
				default:
					t.Fatal("keepAlive did not exit after connection close")
				}
				if tracked.pingWrites.Load() != 1 {
					t.Fatal("more than one pending PING write")
				}
			})
		})
	}
}

func TestPR7121H2KeepAliveActivityBeforeWriteResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tracked *pr7121H2WriteConn
		cc, srv, peer := newPR7121H2Conn(t, func(c net.Conn) net.Conn {
			tracked = &pr7121H2WriteConn{Conn: c, finished: make(chan struct{}), release: make(chan struct{})}
			return tracked
		})
		keepDone := startPR7121H2KeepAlive(cc, 60*time.Second)
		defer func() { cc.Close(); srv.Close(); synctest.Wait(); <-keepDone }()
		go func() {
			f, err := peer.ReadFrame()
			if err != nil {
				t.Errorf("PING read: %v", err)
				return
			}
			if p, ok := f.(*http2.PingFrame); !ok || p.IsAck() {
				t.Errorf("unexpected frame %T", f)
				return
			}
			// A non-ACK frame remains valid liveness evidence, including
			// while the successful Write result is still delayed.
			if err := peer.WriteWindowUpdate(0, 1); err != nil {
				t.Errorf("activity: %v", err)
			}
		}()
		synctest.Wait()
		time.Sleep(60 * time.Second)
		synctest.Wait()
		lastFrame := cc.lastFrame.Load()
		if lastFrame != time.Now().UnixNano() {
			t.Fatal("real incoming activity did not update lastFrame")
		}
		time.Sleep(10 * time.Second)
		close(tracked.release)
		synctest.Wait()
		time.Sleep(http2PingTimeout + time.Second)
		synctest.Wait()
		if err := cc.connErr(); err != nil {
			t.Fatalf("late write result discarded prior activity: %v", err)
		}
		if tracked.pingWrites.Load() != 1 {
			t.Fatal("late completion created another pending PING")
		}
	})
}

func TestPR7121H2KeepAliveWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writeErr := errors.New("test PING write failure")
		cc, srv, _ := newPR7121H2Conn(t, func(c net.Conn) net.Conn {
			return &pr7121H2WriteConn{Conn: c, finished: make(chan struct{}), writeErr: writeErr}
		})
		keepDone := startPR7121H2KeepAlive(cc, 60*time.Second)
		defer func() { cc.Close(); srv.Close(); synctest.Wait(); <-keepDone }()
		synctest.Wait()
		time.Sleep(60 * time.Second)
		synctest.Wait()
		if !errors.Is(cc.connErr(), writeErr) {
			t.Fatalf("write failure = %v, want %v", cc.connErr(), writeErr)
		}
	})
}

func TestPR7121H2KeepAliveDelayedACKCadence(t *testing.T) {
	for _, period := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second} {
		t.Run(period.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				cc, srv, peer := newPR7121H2Conn(t, nil)
				keepDone := startPR7121H2KeepAlive(cc, period)
				defer func() { cc.Close(); srv.Close(); synctest.Wait(); <-keepDone }()
				var pings atomic.Int64
				var secondPing atomic.Int64
				go func() {
					for i := 0; i < 2; i++ {
						f, err := peer.ReadFrame()
						if err != nil {
							t.Errorf("PING read: %v", err)
							return
						}
						p, ok := f.(*http2.PingFrame)
						if !ok || p.IsAck() {
							t.Errorf("unexpected frame %T", f)
							return
						}
						if pings.Add(1) == 2 {
							secondPing.Store(time.Since(start).Nanoseconds())
						}
						// The result from the physical write must be handled
						// before this ACK, opening the receive-timeout state.
						time.Sleep(100 * time.Millisecond)
						if err := peer.WritePing(true, p.Data); err != nil {
							t.Errorf("PING ACK: %v", err)
							return
						}
					}
				}()
				synctest.Wait()
				time.Sleep(period)
				synctest.Wait()
				if pings.Load() != 1 {
					t.Fatalf("first PING count = %d, want 1", pings.Load())
				}
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				if cc.lastFrame.Load() != time.Now().UnixNano() {
					t.Fatal("delayed ACK was not consumed by real readLoop")
				}
				wantSecond := 2*period + time.Second
				time.Sleep(wantSecond - time.Since(start) - time.Nanosecond)
				synctest.Wait()
				if pings.Load() != 1 {
					t.Fatal("second PING sent before its normal ticker deadline")
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if pings.Load() != 2 || time.Duration(secondPing.Load()) != wantSecond {
					t.Fatalf("PING count/time = %d/%v, want 2/%v", pings.Load(), time.Duration(secondPing.Load()), wantSecond)
				}
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				if err := cc.connErr(); err != nil {
					t.Fatalf("delayed ACK cadence: %v", err)
				}
			})
		})
	}
}

func TestPR7121H2KeepAliveStalledWriteFrameActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		var tracked *pr7121H2WriteConn
		cc, srv, peer := newPR7121H2Conn(t, func(c net.Conn) net.Conn {
			tracked = &pr7121H2WriteConn{Conn: c, finished: make(chan struct{})}
			return tracked
		})
		keepDone := startPR7121H2KeepAlive(cc, 60*time.Second)
		stopActivity := make(chan struct{})
		activityDone := make(chan struct{})
		defer func() {
			close(stopActivity)
			cc.Close()
			srv.Close()
			synctest.Wait()
			<-activityDone
			<-keepDone
		}()
		go func() {
			defer close(activityDone)
			// Do not read the outgoing PING. Valid incoming frames continue
			// every 20s, longer than 15s but shorter than the old 75s allowance.
			for _, at := range []time.Duration{62 * time.Second, 82 * time.Second, 102 * time.Second, 122 * time.Second} {
				wait := time.NewTimer(at - time.Since(start))
				select {
				case <-stopActivity:
					wait.Stop()
					return
				case <-wait.C:
				}
				if err := peer.WriteWindowUpdate(0, 1); err != nil {
					select {
					case <-stopActivity:
						return
					default:
					}
					t.Errorf("frame at %v: %v", at, err)
					return
				}
			}
		}()
		synctest.Wait()
		for _, at := range []time.Duration{60 * time.Second, 75 * time.Second, 95 * time.Second, 115 * time.Second, 135 * time.Second, 155 * time.Second, 175 * time.Second, 197*time.Second - time.Nanosecond} {
			time.Sleep(at - time.Since(start))
			synctest.Wait()
			if err := cc.connErr(); err != nil {
				t.Fatalf("at %v: frame-active pending write closed early: %v", at, err)
			}
			if tracked.pingWrites.Load() != 1 {
				t.Fatalf("at %v: pending PING writes = %d, want 1", at, tracked.pingWrites.Load())
			}
		}
		if cc.lastFrame.Load() != start.Add(122*time.Second).UnixNano() {
			t.Fatal("real readLoop did not consume the final activity frame")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if !errors.Is(cc.connErr(), errHTTP2IdleTimeout) {
			t.Fatalf("after activity ceased for period+15s: %v", cc.connErr())
		}
		select {
		case <-tracked.finished:
		default:
			t.Fatal("stalled writer did not exit after frame-idle timeout")
		}
		select {
		case <-keepDone:
		default:
			t.Fatal("keepAlive did not exit after frame-idle timeout")
		}
	})
}
