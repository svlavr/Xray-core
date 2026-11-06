package splithttp

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type refreshCountingListener struct {
	net.Listener
	closes atomic.Int32
}

func (l *refreshCountingListener) Close() error {
	l.closes.Add(1)
	return l.Listener.Close()
}

func TestRefreshH2ParamsConstructionCustody(t *testing.T) {
	for _, tc := range []struct {
		name      string
		params    []byte
		wantError bool
	}{
		{"array", []byte("[]"), true},
		{"wrong-field-type", []byte("{\"MaxConcurrentStreams\":\"bad\"}"), true},
		{"absent", nil, false},
		{"valid", []byte("{\"MaxConcurrentStreams\":8}"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var acquired *refreshCountingListener
			mask := finalmask.NewFinalMask(nil, nil, nil, func(context.Context, net.Addr) (net.Listener, error) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				acquired = &refreshCountingListener{Listener: ln}
				return acquired, nil
			}, nil, nil)
			t.Cleanup(func() {
				if acquired != nil {
					_ = acquired.Listener.Close()
				}
			})
			stream := &internet.MemoryStreamConfig{ProtocolSettings: &Config{Path: "/", H2Params: tc.params}, FinalMask: mask}
			listener, err := ListenXH(context.Background(), xnet.LocalHostIP, xnet.Port(1), stream, nil)
			if tc.wantError {
				if err == nil || listener != nil {
					t.Fatalf("invalid parameters accepted: listener=%v err=%v", listener, err)
				}
				if acquired != nil && acquired.closes.Load() != 1 {
					t.Fatalf("failed construction lost listener custody: closes=%d", acquired.closes.Load())
				}
				return
			}
			if err != nil || listener == nil {
				t.Fatalf("valid constructor: %v", err)
			}
			if acquired == nil || acquired.closes.Load() != 0 {
				t.Fatal("successful listener closed before transfer")
			}
			_ = listener.Close()
			if acquired.closes.Load() == 0 {
				t.Fatal("caller close did not reach listener")
			}
		})
	}
}
