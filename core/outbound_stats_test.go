package core_test

import (
	"bytes"
	"errors"
	"fmt"
	stdnet "net"
	"testing"

	commonnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func startOutboundStatsTCPServer(t *testing.T) commonnet.Destination {
	t.Helper()

	server := &tcp.Server{MsgProcessor: transformOutboundStatsTCPPayload}
	destination, err := server.Start()
	if err != nil {
		t.Fatalf("start loopback TCP server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close loopback TCP server: %v", err)
		}
	})
	return destination
}

func startOutboundStatsUDPServer(t *testing.T, mask byte) commonnet.Destination {
	t.Helper()

	conn, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("start loopback UDP server: %v", err)
	}
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		defer close(done)
		defer close(errCh)
		buffer := make([]byte, 64*1024)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if !errors.Is(err, stdnet.ErrClosed) {
					errCh <- fmt.Errorf("read loopback UDP packet: %w", err)
				}
				return
			}
			response := transformOutboundStatsPayload(buffer[:n], mask)
			if _, err := conn.WriteToUDP(response, source); err != nil {
				if !errors.Is(err, stdnet.ErrClosed) {
					errCh <- fmt.Errorf("write loopback UDP packet: %w", err)
				}
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, stdnet.ErrClosed) {
			t.Errorf("close loopback UDP server: %v", err)
		}
		<-done
		if err, ok := <-errCh; ok {
			t.Error(err)
		}
	})

	local := conn.LocalAddr().(*stdnet.UDPAddr)
	return commonnet.UDPDestination(commonnet.IPAddress(local.IP), commonnet.Port(local.Port))
}

func transformOutboundStatsTCPPayload(payload []byte) []byte {
	return transformOutboundStatsPayload(payload, 0x5a)
}

func transformOutboundStatsPayload(payload []byte, mask byte) []byte {
	response := bytes.Clone(payload)
	for i := range response {
		response[i] ^= mask
	}
	return response
}
