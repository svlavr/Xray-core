package shadowsocks_2022

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat"
)

type inspectionNATHandler struct {
	opened      chan N.PacketConn
	retire      chan struct{}
	oldReturned chan struct{}
	starts      atomic.Int32
	workers     sync.WaitGroup
	waiter      bool
}

func (h *inspectionNATHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, _ M.Metadata) error {
	h.workers.Add(1)
	defer h.workers.Done()
	index := h.starts.Add(1)
	if h.waiter {
		conn.(N.PacketReadWaiter).InitializeReadWaiter(N.ReadWaitOptions{})
	}
	if _, err := readInspectionNATPacket(conn, h.waiter); err != nil {
		return err
	}
	h.opened <- conn
	if index == 1 {
		select {
		case <-h.retire:
		case <-ctx.Done():
		}
		close(h.oldReturned)
	} else {
		<-ctx.Done()
	}
	return nil
}

func (*inspectionNATHandler) NewError(context.Context, error) {}

type inspectionNATWriter struct{}

func (inspectionNATWriter) WritePacket(packet *B.Buffer, _ M.Socksaddr) error {
	packet.Release()
	return nil
}

func TestInspectionSS2022NATRetiredSessionKeepsReplacement(t *testing.T) {
	for _, waiter := range []bool{false, true} {
		t.Run(map[bool]string{false: "ReadPacket", true: "WaitReadPacket"}[waiter], func(t *testing.T) {
			inspectionNATReplacement(t, waiter)
		})
	}
}

func readInspectionNATPacket(conn N.PacketConn, waiter bool) (string, error) {
	if waiter {
		packet, _, err := conn.(N.PacketReadWaiter).WaitReadPacket()
		if packet == nil {
			return "", err
		}
		defer packet.Release()
		return string(packet.Bytes()), err
	}
	packet := B.NewSize(64)
	defer packet.Release()
	_, err := conn.ReadPacket(packet)
	return string(packet.Bytes()), err
}

func inspectionNATReplacement(t *testing.T, waiter bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	handler := &inspectionNATHandler{opened: make(chan N.PacketConn, 4), retire: make(chan struct{}), oldReturned: make(chan struct{}), waiter: waiter}
	t.Cleanup(func() { cancel(); handler.workers.Wait() })
	native := udpnat.New[uint64](60, handler)
	metadata := M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:40000"), Destination: M.ParseSocksaddr("127.0.0.1:40001")}
	send := func(payload string) {
		native.NewPacket(ctx, 42, B.As([]byte(payload)).ToOwned(), metadata, func(N.PacketConn) N.PacketWriter { return inspectionNATWriter{} })
	}
	await := func() N.PacketConn {
		t.Helper()
		select {
		case conn := <-handler.opened:
			return conn
		case <-time.After(3 * time.Second):
			t.Fatal("native association did not start")
			return nil
		}
	}
	send("first")
	old := await()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	send("replacement")
	replacement := await()
	if replacement == old {
		t.Fatal("closed native object was reused")
	}
	close(handler.retire)
	<-handler.oldReturned
	if err := replacement.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := readInspectionNATPacket(replacement, waiter)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("old callback closed the live replacement: %v", err)
	}
	if err := replacement.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	send("still-routed-to-replacement")
	if packet, err := readInspectionNATPacket(replacement, waiter); err != nil || packet != "still-routed-to-replacement" || handler.starts.Load() != 2 {
		t.Fatalf("replacement lost after retirement: packet=%q starts=%d err=%v", packet, handler.starts.Load(), err)
	}
}
