package shadowsocks_2022

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/session"
)

type packetCodecHandler struct {
	run  func(N.PacketConn) error
	done chan error
}

func (h *packetCodecHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return errors.New("unexpected TCP")
}
func (h *packetCodecHandler) NewError(context.Context, error) {}
func (h *packetCodecHandler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	err := h.run(c)
	h.done <- err
	return err
}

func TestInspectionSS2022PacketCodecResults(t *testing.T) {
	for _, methodName := range shadowaead_2022.List {
		for _, outcome := range []string{"complete", "zero-error", "partial-error", "complete-error", "short-nil"} {
			t.Run(methodName+"/"+outcome, func(t *testing.T) {
				key := "MDEyMzQ1Njc4OWFiY2RlZg=="
				if methodName != "2022-blake3-aes-128-gcm" {
					key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
				}
				method, err := shadowaead_2022.NewWithPassword(methodName, key, nil)
				if err != nil {
					t.Fatal(err)
				}
				var wire []byte
				client := method.DialPacketConn(&inspectionTestConn{write: func(p []byte) (int, error) { wire = bytes.Clone(p); return len(p), nil }})
				destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
				if _, err := client.WriteTo([]byte("request"), destination); err != nil {
					t.Fatal(err)
				}
				failure := errors.New("lower failure")
				transport := &inspectionTestConn{write: func(p []byte) (int, error) {
					switch outcome {
					case "zero-error":
						return 0, failure
					case "partial-error":
						return 1, failure
					case "complete-error":
						return len(p), failure
					case "short-nil":
						return 1, nil
					default:
						return len(p), nil
					}
				}}
				flow, view := inspectionFlow(t, nil)
				var access sync.Mutex
				handler := &packetCodecHandler{done: make(chan error, 1)}
				handler.run = func(conn N.PacketConn) error {
					observed := &inspectionPacketConn{PacketConn: conn, receipt: flow, writeAccess: &access}
					waiter := &inspectionPacketWaiter{inspectionPacketConn: observed, waiter: conn.(N.PacketReadWaiter)}
					if N.UnwrapPacketReader(waiter) != waiter || N.UnwrapPacketWriter(waiter) != waiter {
						return errors.New("receipt was unwrapped")
					}
					if N.CalculateFrontHeadroom(waiter) != N.CalculateFrontHeadroom(conn) || N.CalculateRearHeadroom(waiter) != N.CalculateRearHeadroom(conn) {
						return errors.New("codec headroom lost")
					}
					if waiter.InitializeReadWaiter(N.ReadWaitOptions{}) {
						return errors.New("native waiter requested extra copy")
					}
					packet, addr, err := waiter.WaitReadPacket()
					if err != nil {
						return err
					}
					if string(packet.Bytes()) != "request" || addr.String() != destination.String() {
						packet.Release()
						return errors.New("decoded request mismatch")
					}
					packet.Release()
					options := N.ReadWaitOptions{FrontHeadroom: N.CalculateFrontHeadroom(waiter), RearHeadroom: N.CalculateRearHeadroom(waiter)}
					response := options.NewPacketBuffer()
					response.Write([]byte("response"))
					options.PostReturn(response)
					err = waiter.WritePacket(response, addr)
					if outcome == "complete" {
						if err != nil {
							return err
						}
					} else if outcome == "short-nil" {
						if !errors.Is(err, io.ErrShortWrite) {
							return fmt.Errorf("short result: %w", err)
						}
					} else if !errors.Is(err, failure) {
						return fmt.Errorf("error result: %w", err)
					}
					if response.Bytes() != nil {
						return errors.New("response buffer retained")
					}
					return nil
				}
				service, err := shadowaead_2022.NewServiceWithPassword(methodName, key, 500, handler, nil)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if err := service.NewPacket(ctx, &natPacketConn{transport}, B.As(wire).ToOwned(), M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:1234")}); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-handler.done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("codec callback stuck")
				}
				row := inspectionLive(t, view)
				known := uint64(0)
				incomplete := false
				switch outcome {
				case "complete":
					known = 8
				default:
					incomplete = true
				}
				if row.Uplink.Known != 7 || row.Downlink.Known != known || row.Downlink.Incomplete != incomplete {
					t.Fatalf("packet result: %+v", row)
				}
			})
		}
	}
}

func TestSS2022PacketMetadataIsolation(t *testing.T) {
	base := session.ContextWithInbound(context.Background(), &session.Inbound{Name: "parent"})
	base = session.ContextWithOutbounds(base, []*session.Outbound{{Tag: "parent"}})
	base = session.ContextWithContent(base, &session.Content{Attributes: map[string]string{"test": "parent"}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := packetSessionContext(base)
			session.InboundFromContext(ctx).Name = "child"
			session.OutboundsFromContext(ctx)[0].Tag = "child"
			session.ContentFromContext(ctx).Attributes["test"] = "child"
		}()
	}
	wg.Wait()
	if session.InboundFromContext(base).Name != "parent" || session.OutboundsFromContext(base)[0].Tag != "parent" || session.ContentFromContext(base).Attributes["test"] != "parent" {
		t.Fatal("shared packet metadata mutated")
	}
}
