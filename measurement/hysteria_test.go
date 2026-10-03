package measurement_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/measurement"
	hyproxy "github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func hysteriaExecutor(t *testing.T) (*measurement.Executor, *core.Instance) {
	t.Helper()
	certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	stream := func(server bool) *internet.StreamConfig {
		security := &xtls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{hash[:]}, NextProtocol: []string{"h3"}}
		if server {
			security.Certificate = []*xtls.Certificate{xtls.ParseCertificate(certificate)}
		}
		return &internet.StreamConfig{
			ProtocolName:      "hysteria",
			TransportSettings: []*internet.TransportConfig{{ProtocolName: "hysteria", Settings: serial.ToTypedMessage(&hytransport.Config{Auth: "fixture", UdpIdleTimeout: 60})}},
			SecurityType:      serial.GetMessageType(security), SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(security)},
			QuicParams: &internet.QuicParams{DisableChromeParrot: true, Congestion: "reno"},
		}
	}
	port := udp.PickPort()
	peer, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}, StreamSettings: stream(true)}), ProxySettings: serial.ToTypedMessage(&hyproxy.ServerConfig{Users: []*protocol.User{{Account: serial.ToTypedMessage(&hyaccount.Account{Auth: "fixture"})}}})}},
		Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	v := instance(t)
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	if err := core.AddOutboundHandler(v, &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: stream(false)}), ProxySettings: serial.ToTypedMessage(&hyproxy.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port)}})}); err != nil {
		t.Fatal(err)
	}
	return executor(t, v), v
}

func TestHysteriaMeasurementSeriesAndUDPCancellation(t *testing.T) {
	e, v := hysteriaExecutor(t)
	testProtocolMeasurements(t, e, v)
}

func TestNativeProtocolMeasurements(t *testing.T) {
	for _, profile := range []string{"vless", "trojan", ss.MethodAES128GCM, ss.MethodAES256GCM, ss.MethodChaCha20Poly1305} {
		t.Run(profile, func(t *testing.T) {
			if profile == "vless" {
				e, v, _ := udpVLESSExecutor(t)
				testProtocolMeasurements(t, e, v)
				return
			}
			e, v := plainProtocolExecutor(t, profile)
			testProtocolMeasurements(t, e, v)
		})
	}
}

func plainProtocolExecutor(t *testing.T, profile string) (*measurement.Executor, *core.Instance) {
	t.Helper()
	port := tcp.PickPort()
	if profile != "trojan" {
		port = udp.PickPort()
	}
	var inbound, client *serial.TypedMessage
	if profile == "trojan" {
		account := serial.ToTypedMessage(&trojan.Account{Password: "fixture"})
		inbound = serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{{Account: account}}})
		client = serial.ToTypedMessage(&trojan.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: account}}})
	} else {
		keySize := 32
		if profile == ss.MethodAES128GCM {
			keySize = 16
		}
		key := base64.StdEncoding.EncodeToString(make([]byte, keySize)) // Local fixture only.
		inbound = serial.ToTypedMessage(&ss.ServerConfig{Method: profile, Key: key, Network: []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}})
		client = serial.ToTypedMessage(&ss.ClientConfig{Method: profile, Key: key, Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port)})
	}
	peer, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}}), ProxySettings: inbound}},
		Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Start(); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	v := instance(t)
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"exact", "second"} {
		if err := core.AddOutboundHandler(v, &core.OutboundHandlerConfig{Tag: tag, SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: client}); err != nil {
			t.Fatal(err)
		}
	}
	return executor(t, v), v
}

func testProtocolMeasurements(t *testing.T, e *measurement.Executor, v *core.Instance) {
	t.Helper()
	secondWritten := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload":
			acknowledge(w, r)
		case "/partial":
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "prefix")
		case "/identity":
			_, _ = io.WriteString(w, `{"ip":"192.0.2.1"}`)
		case "/attempt":
			index := r.URL.Query().Get("index")
			if index == "0" {
				select {
				case <-secondWritten:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("X-Attempt", index)
			if index == "1" {
				w.Header().Set("Content-Length", "100")
			}
			_, _ = io.WriteString(w, "attempt-"+index)
			if index == "2" {
				w.(http.Flusher).Flush()
				close(secondWritten)
			}
		default:
			_, _ = io.WriteString(w, "fixture")
		}
	}))
	defer s.Close()
	samples, err := measurement.RunSeries(context.Background(), e, 6, 3, func(ctx context.Context, index int) (measurement.HTTPSReceipt, error) {
		r := request(s, measurement.ExactOutbound)
		r.URL += fmt.Sprintf("/attempt?index=%d", index)
		if index%2 == 1 && v.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("second") != nil {
			r.Route.Tag = "second"
		}
		return e.HTTPS(ctx, r)
	})
	if err != nil || len(samples) != 6 {
		t.Fatalf("series: %d, %v", len(samples), err)
	}
	for index, sample := range samples {
		want := fmt.Sprintf("attempt-%d", index)
		validError := sample.Err == nil
		if index == 1 {
			validError = errors.Is(sample.Err, io.ErrUnexpectedEOF)
		}
		if !validError || sample.Index != index || string(sample.Receipt.Body) != want || sample.Receipt.Header.Get("X-Attempt") != fmt.Sprint(index) || sample.Receipt.BodyBytes != int64(len(want)) || sample.Receipt.StatusCode != 200 || sample.Receipt.BodyComplete != (index != 1) || sample.Receipt.Elapsed <= 0 || sample.Receipt.FirstByteElapsed == nil || *sample.Receipt.FirstByteElapsed > sample.Receipt.Elapsed {
			t.Fatalf("sample: %+v", sample)
		}
	}
	head := measurement.HTTPRequest(request(s, measurement.ExactOutbound))
	head.MaxBodyBytes = 0
	if got, err := e.HTTP(context.Background(), http.MethodHead, head); err != nil || got.StatusCode != 200 || got.BodyBytes != 0 || len(got.Body) != 0 || !got.BodyComplete || got.EndpointTLS == nil || got.FirstByteElapsed == nil {
		t.Fatalf("native node HEAD facts: %+v, %v", got, err)
	}
	download := downloadRequest(s, measurement.ExactOutbound)
	download.HTTPS.URL += "/partial"
	partial, err := e.Download(context.Background(), download)
	if !errors.Is(err, io.ErrUnexpectedEOF) || partial.PayloadBytes != 6 || partial.HTTPS.BodyComplete {
		t.Fatalf("partial download: %+v, %v", partial, err)
	}
	upload := uploadRequest(s, measurement.ExactOutbound)
	upload.HTTPS.URL += "/upload"
	uploaded, err := e.Upload(context.Background(), upload)
	if err != nil || uploaded.Acknowledgment == nil || uploaded.WriterAcceptedBytes != upload.PayloadBytes || uploaded.Acknowledgment.Bytes != upload.PayloadBytes {
		t.Fatalf("upload: %+v, %v", uploaded, err)
	}
	identity := request(s, measurement.ExactOutbound)
	identity.URL += "/identity"
	response, err := e.HTTPS(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := measurement.IdentityFromHTTPS(response, measurement.IPv4); err != nil || got.Address.String() != "192.0.2.1" {
		t.Fatalf("identity: %+v, %v", got, err)
	}
	dnsUDP := udpFixture(t, func(pc net.PacketConn, b []byte, addr net.Addr) { _, _ = pc.WriteTo(dnsReply(b), addr) })
	dnsTCP := dnsStreamFixture(t, nil, func(c net.Conn, query []byte) { dnsFrame(c, dnsReply(query)) })
	for transport, addr := range map[measurement.DNSTransport]net.Addr{measurement.DNSUDP: dnsUDP.LocalAddr(), measurement.DNSTCP: dnsTCP} {
		got, err := e.DNSQuery(context.Background(), dnsRequest(addr, transport, measurement.ExactOutbound))
		if err != nil || !got.ResponseComplete || got.Message == nil || len(got.Message.Answer) != 1 {
			t.Fatalf("DNS %d: %+v, %v", transport, got, err)
		}
	}
	pc := udpFixture(t, func(pc net.PacketConn, b []byte, addr net.Addr) { _, _ = pc.WriteTo(b, addr) })
	// Retain an ordinary packet session across a canceled Measurement train.
	ordinaryCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	ordinaryCtx = session.SetForcedOutboundTagToContext(ordinaryCtx, "exact")
	dest, _ := xnet.ParseDestination("udp:" + pc.LocalAddr().String())
	ordinary, err := core.Dial(ordinaryCtx, v, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	ordinaryEcho := func() {
		t.Helper()
		if _, err := ordinary.Write([]byte("ordinary")); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var b [32]byte
			n, err := ordinary.Read(b[:])
			if string(b[:n]) != "ordinary" {
				err = errors.Join(err, errors.New("ordinary packet mismatch"))
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			ordinary.Close()
			<-done
			t.Fatal("ordinary packet session stalled")
		}
	}
	ordinaryEcho() // Prove a live warm session exists before cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan []byte, 1)
	blocked := udpFixture(t, func(_ net.PacketConn, packet []byte, _ net.Addr) {
		select {
		case seen <- packet:
		default:
		}
	})
	r := udpRequest(blocked.LocalAddr(), measurement.ExactOutbound)
	r.Count, r.Interval, r.ReplyWait = 100, time.Millisecond, time.Second
	type udpResult struct {
		receipt measurement.UDPEchoReceipt
		err     error
	}
	returned := make(chan udpResult, 1)
	go func() { got, err := e.UDPEcho(ctx, r); returned <- udpResult{got, err} }()
	var packet []byte
	select {
	case packet = <-seen:
	case <-time.After(2 * time.Second):
		cancel()
		<-returned
		t.Fatal("Measurement datagram did not reach endpoint")
	}
	cancel()
	select {
	case got := <-returned:
		if !errors.Is(got.err, context.Canceled) || got.receipt.Elapsed < 0 || got.receipt.WindowComplete || len(got.receipt.Replies) != 0 || len(got.receipt.Sends) == 0 || len(got.receipt.Sends) > r.Count || len(packet) < 24 || !bytes.Equal(got.receipt.Nonce[:], packet[4:20]) {
			t.Fatalf("canceled train facts: %+v, %v", got.receipt, got.err)
		}
		for i, sent := range got.receipt.Sends {
			if sent.Sequence != uint32(i) || sent.WriteReturned == nil {
				t.Fatalf("canceled write facts: %+v", sent)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Measurement UDP cancel stalled")
	}
	ordinaryEcho()
	got, err := e.UDPEcho(context.Background(), udpRequest(pc.LocalAddr(), measurement.ExactOutbound))
	if err != nil || len(got.Replies) != 3 || !got.WindowComplete {
		t.Fatalf("post-cancel train: %+v, %v", got, err)
	}
	for _, reply := range got.Replies {
		if reply.Issue != measurement.UDPReplyValid {
			t.Fatalf("reply: %+v", reply)
		}
	}
}
