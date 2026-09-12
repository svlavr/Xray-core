package hysteria_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestListenAndDialLogicalTCPStream(t *testing.T) {
	serverRead := make(chan string, 1)
	serverDone := make(chan error, 1)
	serverExited := make(chan struct{})
	releaseServer := make(chan struct{})
	var releaseServerOnce sync.Once
	release := func() { releaseServerOnce.Do(func() { close(releaseServer) }) }
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "hysteria",
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate: []*tls.Certificate{serverCertificate},
		},
	}
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "hysteria",
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			PinnedPeerCertSha256: [][]byte{certificateHash[:]},
		},
	}
	port := udp.PickPort()
	listener, err := Listen(context.Background(), net.LocalHostIP, port, serverSettings, func(conn stat.Connection) {
		go func() {
			defer close(serverExited)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var request [32]byte
			n, err := conn.Read(request[:])
			if err != nil {
				serverDone <- err
				return
			}
			serverRead <- string(request[:n])
			_, err = conn.Write([]byte("response"))
			serverDone <- err
			<-releaseServer
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cleanupServer := func() {
		release()
		select {
		case <-serverExited:
		case <-time.After(2 * time.Second):
			t.Errorf("timed out waiting for Hysteria server callback to exit")
		}
	}
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), port), clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	var response [32]byte
	n, err := conn.Read(response[:])
	if err != nil {
		select {
		case serverErr := <-serverDone:
			t.Fatalf("client read failed: %v; server result: %v", err, serverErr)
		default:
			t.Fatal(err)
		}
	}
	if got := string(response[:n]); got != "response" {
		t.Fatalf("got response %q, want %q", got, "response")
	}
	var got string
	select {
	case got = <-serverRead:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Hysteria server request")
	}
	if got != "request" {
		t.Fatalf("server got request %q, want %q", got, "request")
	}
	var serverErr error
	select {
	case serverErr = <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Hysteria server result")
	}
	if serverErr != nil {
		t.Fatal(serverErr)
	}
	cleanupServer()
}
