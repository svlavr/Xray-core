package http

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	apppolicy "github.com/xtls/xray-core/app/policy"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/http2"
)

func cachedHTTP2TestConn(t *testing.T, handler stdhttp.Handler) (cnet.Destination, *http2.ClientConn, stdnet.Conn) {
	t.Helper()
	client, server := stdnet.Pipe()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	server.SetDeadline(time.Now().Add(10 * time.Second))
	go new(http2.Server).ServeConn(server, &http2.ServeConnOpts{Handler: handler})
	h2client, err := new(http2.Transport).NewClientConn(client)
	if err != nil {
		client.Close()
		server.Close()
		t.Fatal(err)
	}
	destination := cnet.TCPDestination(cnet.LocalHostIP, 443)
	cachedH2Mutex.Lock()
	previous := cachedH2Conns
	cachedH2Conns = map[cnet.Destination]h2Conn{destination: {rawConn: client, h2Conn: h2client}}
	cachedH2Mutex.Unlock()
	t.Cleanup(func() {
		cachedH2Mutex.Lock()
		cachedH2Conns = previous
		cachedH2Mutex.Unlock()
		h2client.Close()
		client.Close()
		server.Close()
	})
	return destination, h2client, client
}

func TestHTTP2SetupFailureJoinsPayloadWriterAndPreservesSibling(t *testing.T) {
	handler := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if strings.HasPrefix(r.Host, "reset.") {
			panic(stdhttp.ErrAbortHandler)
		}
		if strings.HasPrefix(r.Host, "reject.") {
			// A non-200 status below 300 does not make x/net/http2 abort the
			// request body. Setup must close its own pipe before joining the
			// first-payload writer.
			w.WriteHeader(stdhttp.StatusNoContent)
			w.(stdhttp.Flusher).Flush()
			return
		}
		w.WriteHeader(stdhttp.StatusOK)
		w.(stdhttp.Flusher).Flush()
		buffer := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
					return
				}
				w.(stdhttp.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})
	destination, _, rawConn := cachedHTTP2TestConn(t, handler)

	firstPayload := []byte("first logical payload")
	active, err := setUpHTTPTunnel(context.Background(), destination, "active.invalid:80", nil, nil, nil, firstPayload)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	got := make([]byte, len(firstPayload))
	if _, err := io.ReadFull(active, got); err != nil || !bytes.Equal(got, firstPayload) {
		t.Fatalf("first payload: %q %v", got, err)
	}

	for _, host := range []string{"reject.invalid:80", "reset.invalid:80"} {
		failed := make(chan error, 1)
		go func() {
			_, err := setUpHTTPTunnel(context.Background(), destination, host, nil, nil, nil, bytes.Repeat([]byte("x"), 1<<20))
			failed <- err
		}()
		select {
		case err := <-failed:
			if err == nil || (strings.HasPrefix(host, "reject.") && !strings.Contains(err.Error(), "204")) {
				t.Fatalf("failed setup %s: %v", host, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("failed HTTP/2 setup %s did not release its payload writer", host)
		}
	}
	if err := rawConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	extra := []byte("sibling remains on the shared carrier")
	if _, err := active.Write(extra); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(extra))
	if _, err := io.ReadFull(active, got); err != nil || !bytes.Equal(got, extra) {
		t.Fatalf("surviving sibling: %q %v", got, err)
	}
}

type observedHTTP2Endpoint struct {
	conn stdnet.Conn
	done <-chan error
}

func startObservedHTTP2Endpoint(t *testing.T, client *Client, manager *appstats.Manager, view fs.FlowInspection, target cnet.Destination, serial uint64, payload []byte) observedHTTP2Endpoint {
	t.Helper()
	endpoint, peer := stdnet.Pipe()
	peer.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(endpoint), Writer: buf.NewWriter(endpoint)}
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: cnet.TCPDestination(cnet.LocalHostIP, cnet.Port(serial))})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	ctx, finish := proxy.ObserveTCP(ctx, manager, endpoint, target, link)
	if finish == nil {
		t.Fatal("inspection was not enabled")
	}
	observation := session.LogicalObservationFromContext(ctx)
	observation.Exchange.Route(fs.RouteStep{
		Outbound:       fs.OutboundRef{Runtime: view.Info().Runtime, Serial: serial, Tag: "http-proxy"},
		Original:       target,
		RouteTarget:    target,
		SelectedTarget: target,
	})
	done := make(chan error, 1)
	go func() {
		defer finish()
		done <- client.Process(ctx, link, nil)
	}()
	if _, err := peer.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("logical payload: %q %v", got, err)
	}
	return observedHTTP2Endpoint{conn: peer, done: done}
}

func waitHTTPInspection(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("inspection condition did not complete")
}

func TestHTTP2ProcessObservationAndExactStreamStop(t *testing.T) {
	handler := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusOK)
		w.(stdhttp.Flusher).Flush()
		buffer := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
					return
				}
				w.(stdhttp.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})
	server, _, _ := cachedHTTP2TestConn(t, handler)
	policyManager, err := apppolicy.New(context.Background(), &apppolicy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	client := &Client{server: protocol.NewServerSpec(server, nil), policyManager: policyManager}
	target := cnet.TCPDestination(cnet.DomainAddress("logical.invalid"), 443)
	payload := append([]byte("GET / HTTP/1.1\r\nHost: logical.invalid\r\n\r\n"), bytes.Repeat([]byte("p"), 8192)...)
	first := startObservedHTTP2Endpoint(t, client, manager, view, target, 1, payload)
	second := startObservedHTTP2Endpoint(t, client, manager, view, target, 2, payload)

	var selected fs.FlowRef
	waitHTTPInspection(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 2 {
			return false
		}
		for _, row := range live.Rows {
			if row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) || row.Uplink.Incomplete || row.Downlink.Incomplete {
				return false
			}
			if row.AccountingRoute.Outbound.Tag != "http-proxy" || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != target || row.Uplink.Incomplete || row.Downlink.Incomplete {
				t.Fatalf("live HTTP/2 receipt: %+v", row)
			}
			if row.AccountingRoute.Outbound.Serial == 1 {
				selected = row.Ref
			}
		}
		return selected.ID != 0
	})
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("exact stream close: %+v %v", outcomes, err)
	}
	waitHTTPInspection(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected && page.Rows[0].Reason == fs.EndReasonLocalStop
	})
	select {
	case <-first.done:
	case <-time.After(3 * time.Second):
		t.Fatal("stopped HTTP/2 stream did not finish")
	}
	extra := []byte("shared carrier sibling")
	if _, err := second.conn.Write(extra); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(extra))
	if _, err := io.ReadFull(second.conn, got); err != nil || !bytes.Equal(got, extra) {
		t.Fatalf("surviving HTTP/2 stream: %q %v", got, err)
	}
	second.conn.Close()
	waitHTTPInspection(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 2
	})
	want := uint64(2*len(payload) + len(extra))
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatalf("HTTP/2 totals: %+v %v", totals, err)
	}
	var up, down uint64
	var selectedBuckets int
	for _, row := range totals.Rows {
		if row.Outbound.Serial == 0 {
			if row.Uplink.Known != 0 || row.Downlink.Known != 0 {
				t.Fatalf("unexpected unassigned HTTP/2 credit: %+v", row)
			}
			continue
		}
		selectedBuckets++
		if row.Outbound.Tag != "http-proxy" || row.Origin != fs.TrafficOriginUser || row.Uplink.Incomplete || row.Downlink.Incomplete {
			t.Fatalf("HTTP/2 total attribution: %+v", row)
		}
		up += row.Uplink.Known
		down += row.Downlink.Known
	}
	if selectedBuckets != 2 || up != want || down != want {
		t.Fatalf("HTTP/2 framing included or payload lost: buckets=%d %d/%d want %d", selectedBuckets, up, down, want)
	}
}
