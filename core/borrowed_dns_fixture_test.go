package core_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	wiredns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Everything in this fixture is test-only: the callback is a borrowed double,
// not a resolver engine, and the wrappers use existing App/proxy construction.
type borrowedDNSFixtureKey struct{}

func init() {
	common.Must(common.RegisterConfig((*wrapperspb.StringValue)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		f, ok := ctx.Value(borrowedDNSFixtureKey{}).(*borrowedDNSFixture)
		if !ok {
			return nil, errors.New("borrowed DNS fixture missing")
		}
		return f.client, nil
	}))
	common.Must(common.RegisterConfig((*wrapperspb.BytesValue)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		f, ok := ctx.Value(borrowedDNSFixtureKey{}).(*borrowedDNSFixture)
		if !ok {
			return nil, errors.New("borrowed DNS fixture missing")
		}
		return f.gateway, nil
	}))
}

type borrowedDNSRecord struct {
	question *wiredns.Msg
	endpoint net.Destination
	content  *session.Content
}

type borrowedDNSBlock struct {
	entered, canceled, release chan struct{}
	releaseOnce                sync.Once
}

func newBorrowedDNSBlock(t *testing.T) *borrowedDNSBlock {
	b := &borrowedDNSBlock{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(b.unblock)
	return b
}

func (b *borrowedDNSBlock) unblock() { b.releaseOnce.Do(func() { close(b.release) }) }

type borrowedDNSService struct {
	mu      sync.Mutex
	records []borrowedDNSRecord
	blocks  map[string]*borrowedDNSBlock // immutable after composition
	closed  bool
}

func (s *borrowedDNSService) exchange(ctx context.Context, q *wiredns.Msg, endpoint net.Destination) (*wiredns.Msg, error) {
	if session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal || session.LogicalObservationFromContext(ctx) != nil ||
		session.InboundFromContext(ctx) != nil || len(session.OutboundsFromContext(ctx)) != 0 {
		return nil, errors.New("backend inherited caller observation or session metadata")
	}
	c := session.ContentFromContext(ctx)
	if c == nil || c.Protocol != "" || len(c.Attributes) != 0 || c.SniffingRequest.Enabled || c.SkipDNSResolve {
		return nil, errors.New("backend content was not reset")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	s.records = append(s.records, borrowedDNSRecord{q.Copy(), endpoint, c})
	b := s.blocks[q.Question[0].Name]
	s.mu.Unlock()
	if b != nil {
		close(b.entered)
		<-ctx.Done()
		close(b.canceled)
		<-b.release // deliberately delay retirement to witness Close joining
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := borrowedDNSAnswer(q)
	if q.Question[0].Name == "wrong-id.invalid." {
		r.Id++
	}
	return r, nil
}

func (s *borrowedDNSService) snapshot() ([]borrowedDNSRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]borrowedDNSRecord(nil), s.records...), s.closed
}

func (s *borrowedDNSService) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func borrowedDNSAnswer(q *wiredns.Msg) *wiredns.Msg {
	r := q.Copy()
	r.Response = true
	r.RecursionAvailable = true
	n := q.Question[0].Name
	r.Answer = []wiredns.RR{
		&wiredns.CNAME{Hdr: wiredns.RR_Header{Name: n, Rrtype: wiredns.TypeCNAME, Class: wiredns.ClassINET, Ttl: 60}, Target: "answer.invalid."},
		&wiredns.A{Hdr: wiredns.RR_Header{Name: "answer.invalid.", Rrtype: wiredns.TypeA, Class: wiredns.ClassINET, Ttl: 60}, A: net.IP{203, 0, 113, 9}},
		&wiredns.TXT{Hdr: wiredns.RR_Header{Name: n, Rrtype: wiredns.TypeTXT, Class: wiredns.ClassINET, Ttl: 60}, Txt: []string{"borrowed-full-message"}},
	}
	r.Ns = []wiredns.RR{&wiredns.SOA{Hdr: wiredns.RR_Header{Name: "invalid.", Rrtype: wiredns.TypeSOA, Class: wiredns.ClassINET, Ttl: 60}, Ns: "ns.invalid.", Mbox: "hostmaster.invalid.", Serial: 7, Refresh: 60, Retry: 60, Expire: 600, Minttl: 60}}
	return r
}

type borrowedDNSClient struct {
	callback func(context.Context, *wiredns.Msg, net.Destination) (*wiredns.Msg, error)
	mu       sync.Mutex
	sealed   bool
	next     uint64
	active   map[uint64]context.CancelFunc
	wg       sync.WaitGroup
}

func (*borrowedDNSClient) Type() interface{} { return featuredns.ClientType() }
func (*borrowedDNSClient) Start() error      { return nil }

func (c *borrowedDNSClient) admit(parent context.Context) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed {
		return nil, nil, io.ErrClosedPipe
	}
	ctx, cancel := context.WithCancel(parent)
	c.next++
	id := c.next
	c.active[id] = cancel
	c.wg.Add(1)
	return ctx, func() {
		cancel()
		c.mu.Lock()
		delete(c.active, id)
		c.mu.Unlock()
		c.wg.Done()
	}, nil
}

func (c *borrowedDNSClient) Close() error {
	c.mu.Lock()
	c.sealed = true // seal Add before Wait
	for _, cancel := range c.active {
		cancel()
	}
	c.mu.Unlock()
	c.wg.Wait()
	return nil // borrowed callback/service/pools remain with composition
}

// Reset mutable state and fence inherited USER observation using existing APIs.
// Origin marking alone would leave the caller's logical exchange reachable.
func borrowedDNSBackendContext(ctx context.Context) context.Context {
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginInternal)
	ctx = session.ContextWithInbound(ctx, nil)
	ctx = session.ContextWithOutbounds(ctx, nil)
	return session.ContextWithContent(ctx, &session.Content{})
}

func (c *borrowedDNSClient) LookupIP(domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	return c.LookupIPContext(context.Background(), domain, option)
}

func (c *borrowedDNSClient) LookupIPContext(parent context.Context, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	ctx, done, err := c.admit(parent)
	if err != nil {
		return nil, 0, err
	}
	defer done()
	if !option.IPv4Enable {
		return nil, 0, featuredns.ErrEmptyResponse // fixture only projects IPv4
	}
	q := new(wiredns.Msg)
	q.SetQuestion(wiredns.Fqdn(domain), wiredns.TypeA)
	r, err := c.callback(borrowedDNSBackendContext(ctx), q, net.Destination{})
	if err != nil {
		return nil, 0, err
	}
	var ips []net.IP
	for _, rr := range r.Answer {
		if a, ok := rr.(*wiredns.A); ok {
			ips = append(ips, a.A)
		}
	}
	return ips, 60, nil
}

type borrowedDNSGateway struct {
	client   *borrowedDNSClient
	endpoint net.Address
	reads    chan int
}

func (g *borrowedDNSGateway) Process(parent context.Context, link *transport.Link, _ internet.Dialer) error {
	ctx, done, err := g.client.admit(parent)
	if err != nil {
		return err
	}
	defer done()
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 {
		return errors.New("missing target")
	}
	dest := obs[len(obs)-1].Target
	if dest.Address != g.endpoint || dest.Port != 53 || (dest.Network != net.Network_UDP && dest.Network != net.Network_TCP) {
		return fmt.Errorf("unsupported DNS endpoint: %v", dest)
	}
	serve := func(raw []byte, endpoint net.Destination) ([]byte, string, error) {
		g.reads <- len(raw)
		q := new(wiredns.Msg)
		if err := q.Unpack(raw); err != nil {
			return nil, "", err
		}
		if len(q.Question) != 1 {
			return nil, "", errors.New("fixture requires one question")
		}
		r, err := g.client.callback(borrowedDNSBackendContext(ctx), q, endpoint)
		if err != nil {
			return nil, "", err
		}
		wire, err := r.Pack()
		return wire, q.Question[0].Name, err
	}
	if dest.Network == net.Network_TCP {
		r := &buf.BufferedReader{Reader: link.Reader}
		defer func() { buf.ReleaseMulti(r.Buffer) }()
		for {
			var header [2]byte
			if _, err := io.ReadFull(r, header[:]); err != nil {
				return err
			}
			raw := make([]byte, int(binary.BigEndian.Uint16(header[:])))
			if _, err := io.ReadFull(r, raw); err != nil {
				return err
			}
			wire, _, err := serve(raw, dest)
			if err != nil {
				return err
			}
			framed := make([]byte, len(wire)+2)
			binary.BigEndian.PutUint16(framed, uint16(len(wire)))
			copy(framed[2:], wire)
			if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, framed)); err != nil {
				return err
			}
		}
	}
	for {
		mb, readErr := link.Reader.ReadMultiBuffer()
		for i, b := range mb {
			endpoint := dest
			if b.UDP != nil {
				endpoint = *b.UDP
			}
			if endpoint != dest {
				buf.ReleaseMulti(mb)
				return errors.New("UDP destination mismatch")
			}
			wire, name, err := serve(b.Bytes(), endpoint)
			b.Release()
			mb[i] = nil
			if err != nil {
				buf.ReleaseMulti(mb)
				return err
			}
			if len(wire) > buf.Size {
				buf.ReleaseMulti(mb)
				return errors.New("fixture UDP response exceeds native buffer")
			}
			response := buf.New()
			response.Write(wire)
			if name != "no-source.invalid." {
				source := endpoint
				if name == "wrong-source.invalid." {
					source.Address = net.IPAddress(net.IP{192, 0, 2, 99})
				}
				response.UDP = &source
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{response}); err != nil {
				buf.ReleaseMulti(mb)
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

type borrowedDNSFixture struct {
	instance *core.Instance
	service  *borrowedDNSService
	client   *borrowedDNSClient
	gateway  *borrowedDNSGateway
}

func newBorrowedDNSFixture(t *testing.T, blocks map[string]*borrowedDNSBlock) *borrowedDNSFixture {
	t.Helper()
	f := &borrowedDNSFixture{service: &borrowedDNSService{blocks: blocks}}
	f.client = &borrowedDNSClient{callback: f.service.exchange, active: make(map[uint64]context.CancelFunc)}
	f.gateway = &borrowedDNSGateway{client: f.client, endpoint: net.IPAddress(net.IP{192, 0, 2, 53}), reads: make(chan int, 32)}
	// Cleanup is composition-owned and explicitly closes the borrowed service last.
	t.Cleanup(func() {
		for _, block := range blocks {
			block.unblock()
		}
		if f.instance != nil {
			if err := f.instance.Close(); err != nil {
				t.Error(err)
			}
		}
		internet.InitSystemDialer(localdns.New(), nil)
		f.service.Close()
	})
	ctx := context.WithValue(context.Background(), borrowedDNSFixtureKey{}, f)
	config := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&router.Config{DomainStrategy: router.Config_IpOnDemand, Rule: []*router.RoutingRule{{
			TargetTag: &router.RoutingRule_Tag{Tag: "borrowed-dns"},
			Ip:        []*geodata.IPRule{{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{Cidr: &geodata.CIDR{Ip: []byte{203, 0, 113, 9}, Prefix: 32}}}}},
		}}}),
		// No native app/dns: dependencies resolve against this App client.
		serial.ToTypedMessage(wrapperspb.String("borrowed-dns-client")),
	}, Outbound: []*core.OutboundHandlerConfig{{Tag: "borrowed-dns", ProxySettings: serial.ToTypedMessage(wrapperspb.Bytes([]byte("borrowed-dns-gateway")))}}}
	var err error
	f.instance, err = core.NewWithContext(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.instance.Start(); err != nil {
		t.Fatal(err)
	}
	return f
}

func borrowedDNSWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("borrowed DNS witness timed out")
	}
}

var _ featuredns.Client = (*borrowedDNSClient)(nil)
var _ featuredns.ContextClient = (*borrowedDNSClient)(nil)
