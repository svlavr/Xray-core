package measurement

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

var (
	ErrDNSResponse = errors.New("invalid or mismatched DNS response")
	ErrDNSLimit    = errors.New("DNS response exceeds request limit")
)

type DNSTransport uint8

const (
	DNSUDP DNSTransport = iota + 1
	DNSTCP
	DNSDoT
	DNSDoH
)

// DNSRequest describes one cache-free IN question to an explicit numeric resolver.
// ServerName is authenticated endpoint TLS identity, never a resolver lookup.
// RootCAs nil uses system roots; DoHPath is an absolute path, optionally with query.
type DNSRequest struct {
	Route            Route
	Transport        DNSTransport
	Resolver         netip.AddrPort
	Name             string // Absolute presentation name, including final dot.
	Type             uint16
	RecursionDesired bool
	EDNSSize         uint16 // Advertised UDP size; DNSSECOK requires EDNS.
	DNSSECOK         bool
	Timeout          time.Duration
	MaxResponseBytes int // Caller-selected retained-response limit, at least 12 bytes.
	ServerName       string
	RootCAs          *x509.CertPool
	DoHPath          string
	MaxHeaderBytes   int64 // Required for DoH only.
}

// DNSReceipt retains bounded raw wire, including partial/invalid responses.
// Message is present only after complete framing and matching ID/question checks.
// RCODE and TC/AD are observed facts; no fallback, health or DNSSEC verdict exists.
// WrittenBytes is logical DNS payload writer acceptance, excluding TCP framing.
type DNSReceipt struct {
	QueryID          uint16
	Wire             []byte
	Message          *dns.Msg
	WrittenBytes     *int
	ResponseComplete bool
	Elapsed          time.Duration
	EndpointTLS      *time.Duration
	OutboundError    error
	HTTPStatus       int
	HTTPContentType  string
}

func validateDNS(request DNSRequest) error {
	if request.Transport < DNSUDP || request.Transport > DNSDoH || !request.Resolver.IsValid() || request.Resolver.Addr().Zone() != "" || !request.Route.valid() {
		return errors.New("invalid DNS transport/resolver/route")
	}
	if request.Timeout <= 0 || request.MaxResponseBytes < 12 {
		return errors.New("invalid DNS byte/time budget")
	}
	if request.Type == dns.TypeAXFR || request.Type == dns.TypeIXFR {
		return ErrUnsupported // Zone transfers are not a single-response query.
	}
	if request.DNSSECOK && request.EDNSSize == 0 {
		return errors.New("DNSSEC flag requires EDNS")
	}
	return nil
}

// DNSQuery performs one wire exchange. It never calls the ordinary DNS client,
// modifies a resolver/cache, follows a redirect, retries, or falls back to TCP.
func (e *Executor) DNSQuery(ctx context.Context, request DNSRequest) (receipt DNSReceipt, resultErr error) {
	if ctx == nil {
		return receipt, errors.New("nil request context")
	}
	if err := validateDNS(request); err != nil {
		return receipt, err
	}
	request.Resolver = netip.AddrPortFrom(request.Resolver.Addr().Unmap(), request.Resolver.Port())
	query := new(dns.Msg)
	query.Question = []dns.Question{{Name: request.Name, Qtype: request.Type, Qclass: dns.ClassINET}}
	query.RecursionDesired = request.RecursionDesired
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return receipt, err
	}
	query.Id = binary.BigEndian.Uint16(id[:])
	if request.Transport == DNSDoH {
		query.Id = 0
	}
	receipt.QueryID = query.Id
	if request.EDNSSize != 0 {
		query.SetEdns0(request.EDNSSize, request.DNSSECOK)
	}
	wire, err := query.Pack()
	if err != nil {
		return receipt, err
	}
	// Compare the expected question in its actual wire representation. DNS
	// presentation escapes may have several spellings for the same label.
	if err := query.Unpack(wire); err != nil {
		return receipt, err
	}
	dest := xnet.TCPDestination(xnet.IPAddress(request.Resolver.Addr().AsSlice()), xnet.Port(request.Resolver.Port()))
	if request.Transport == DNSUDP {
		dest.Network = xnet.Network_UDP
	}
	if request.Transport == DNSDoH {
		options := &httpExchangeOptions{destination: dest, body: bytes.NewReader(wire), headers: http.Header{"Accept": {"application/dns-message"}, "Content-Type": {"application/dns-message"}}}
		https := HTTPSRequest{Route: request.Route, URL: "https://" + net.JoinHostPort(request.ServerName, strconv.Itoa(int(request.Resolver.Port()))) + request.DoHPath, Timeout: request.Timeout, MaxBodyBytes: int64(request.MaxResponseBytes), MaxHeaderBytes: request.MaxHeaderBytes, RootCAs: request.RootCAs}
		// The POST body has a finite known length. No upload acknowledgment is inferred.
		r, err := e.exchangeHTTP(ctx, https, http.MethodPost, nil, options, func(ctx context.Context, response *http.Response, r *HTTPSReceipt) error {
			readErr := readHTTPSBody(response, r, https.MaxBodyBytes)
			media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
			if response.StatusCode < 200 || response.StatusCode >= 300 || mediaErr != nil || media != "application/dns-message" {
				return errors.Join(readErr, ErrDNSResponse)
			}
			if readErr != nil {
				return readErr
			}
			var err error
			receipt.Message, err = parseDNSResponse(ctx, r.Body, query)
			return err
		})
		receipt.Wire, receipt.ResponseComplete = r.Body, r.BodyComplete
		receipt.Elapsed, receipt.EndpointTLS = r.Elapsed, r.EndpointTLS
		receipt.OutboundError = r.OutboundError
		receipt.HTTPStatus, receipt.HTTPContentType = r.StatusCode, r.Header.Get("Content-Type")
		// net/http does not expose an independent POST payload writer count here.
		return receipt, err
	}
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	if err := e.acquire(ctx); err != nil {
		return receipt, err
	}
	defer func() { <-e.slots }()
	started := time.Now()
	o := new(operation)
	ctx = measurementContext(ctx, o)
	defer func() {
		receipt.Elapsed = time.Since(started)
		o.mu.Lock()
		receipt.OutboundError, receipt.EndpointTLS = o.nativeError, o.tlsTime
		o.mu.Unlock()
	}()
	rawConn, err := e.open(ctx, request.Route, dest)
	if err != nil {
		return receipt, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stopClose()
	defer rawConn.Close()
	conn := rawConn
	if request.Transport == DNSDoT {
		conn, err = o.handshakeTLS(ctx, conn, &tls.Config{ServerName: request.ServerName, MinVersion: tls.VersionTLS12, RootCAs: request.RootCAs})
		if err != nil {
			return receipt, err
		}
	}
	if err := exchangeDNSWire(conn, wire, request, &receipt); err != nil {
		return receipt, errors.Join(err, ctx.Err())
	}
	receipt.Message, resultErr = parseDNSResponse(ctx, receipt.Wire, query)
	return receipt, resultErr
}

// exchangeDNSWire writes raw facts directly into the operation's receipt,
// retaining positive partial writes and response bytes even with native errors.
func exchangeDNSWire(conn net.Conn, wire []byte, request DNSRequest, receipt *DNSReceipt) error {
	payloadWritten := 0
	receipt.WrittenBytes = &payloadWritten
	if request.Transport == DNSUDP {
		n, err := conn.Write(wire)
		payloadWritten = n
		if err != nil {
			return err
		}
		if n != len(wire) {
			return io.ErrShortWrite
		}
		var packet []byte
		var readErr error
		if pc, ok := conn.(net.PacketConn); ok {
			packet = make([]byte, 65536)
			n, addr, err := pc.ReadFrom(packet)
			packet = packet[:n]
			readErr = err
			source, ok := addr.(*net.UDPAddr)
			if !ok || netip.AddrPortFrom(source.AddrPort().Addr().Unmap(), source.AddrPort().Port()) != request.Resolver {
				readErr = errors.Join(readErr, ErrDNSResponse)
			}
		} else if reader, ok := conn.(buf.Reader); ok {
			mb, err := reader.ReadMultiBuffer()
			readErr = err
			defer buf.ReleaseMulti(mb)
			if len(mb) > 0 {
				b := mb[0]
				packet = b.Bytes()
				if b.UDP == nil || b.UDP.Address.String() != request.Resolver.Addr().String() || uint16(b.UDP.Port) != request.Resolver.Port() {
					readErr = errors.Join(readErr, ErrDNSResponse)
				}
			}
		} else {
			return ErrUnsupported
		}
		receipt.Wire = append([]byte(nil), packet[:min(len(packet), request.MaxResponseBytes)]...)
		if len(packet) > request.MaxResponseBytes {
			readErr = errors.Join(readErr, ErrDNSLimit)
		} else {
			receipt.ResponseComplete = readErr == nil
		}
		return readErr
	}
	frame := make([]byte, len(wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	written := 0
	for written < len(frame) {
		n, err := conn.Write(frame[written:])
		written += n
		payloadWritten = max(0, written-2)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	if size > request.MaxResponseBytes {
		return ErrDNSLimit
	}
	if size < 12 {
		return ErrDNSResponse
	}
	receipt.Wire = make([]byte, size)
	n, err := io.ReadFull(conn, receipt.Wire)
	receipt.Wire = receipt.Wire[:n]
	receipt.ResponseComplete = err == nil
	return err
}

func parseDNSResponse(ctx context.Context, wire []byte, query *dns.Msg) (response *dns.Msg, resultErr error) {
	// Linearize completion before our caller's deferred cancellation. A result
	// queued by the wire worker must not hide cancellation at final handoff.
	defer func() { resultErr = errors.Join(resultErr, ctx.Err()) }()
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return nil, errors.Join(ErrDNSResponse, err)
	}
	if msg.Id != query.Id || !msg.Response || msg.Opcode != dns.OpcodeQuery || len(msg.Question) != 1 || !strings.EqualFold(msg.Question[0].Name, query.Question[0].Name) || msg.Question[0].Qtype != query.Question[0].Qtype || msg.Question[0].Qclass != dns.ClassINET {
		return nil, ErrDNSResponse
	}
	return msg, nil
}
