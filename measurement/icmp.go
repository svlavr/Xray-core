package measurement

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPEchoRequest names one numeric endpoint, not an arbitrary proxy path.
// PayloadBytes includes the 16-byte unpredictable correlation nonce, excluding
// the eight-byte ICMP header. Native socket privilege errors remain visible.
type ICMPEchoRequest struct {
	Route        Route
	Destination  netip.Addr
	PayloadBytes int
	Timeout      time.Duration // Positive; includes admission wait.
}

// ICMPEchoReceipt retains one actual write and its matching EchoReply. Byte
// counts include the ICMP header, not the IP header. RoundTrip starts before
// WriteTo and ends when the matched packet is read; it is not a kernel RTT.
// Missing RoundTrip/invalid ReplySource means no matching reply was observed.
type ICMPEchoReceipt struct {
	Nonce        [16]byte
	WrittenBytes *int
	ReplyBytes   int
	ReplySource  netip.Addr
	RoundTrip    *time.Duration
	Elapsed      time.Duration // Admission through I/O completion, excluding cleanup.
}

// ICMPEcho executes one endpoint Echo. Existing RunSeries supplies repetitions.
// It does not invoke a system ping process, a proxy route or a shared socket.
func (e *Executor) ICMPEcho(ctx context.Context, request ICMPEchoRequest) (receipt ICMPEchoReceipt, resultErr error) {
	if ctx == nil || !request.Route.valid() || !request.Destination.IsValid() || request.Destination.Zone() != "" || request.Timeout <= 0 {
		return receipt, errors.New("invalid ICMP endpoint/route/time budget")
	}
	if request.Route.Kind != Direct {
		return receipt, ErrUnsupported
	}
	request.Destination = request.Destination.Unmap()
	maxPayload := 65535 - 8
	if request.Destination.Is4() {
		maxPayload -= ipv4.HeaderLen
	}
	if request.PayloadBytes < len(receipt.Nonce) || request.PayloadBytes > maxPayload {
		return receipt, errors.New("invalid ICMP payload budget")
	}
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	if err := e.acquire(ctx); err != nil {
		return receipt, err
	}
	started := time.Now()
	var conn *icmp.PacketConn
	defer func() {
		receipt.Elapsed = time.Since(started)
		resultErr = errors.Join(resultErr, ctx.Err())
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		<-e.slots
	}()
	payload := make([]byte, request.PayloadBytes)
	if _, err := rand.Read(payload); err != nil {
		return receipt, err
	}
	copy(receipt.Nonce[:], payload)
	network, local := "ip6:ipv6-icmp", "::"
	if request.Destination.Is4() {
		network, local = "ip4:icmp", "0.0.0.0"
	}
	datagram := runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin" || runtime.GOOS == "ios"
	if datagram {
		network = "udp6"
		if request.Destination.Is4() {
			network = "udp4"
		}
	}
	var err error
	conn, err = icmp.ListenPacket(network, local)
	if err != nil {
		return receipt, err
	}
	var native net.PacketConn
	if v4 := conn.IPv4PacketConn(); v4 != nil {
		native = v4.PacketConn
	} else {
		native = conn.IPv6PacketConn().PacketConn
	}
	raw, err := native.(syscall.Conn).SyscallConn()
	if err != nil {
		return receipt, err
	}
	internet.ControllersLock.Lock()
	controllers := slices.Clone(internet.Controllers)
	internet.ControllersLock.Unlock()
	controllerNetwork := network
	if !datagram {
		controllerNetwork = "ip6"
		if request.Destination.Is4() {
			controllerNetwork = "ip4"
		}
	}
	// Native controllers receive a socket family and IP:port address. Port zero
	// preserves their endpoint/loopback parsing; ICMP has no transport port.
	controllerAddress := net.JoinHostPort(request.Destination.String(), "0")
	for _, control := range controllers {
		if err := ctx.Err(); err != nil {
			return receipt, err
		}
		if err := control(controllerNetwork, controllerAddress, raw); err != nil {
			return receipt, err
		}
	}
	resultErr = exchangeICMPEcho(ctx, conn, request.Destination, payload, datagram, &receipt)
	return receipt, resultErr
}

func exchangeICMPEcho(ctx context.Context, conn net.PacketConn, destination netip.Addr, payload []byte, datagram bool, receipt *ICMPEchoReceipt) error {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	protocol, requestType, replyType := 58, icmp.Type(ipv6.ICMPTypeEchoRequest), icmp.Type(ipv6.ICMPTypeEchoReply)
	if destination.Is4() {
		protocol, requestType, replyType = 1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	}
	id := int(binary.BigEndian.Uint16(payload[:2]))
	wire, err := (&icmp.Message{Type: requestType, Body: &icmp.Echo{ID: id, Seq: 1, Data: payload}}).Marshal(nil)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var peer net.Addr = &net.IPAddr{IP: destination.AsSlice()}
	if datagram {
		peer = &net.UDPAddr{IP: destination.AsSlice()}
	}
	started := time.Now()
	n, err := conn.WriteTo(wire, peer)
	receipt.WrittenBytes = &n
	if err != nil {
		return err
	}
	if n != len(wire) {
		return io.ErrShortWrite
	}
	buffer := make([]byte, 65536)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, addr, readErr := conn.ReadFrom(buffer)
		observed := time.Since(started)
		var ip net.IP
		switch addr := addr.(type) {
		case *net.IPAddr:
			ip = addr.IP
		case *net.UDPAddr:
			ip = addr.IP
		}
		source, _ := netip.AddrFromSlice(ip)
		message, parseErr := icmp.ParseMessage(protocol, buffer[:n])
		if parseErr == nil && message.Type == replyType && message.Code == 0 && source.Unmap() == destination {
			if echo, ok := message.Body.(*icmp.Echo); ok && echo.Seq == 1 && (datagram || echo.ID == id) && bytes.Equal(echo.Data, payload) {
				// Raw IPv4 sockets may expose packets before ICMP checksum
				// validation. Reuse native marshaling for the matched frame.
				if !datagram && destination.Is4() {
					valid, err := message.Marshal(nil)
					if err != nil || !bytes.Equal(valid, buffer[:n]) {
						if readErr != nil {
							return readErr
						}
						continue
					}
				}
				receipt.ReplyBytes, receipt.ReplySource, receipt.RoundTrip = n, source.Unmap(), &observed
				return readErr
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}
