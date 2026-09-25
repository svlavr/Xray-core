package dokodemo

import (
	"context"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DokodemoDoor)
		err := core.RequireFeatures(ctx, func(pm policy.Manager, sm stats.Manager) error {
			d.statsManager = sm
			return d.Init(config.(*Config), pm, session.SockoptFromContext(ctx))
		})
		return d, err
	}))
}

type DokodemoDoor struct {
	policyManager  policy.Manager
	statsManager   stats.Manager
	config         *Config
	rewriteAddress net.Address
	rewritePort    net.Port
	portMap        map[string]string
	sockopt        *session.Sockopt
}

// Init initializes the DokodemoDoor instance with necessary parameters.
func (d *DokodemoDoor) Init(config *Config, pm policy.Manager, sockopt *session.Sockopt) error {
	if len(config.AllowedNetworks) == 0 {
		return errors.New("no network specified")
	}
	d.config = config
	d.rewriteAddress = config.GetPredefinedAddress()
	d.rewritePort = net.Port(config.RewritePort)
	d.portMap = config.PortMap
	d.policyManager = pm
	d.sockopt = sockopt

	return nil
}

// Network implements proxy.Inbound.
func (d *DokodemoDoor) Network() []net.Network {
	if slices.Contains(d.config.AllowedNetworks, net.Network_TCP) {
		return append(d.config.AllowedNetworks, net.Network_UNIX)
	}
	return d.config.AllowedNetworks
}

func (d *DokodemoDoor) policy() policy.Session {
	config := d.config
	p := d.policyManager.ForLevel(config.UserLevel)
	return p
}

// Process implements proxy.Inbound.
func (d *DokodemoDoor) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	errors.LogDebug(ctx, "processing connection from: ", conn.RemoteAddr())
	// forward to TCP if from UNIX
	if network == net.Network_UNIX {
		network = net.Network_TCP
	}
	dest := net.Destination{
		Network: network,
		Address: d.rewriteAddress,
		Port:    d.rewritePort,
	}

	if !d.config.FollowRedirect {
		host, port, err := net.SplitHostPort(conn.LocalAddr().String())
		if dest.Address == nil {
			if err != nil {
				dest.Address = net.DomainAddress("localhost")
			} else {
				if strings.Contains(host, ".") {
					dest.Address = net.LocalHostIP
				} else {
					dest.Address = net.LocalHostIPv6
				}
			}
		}
		if dest.Port == 0 && port != "" {
			dest.Port = net.Port(common.Must2(strconv.Atoi(port)))
		}
		if d.portMap != nil && d.portMap[port] != "" {
			h, p, _ := net.SplitHostPort(d.portMap[port])
			if len(h) > 0 {
				dest.Address = net.ParseAddress(h)
			}
			if len(p) > 0 {
				dest.Port = net.Port(common.Must2(strconv.Atoi(p)))
			}
		}
	}

	destinationOverridden := false
	if d.config.FollowRedirect {
		outbounds := session.OutboundsFromContext(ctx)
		if len(outbounds) > 0 {
			ob := outbounds[len(outbounds)-1]
			if ob.Target.IsValid() {
				dest = ob.Target
				destinationOverridden = true
			}
		}
		iConn := stat.TryUnwrapStatsConn(conn)
		if tlsConn, ok := iConn.(tls.Interface); ok && !destinationOverridden {
			if serverName := tlsConn.HandshakeContextServerName(ctx); serverName != "" {
				dest.Address = net.DomainAddress(serverName)
				destinationOverridden = true
				ctx = session.ContextWithMitmServerName(ctx, serverName)
			}
			if tlsConn.NegotiatedProtocol() != "h2" {
				ctx = session.ContextWithMitmAlpn11(ctx, true)
			}
		}
	}
	if !dest.IsValid() || dest.Address == nil {
		return errors.New("unable to get destination")
	}

	inbound := session.InboundFromContext(ctx)
	inbound.Name = "dokodemo-door"
	inbound.CanSpliceCopy = 1
	inbound.User = &protocol.MemoryUser{
		Level: d.config.UserLevel,
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "received request for ", conn.RemoteAddr())

	var reader buf.Reader
	if dest.Network == net.Network_TCP {
		reader = buf.NewReader(conn)
	} else {
		reader = buf.NewPacketReader(conn)
	}

	var writer buf.Writer
	var packetWriter *PacketWriter
	if network == net.Network_TCP {
		writer = buf.NewWriter(conn)
	} else {
		// if we are in TPROXY mode, use linux's udp forging functionality
		if !destinationOverridden {
			writer = &buf.SequentialWriter{Writer: conn}
		} else {
			back := conn.RemoteAddr().(*net.UDPAddr)
			if !dest.Address.Family().IsIP() {
				if len(back.IP) == 4 {
					dest.Address = net.AnyIP
				} else {
					dest.Address = net.AnyIPv6
				}
			}
			addr := &net.UDPAddr{
				IP:   dest.Address.IP(),
				Port: int(dest.Port),
			}
			var mark int
			if d.sockopt != nil {
				mark = int(d.sockopt.Mark)
			}
			pConn, err := FakeUDP(addr, mark)
			if err != nil {
				return err
			}
			writer = NewPacketWriter(pConn, &dest, mark, back)
			packetWriter = writer.(*PacketWriter)
		}
	}

	link := &transport.Link{Reader: reader, Writer: writer}
	var finish func()
	if network == net.Network_TCP && dest.Network == net.Network_TCP {
		ctx, finish = proxy.ObserveTCP(ctx, d.statsManager, conn, dest, link)
	} else if network == net.Network_UDP && dest.Network == net.Network_UDP {
		ctx, finish = proxy.ObserveUDP(ctx, d.statsManager, conn, dest, link)
	}
	if finish != nil {
		defer finish()
	}
	if packetWriter != nil {
		defer packetWriter.Close()
	} // before observation can finish
	if err := dispatcher.DispatchLink(
		ctx, dest, link,
	); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	return nil // Unlike Dispatch(), DispatchLink() will not return until the outbound finishes Process()
}

func NewPacketWriter(conn net.PacketConn, d *net.Destination, mark int, back *net.UDPAddr) buf.Writer {
	writer := &PacketWriter{
		conn:  conn,
		conns: make(map[net.Destination]net.PacketConn),
		mark:  mark,
		back:  back,
	}
	writer.conns[*d] = conn
	return writer
}

type PacketWriter struct {
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	conn      net.PacketConn
	conns     map[net.Destination]net.PacketConn
	mark      int
	back      *net.UDPAddr
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writeMultiBuffer(mb, nil)
}

func (w *PacketWriter) writeMultiBuffer(mb buf.MultiBuffer, receipt stats.Exchange) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var err error
		if b.UDP != nil && b.UDP.Address.Family().IsIP() {
			conn, openErr := w.packetConn(b.UDP)
			if openErr != nil {
				b.Release()
				if openErr == io.ErrClosedPipe {
					buf.ReleaseMulti(mb)
					return openErr
				}
				errors.LogInfo(context.Background(), openErr.Error())
				continue
			}
			n, writeErr := conn.WriteTo(b.Bytes(), w.back)
			err = writeErr
			if receipt != nil {
				proxy.RecordUnframedPacketWrite(receipt, int(b.Len()), n, err)
			}
			if err != nil {
				errors.LogInfo(context.Background(), err.Error())
				w.retire(*b.UDP, conn)
			}
			b.Release()
		} else {
			conn, openErr := w.packetConn(nil)
			if openErr != nil {
				b.Release()
				buf.ReleaseMulti(mb)
				return openErr
			}
			n, writeErr := conn.WriteTo(b.Bytes(), w.back)
			err = writeErr
			if receipt != nil {
				proxy.RecordUnframedPacketWrite(receipt, int(b.Len()), n, err)
			}
			b.Release()
			if err != nil {
				buf.ReleaseMulti(mb)
				return err
			}
		}
	}
	return nil
}

func (w *PacketWriter) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		conns := w.conns
		w.conns = nil
		w.mu.Unlock()
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
	})
	return nil
}

func (w *PacketWriter) packetConn(destination *net.Destination) (net.PacketConn, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	conn := w.conn
	if destination != nil {
		conn = w.conns[*destination]
	}
	w.mu.Unlock()
	if conn != nil || destination == nil {
		return conn, nil
	}
	conn, err := FakeUDP(&net.UDPAddr{IP: destination.Address.IP(), Port: int(destination.Port)}, w.mark)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		conn.Close()
		return nil, io.ErrClosedPipe
	}
	if current := w.conns[*destination]; current != nil {
		w.mu.Unlock()
		conn.Close()
		return current, nil
	}
	w.conns[*destination] = conn
	w.mu.Unlock()
	return conn, nil
}

func (w *PacketWriter) retire(destination net.Destination, conn net.PacketConn) {
	w.mu.Lock()
	owned := w.conns[destination] == conn
	if owned {
		delete(w.conns, destination)
	}
	w.mu.Unlock()
	if owned {
		conn.Close()
	}
}

func (w *PacketWriter) WithWriterReceipt(receipt stats.Exchange) buf.Writer {
	return &inspectionPacketWriter{PacketWriter: w, receipt: receipt}
}

type inspectionPacketWriter struct {
	*PacketWriter
	receipt stats.Exchange
}

func (w *inspectionPacketWriter) WriterReceipt() stats.Exchange { return w.receipt }
func (w *inspectionPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.PacketWriter.writeMultiBuffer(mb, w.receipt)
}
