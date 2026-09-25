package hysteria

import (
	"context"
	go_errors "errors"
	"io"
	"math/rand"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*hysteria.Config); !ok {
		return nil, errors.New("not hysteria transport")
	}
	if config.Server == nil {
		return nil, errors.New(`no target server found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	return &Client{
		server:        server,
		policyManager: p,
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "hysteria"
	ob.CanSpliceCopy = 3
	target := ob.Target
	ordinaryTarget := target.Network == net.Network_TCP || target.Network == net.Network_UDP
	if target.Address.Family().IsDomain() && target.Address.Domain() == "v1.mux.cool" {
		ordinaryTarget = false
	}
	observation := proxy.ClaimObservedEndpoint(ctx, link.Reader, ordinaryTarget)
	if observation != nil {
		observation.Exchange.Effective(target)
	}

	conn, err := dialer.Dial(hysteria.ContextWithDatagram(ctx, target.Network == net.Network_UDP), c.server.Destination)
	if err != nil {
		return errors.New("failed to find an available destination").AtWarning().Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", target.Network, ":", c.server.Destination.NetAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	if newCtx != nil {
		ctx = newCtx
	}

	if target.Network == net.Network_TCP {
		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
			err := WriteTCPRequest(bufferedWriter, target.NetAddr())
			if err != nil {
				return errors.New("failed to write request").Base(err)
			}
			if err := bufferedWriter.SetBuffered(false); err != nil {
				return err
			}
			return buf.Copy(link.Reader, bufferedWriter, buf.UpdateActivity(timer))
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			ok, msg, err := ReadTCPResponse(conn)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New(msg)
			}
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	if target.Network == net.Network_UDP {
		iConn := stat.TryUnwrapStatsConn(conn)
		_, ok := iConn.(*hysteria.InterConn)
		if !ok {
			return errors.New("udp requires hysteria udp transport")
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			writer := &UDPWriter{
				writer: conn,
				addr:   target.NetAddr(),
			}

			if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP request").Base(err)
			}

			return nil
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			reader := &UDPReader{
				reader: conn,
				df:     &Defragger{},
			}

			if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP response").Base(err)
			}

			return nil
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type UDPWriter struct {
	writer io.Writer
	addr   string
	buf    [buf.Size]byte
}

func (w *UDPWriter) SendMessage(msg *UDPMessage) error {
	_, err := w.sendMessage(msg)
	return err
}

func (w *UDPWriter) sendMessage(msg *UDPMessage) (int, error) {
	size := msg.Size()
	message := w.buf[:]
	if size > len(message) {
		message = make([]byte, size)
	}
	msgN := msg.Serialize(message)
	if msgN != size {
		return 0, errors.New("failed to serialize UDP message")
	}
	n, err := w.writer.Write(message[:msgN])
	if err != nil {
		return n, err
	}
	if n != msgN {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (w *UDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writeMultiBuffer(mb, nil)
}

func (w *UDPWriter) writeMultiBuffer(mb buf.MultiBuffer, receipt stats.Exchange) error {
	for i, b := range mb {
		if err := w.writePacket(b, receipt); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

func (w *UDPWriter) writePacket(b *buf.Buffer, receipt stats.Exchange) (err error) {
	complete, partial := false, false
	if receipt != nil {
		defer func() { proxy.RecordPacketOutcome(receipt, uint64(b.Len()), complete, partial, err) }()
	}
	addr := w.addr
	if b.UDP != nil {
		addr = b.UDP.NetAddr()
	}

	msg := &UDPMessage{
		SessionID: 0,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      addr,
		Data:      b.Bytes(),
	}

	n, err := w.sendMessage(msg)
	complete, partial = n == msg.Size(), n > 0
	var errTooLarge *quic.DatagramTooLargeError
	if go_errors.As(err, &errTooLarge) {
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
		if len(fMsgs) == 0 {
			return errors.New("failed to fragment UDP message")
		}
		all := true
		for i, fMsg := range fMsgs {
			n, sendErr := w.sendMessage(&fMsg)
			all = all && n == fMsg.Size()
			partial = partial || n > 0
			if i == len(fMsgs)-1 {
				complete = complete || all
			}
			err := sendErr
			if err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}
	return nil
}

type inspectionUDPWriter struct {
	*UDPWriter
	receipt stats.Exchange
}

func (w *inspectionUDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.UDPWriter.writeMultiBuffer(mb, w.receipt)
}

func (w *UDPWriter) WithWriterReceipt(flow stats.Exchange) buf.Writer {
	if flow == nil {
		return w
	}
	return &inspectionUDPWriter{UDPWriter: w, receipt: flow}
}

type UDPReader struct {
	reader   io.Reader
	df       *Defragger
	firstBuf *buf.Buffer
}

func (r *UDPReader) ReadFrom(p []byte) (n int, addr *net.Destination, err error) {
	for {
		var packet [1500]byte

		n, err := r.reader.Read(packet[:])
		if err != nil {
			return 0, nil, err
		}

		msg, err := ParseUDPMessage(packet[:n])
		if err != nil {
			continue
		}

		dfMsg := r.df.Feed(msg)
		if dfMsg == nil {
			continue
		}

		dest, err := net.ParseDestination("udp:" + dfMsg.Addr)
		if err != nil {
			continue
		}

		if len(p) < len(dfMsg.Data) {
			continue
		}

		return copy(p, dfMsg.Data), &dest, nil
	}
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.firstBuf != nil {
		mb := buf.MultiBuffer{r.firstBuf}
		r.firstBuf = nil
		return mb, nil
	}
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := r.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	b.UDP = addr
	return buf.MultiBuffer{b}, nil
}
