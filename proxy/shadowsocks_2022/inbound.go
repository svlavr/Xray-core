package shadowsocks_2022

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Inbound struct {
	networks      []net.Network
	method        *CipherMethod
	psk           []byte
	user          *protocol.MemoryUser
	saltFilter    *antireplay.ReplayFilter[[32]byte]
	udpCodec      *UDPServerCodec
	udpConns      *utils.TypedSyncMap[uint64, *udpConnEntry]
	policyManager policy.Manager
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}

	method, err := GetCipherMethod(config.Method)
	if err != nil {
		return nil, errors.New("unsupported method: ", config.Method).Base(err)
	}

	psk, err := ParseKey(config.Key, method.KeySaltLength)
	if err != nil {
		return nil, err
	}

	udpCodec, err := NewUDPServerCodec(method, psk, 500*time.Second)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	return &Inbound{
		networks:   networks,
		method:     method,
		psk:        psk,
		saltFilter: antireplay.NewMapFilter[[32]byte](60),
		user: &protocol.MemoryUser{
			Email: config.Email,
			Level: uint32(config.Level),
		},
		udpCodec:      udpCodec,
		udpConns:      utils.NewTypedSyncMap[uint64, *udpConnEntry](),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (i *Inbound) Network() []net.Network {
	return i.networks
}

func (i *Inbound) Close() error {
	i.udpConns.Range(func(_ uint64, entry *udpConnEntry) bool { entry.Close(); return true })
	return nil
}

func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022"
	inbound.CanSpliceCopy = 3
	inbound.User = i.user

	if network == net.Network_TCP {
		return i.processTCP(ctx, connection, dispatcher)
	}
	return i.processUDP(packetContext(ctx, connection), connection, dispatcher)
}

func (i *Inbound) processTCP(ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) error {
	defer conn.Close()

	sessionPolicy := i.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err)
	}

	// 1. Single read call for Salt + Fixed-length header chunk per SIP022 §3.1.4
	headerLen := i.method.KeySaltLength + RequestHeaderFixedChunkLength + AEADTagSize
	headerBuf := make([]byte, headerLen)
	n, err := conn.Read(headerBuf)
	if err != nil || n < headerLen {
		ResetTCPConn(conn)
		return errors.New("failed to read complete handshake header")
	}

	var salt [32]byte
	copy(salt[:i.method.KeySaltLength], headerBuf[:i.method.KeySaltLength])
	saltSlice := salt[:i.method.KeySaltLength]
	fixedChunk := headerBuf[i.method.KeySaltLength:]

	reader, reqHeader, err := InitServerStream(conn, i.method, i.psk, saltSlice, salt, fixedChunk, i.saltFilter)
	if err != nil {
		ResetTCPConn(conn)
		return err
	}

	dest := reqHeader.Destination

	writer := NewServerStreamWriter(conn, i.method, i.psk, saltSlice)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  i.user.Email,
	})

	errors.LogInfo(ctx, "tunneling request to ", dest)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	if len(reqHeader.EarlyData) > 0 {
		mb := buf.MergeBytes(nil, reqHeader.EarlyData)
		if err := link.Writer.WriteMultiBuffer(mb); err != nil {
			return err
		}
	}

	return TransportTCP(ctx, i.policyManager.ForLevel(uint32(i.user.Level)), reader, writer, link)
}

func (i *Inbound) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	udpConns := i.udpConns

	reader := buf.NewPacketReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}

		for _, b := range mb {
			decoded, err := i.udpCodec.DecodePacket(b.Bytes())
			if err != nil {
				b.Release()
				continue
			}

			entry, ok := udpConns.Load(decoded.SessionID)
			if !ok {
				sessCtx, cancel := context.WithCancel(packetSessionContext(ctx))
				newEntry := &udpConnEntry{cancel: cancel}
				newEntry.setTransport(conn)
				newEntry.onClose = func() {
					udpConns.CompareAndDelete(decoded.SessionID, newEntry)
				}
				sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
					From:   conn.RemoteAddr(),
					To:     decoded.Destination,
					Status: log.AccessAccepted,
					Email:  i.user.Email,
				})

				link, err := dispatcher.Dispatch(sessCtx, decoded.Destination)
				if err != nil {
					newEntry.Close()
					b.Release()
					continue
				}
				if !newEntry.bind(link) {
					newEntry.Close()
					b.Release()
					continue
				}
				sessionPolicy := i.policyManager.ForLevel(uint32(i.user.Level))
				newEntry.setTimer(signal.CancelAfterInactivity(sessCtx, func() { newEntry.Close() }, sessionPolicy.Timeouts.ConnectionIdle))

				actual, loaded := udpConns.LoadOrStore(decoded.SessionID, newEntry)
				if loaded {
					// Another goroutine/packet beat us to storing, terminate our redundant link
					newEntry.Close()
					entry = actual
				} else {
					entry = newEntry
					if entry.isClosed() {
						udpConns.CompareAndDelete(decoded.SessionID, entry)
						b.Release()
						continue
					}
					go func(sessID uint64, dest net.Destination, cEntry *udpConnEntry) {
						defer cEntry.Close()
						for {
							resMb, err := cEntry.link.Reader.ReadMultiBuffer()
							if err != nil {
								return
							}
							cEntry.timer.Update()
							for _, rb := range resMb {
								responseDest := dest
								if rb.UDP != nil {
									responseDest = *rb.UDP
								}

								encPacket, err := i.udpCodec.EncodeServerPacket(sessID, responseDest, rb.Bytes())
								rb.Release()
								if err != nil {
									continue
								}
								n, writeErr := cEntry.writePacket(encPacket)
								if writeErr != nil || n != len(encPacket) {
									return
								}
							}
						}
					}(decoded.SessionID, decoded.Destination, entry)
				}
			}

			if entry.isClosed() {
				b.Release()
				continue
			}
			entry.setTransport(conn)
			entry.timer.Update()
			payloadBuf := buf.New()
			payloadBuf.Write(decoded.Payload)
			packetDest := decoded.Destination
			payloadBuf.UDP = &packetDest
			b.Release()
			_ = entry.link.Writer.WriteMultiBuffer(buf.MultiBuffer{payloadBuf})
		}
	}
}
