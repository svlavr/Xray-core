package udp

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName,
		func(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
			var sockopt *internet.SocketConfig
			if streamSettings != nil {
				sockopt = streamSettings.SocketSettings
			}
			conn, err := internet.DialSystem(ctx, dest, sockopt)
			if err != nil {
				return nil, err
			}

			if streamSettings != nil && streamSettings.UdpmaskManager != nil {
				pktConn, udpAddr, err := internet.PacketConnView(conn)
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				newConn, err := streamSettings.UdpmaskManager.WrapPacketConnClientContext(ctx, pktConn)
				if err != nil {
					return nil, errors.New("mask err").Base(err)
				}
				pktConn = newConn
				conn = &internet.PacketConnWrapper{
					PacketConn: pktConn,
					Dest:       udpAddr,
				}
			}

			return conn, nil
		}))
}
