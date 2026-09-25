package core

import (
	"bytes"
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/udp"
)

// CreateObject creates a new object based on the given Xray instance and config. The Xray instance may be nil.
func CreateObject(v *Instance, config interface{}) (interface{}, error) {
	ctx := v.ctx
	if v != nil {
		ctx = toContext(v.ctx, v)
	}
	return common.CreateObject(ctx, config)
}

// StartInstance starts a new Xray instance with given serialized config.
// By default Xray only support config in protobuf format, i.e., configFormat = "protobuf". Caller need to load other packages to add JSON support.
//
// xray:api:stable
func StartInstance(configFormat string, configBytes []byte) (*Instance, error) {
	config, err := LoadConfig(configFormat, bytes.NewReader(configBytes))
	if err != nil {
		return nil, err
	}
	instance, err := New(config)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, err
	}
	return instance, nil
}

// Dial provides an easy way for upstream caller to create net.Conn through Xray.
// It dispatches the request to the given destination by the given Xray instance.
// Since it is under a proxy context, the LocalAddr() and RemoteAddr() in returned net.Conn
// will not show real addresses being used for communication.
//
// xray:api:stable
func Dial(ctx context.Context, v *Instance, dest net.Destination) (net.Conn, error) {
	ctx = toContext(ctx, v)
	kind := stats.FlowKindTCP
	if dest.Network == net.Network_UDP {
		kind = stats.FlowKindUDPAssociation
	}
	ctx, observation := beginAPIObservation(ctx, v, dest, kind, true)

	dispatcher := v.GetFeature(routing.DispatcherType())
	if dispatcher == nil {
		if observation != nil {
			observation.Close()
		}
		return nil, errors.New("routing.Dispatcher is not registered in Xray core")
	}

	r, err := dispatcher.(routing.Dispatcher).Dispatch(ctx, dest)
	if err != nil {
		if observation != nil {
			observation.Close()
		}
		return nil, err
	}
	var readerOpt cnc.ConnectionOption
	if dest.Network == net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(r.Reader)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(r.Reader)
	}
	conn := cnc.NewConnection(cnc.ConnectionInputMulti(r.Writer), readerOpt)
	if observation == nil {
		return conn, nil
	}
	observation.attach(conn)
	return &inspectedAPIConn{Conn: conn, observation: observation}, nil
}

// DialUDP provides a way to exchange UDP packets through Xray instance to remote servers.
// Since it is under a proxy context, the LocalAddr() in returned PacketConn will not show the real address.
//
// TODO: SetDeadline() / SetReadDeadline() / SetWriteDeadline() are not implemented.
//
// xray:api:beta
func DialUDP(ctx context.Context, v *Instance) (net.PacketConn, error) {
	ctx = toContext(ctx, v)
	ctx, observation := beginAPIObservation(ctx, v, net.Destination{}, stats.FlowKindUDPAssociation, false)

	dispatcher := v.GetFeature(routing.DispatcherType())
	if dispatcher == nil {
		if observation != nil {
			observation.Close()
		}
		return nil, errors.New("routing.Dispatcher is not registered in Xray core")
	}
	conn, err := udp.DialDispatcher(ctx, dispatcher.(routing.Dispatcher))
	if err != nil {
		if observation != nil {
			observation.Close()
		}
		return nil, err
	}
	if observation == nil {
		return conn, nil
	}
	observation.attach(conn)
	return &inspectedAPIPacketConn{PacketConn: conn, observation: observation}, nil
}
