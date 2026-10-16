package xdns

import (
	"errors"
	"net"
	"sync"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const maxDNSMessageSize = 65535

// DNS-message storage is separate from the application/reassembly pool4K.
var poolDNSMessage = sync.Pool{
	New: func() any {
		return make([]byte, maxDNSMessageSize)
	},
}

type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	Send(p []byte)
	Close()
}

func NewResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	switch config.Type {
	case "tcp":
		return NewTCPResolver(config, dialer)
	case "udp":
		return NewUDPResolver(config, dialer)
	case "https":
		return NewDOHResolver(config, dialer)
	default:
		return nil, errors.New("unknown type")
	}
}
