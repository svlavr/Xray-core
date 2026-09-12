// Package natpmp is a context-aware adaptation of github.com/jackpal/go-nat-pmp v1.0.2.
package natpmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type (
	Client                   struct{ gateway *net.UDPAddr }
	GetExternalAddressResult struct {
		SecondsSinceStartOfEpoc uint32
		ExternalIPAddress       [4]byte
	}
)

type AddPortMappingResult struct {
	SecondsSinceStartOfEpoc      uint32
	InternalPort                 uint16
	MappedExternalPort           uint16
	PortMappingLifetimeInSeconds uint32
}

func NewClient(gateway net.IP) *Client {
	return newClient(&net.UDPAddr{IP: gateway, Port: 5351})
}

func newClient(gateway *net.UDPAddr) *Client { return &Client{gateway: gateway} }

func (c *Client) GetExternalAddress() (*GetExternalAddressResult, error) {
	return c.GetExternalAddressContext(context.Background())
}

func (c *Client) GetExternalAddressContext(ctx context.Context) (*GetExternalAddressResult, error) {
	r, err := c.rpc(ctx, []byte{0, 0}, 12)
	if err != nil {
		return nil, err
	}
	var out GetExternalAddressResult
	out.SecondsSinceStartOfEpoc = binary.BigEndian.Uint32(r[4:8])
	copy(out.ExternalIPAddress[:], r[8:12])
	return &out, nil
}

func (c *Client) AddPortMapping(protocol string, internal, external, lifetime int) (*AddPortMappingResult, error) {
	return c.AddPortMappingContext(context.Background(), protocol, internal, external, lifetime)
}

func (c *Client) AddPortMappingContext(ctx context.Context, protocol string, internal, external, lifetime int) (*AddPortMappingResult, error) {
	op := byte(1)
	if protocol == "tcp" {
		op = 2
	}
	if protocol != "udp" && protocol != "tcp" {
		return nil, fmt.Errorf("unknown protocol %q", protocol)
	}
	if internal < 0 || internal > int(^uint16(0)) || external < 0 || external > int(^uint16(0)) || lifetime < 0 || uint64(lifetime) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("NAT-PMP mapping argument out of range")
	}
	m := make([]byte, 12)
	m[1] = op
	binary.BigEndian.PutUint16(m[4:], uint16(internal))
	binary.BigEndian.PutUint16(m[6:], uint16(external))
	binary.BigEndian.PutUint32(m[8:], uint32(lifetime))
	r, err := c.rpc(ctx, m, 16)
	if err != nil {
		return nil, err
	}
	return &AddPortMappingResult{
		SecondsSinceStartOfEpoc:      binary.BigEndian.Uint32(r[4:8]),
		InternalPort:                 binary.BigEndian.Uint16(r[8:10]),
		MappedExternalPort:           binary.BigEndian.Uint16(r[10:12]),
		PortMappingLifetimeInSeconds: binary.BigEndian.Uint32(r[12:16]),
	}, nil
}

func (c *Client) rpc(ctx context.Context, msg []byte, size int) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, c.gateway)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-stopped }()
	for delay := 250 * time.Millisecond; ; delay *= 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := conn.SetDeadline(time.Now().Add(delay)); err != nil {
			return nil, err
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, err
		}
		buf := make([]byte, size)
		n, addr, err := conn.ReadFromUDP(buf)
		if err == nil && addr.IP.Equal(c.gateway.IP) && addr.Port == c.gateway.Port {
			if n != size || buf[0] != 0 || buf[1] != msg[1]|0x80 || binary.BigEndian.Uint16(buf[2:4]) != 0 {
				return nil, fmt.Errorf("invalid NAT-PMP response")
			}
			return buf, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if delay >= 64*time.Second {
			return nil, err
		}
	}
}
