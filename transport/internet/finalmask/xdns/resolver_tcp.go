package xdns

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type TCPResolver struct {
	dest   net.Destination
	dialer *finalmask.Dialer

	conn    net.Conn
	tcpAddr *net.TCPAddr
	udpAddr *net.UDPAddr

	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewTCPResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	dest, err := net.ParseDestination("tcp:" + config.Addr)
	if err != nil {
		return nil, err
	}
	r := &TCPResolver{
		dest:    dest,
		dialer:  dialer,
		readCh:  make(chan []byte),
		closeCh: make(chan struct{}),
	}
	if err := r.dial(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *TCPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *TCPResolver) dial() error {
	if r.closed() {
		return errors.New("closed")
	}
	if r.conn != nil {
		return nil
	}
	conn, err := r.dialer.DialTCP(r.dest)
	if err != nil {
		return err
	}
	r.conn = conn
	r.tcpAddr = conn.RemoteAddr().(*net.TCPAddr)
	r.udpAddr = &net.UDPAddr{IP: r.tcpAddr.IP, Port: r.tcpAddr.Port}
	r.wg.Add(1)
	go r.recv(conn)
	return nil
}

func (r *TCPResolver) recv(conn net.Conn) {
	defer r.wg.Done()

	var prefix [2]byte
	for {
		_, err := io.ReadFull(conn, prefix[:])
		if err != nil {
			break
		}
		n := int(binary.BigEndian.Uint16(prefix[:]))
		if n == 0 {
			continue
		}
		p := poolDNSMessage.Get().([]byte)
		_, err = io.ReadFull(conn, p[:n])
		if err != nil {
			poolDNSMessage.Put(p[:cap(p)])
			break
		}
		select {
		case <-r.closeCh:
			poolDNSMessage.Put(p[:cap(p)])
		case r.readCh <- p[:n]:
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_ = conn.Close()
	r.conn = nil
}

func (r *TCPResolver) Addr() *net.UDPAddr {
	return r.udpAddr
}

func (r *TCPResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		poolDNSMessage.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *TCPResolver) Send(p []byte) {
	if len(p) == 0 || len(p) > maxDNSMessageSize {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dial() != nil {
		return
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(p)))
	if n, err := r.conn.Write(prefix[:]); err != nil || n != len(prefix) {
		_ = r.conn.Close()
		return
	}
	if n, err := r.conn.Write(p); err != nil || n != len(p) {
		_ = r.conn.Close()
	}
}

func (r *TCPResolver) Close() {
	r.mu.Lock()
	if r.closed() {
		r.mu.Unlock()
		return
	}
	close(r.closeCh)
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	r.wg.Wait()
	close(r.readCh)
}
