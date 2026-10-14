package measurement

import (
	"net"
	"net/netip"

	"github.com/xtls/xray-core/common/buf"
)

func packetReadable(conn net.Conn) bool {
	_, socket := conn.(net.PacketConn)
	_, batch := conn.(buf.Reader)
	return socket || batch
}

// Payload is borrowed for the callback. Native and visitor errors remain separate
// so DNS completion and cleanup suppression cannot erase native packet facts.
func readPacketBatch(conn net.Conn, packet []byte, visit func([]byte, netip.AddrPort) error, firstOnly bool) (hadData bool, nativeErr error, visitErr error) {
	if pc, ok := conn.(net.PacketConn); ok {
		n, addr, err := pc.ReadFrom(packet)
		if n > 0 || err == nil || firstOnly {
			var source netip.AddrPort
			if udp, ok := addr.(*net.UDPAddr); ok {
				a := udp.AddrPort()
				source = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
			}
			return n > 0 || err == nil, err, visit(packet[:n], source)
		}
		return false, err, nil
	}
	reader, ok := conn.(buf.Reader)
	if !ok {
		return false, ErrUnsupported, nil
	}
	mb, err := reader.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		var source netip.AddrPort
		if b.UDP != nil && b.UDP.Address.Family().IsIP() {
			if ip, ok := netip.AddrFromSlice(b.UDP.Address.IP()); ok {
				source = netip.AddrPortFrom(ip.Unmap(), uint16(b.UDP.Port))
			}
		}
		if visitErr = visit(b.Bytes(), source); visitErr != nil || firstOnly {
			break
		}
	}
	return len(mb) > 0, err, visitErr
}

// Error-only native multibuffer writers expose supplied size, not acceptance.
func writeUDPPacket(conn net.Conn, packet []byte) (int, bool, error) {
	if writer, ok := conn.(buf.Writer); ok {
		b := buf.NewWithSize(int32(len(packet)))
		_, _ = b.Write(packet)
		return len(packet), false, writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	n, err := conn.Write(packet)
	return n, true, err
}
