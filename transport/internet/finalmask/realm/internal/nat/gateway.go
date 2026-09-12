// Adapted from github.com/libp2p/go-nat at
// 01afc089f138bf26b9f467ccba7f53ac34e0c679 (Apache-2.0).
package nat

import (
	"net"

	"github.com/libp2p/go-netroute"
)

func getDefaultGateway() (net.IP, error) {
	router, err := netroute.New()
	if err != nil {
		return nil, err
	}
	_, ip, _, err := router.Route(net.IPv4zero)
	return ip, err
}
