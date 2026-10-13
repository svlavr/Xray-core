package dns

import (
	"context"

	"github.com/xtls/xray-core/common/net"
)

// SystemDNSGateway is an optional serving capability of the actual routed
// outbound proxy, independent of the selected Client and its SystemDNSClient
// lease. A nil result certifies that its full-message callback path is ready to
// serve the exact advertised destination and protocol, not merely that a type
// was registered or an unrelated listener exists. Upstream health is not required.
// Implementations must perform a bounded check, honor ctx cancellation and avoid
// starting background work whose lifetime escapes this call. Admission does not
// acquire the service lifetime; composition owns service Close and OS revert.
type SystemDNSGateway interface {
	VerifySystemDNS(ctx context.Context, destination net.Destination) error
}

// SystemDNSClient is an optional admission capability for a client selected
// before the platform redirects system DNS into the core. It must account for
// every resolver path, including bootstrap, and deny a recursive or unavailable
// path. This capability does not prove that the advertised DNS endpoint serves.
type SystemDNSClient interface {
	Client
	MayUseSystemResolver() bool

	// AcquireSystemDNS keeps nonrecursive resolver paths available until release.
	// On success release must be non-nil. Hold it through OS takeover and release
	// only after successful revert. Confirmed disappearance of the owned link
	// suffices only where the platform proves its DNS settings vanish with that
	// link (Linux); FreeBSD resolvconf file entries require explicit revert.
	// The caller separately orders feature/service Close; a lease is not Close.
	AcquireSystemDNS() (release func(), err error)
}
