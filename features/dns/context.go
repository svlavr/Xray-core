package dns

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/net"
)

// ContextClient is an optional DNS lookup entry that preserves caller
// cancellation. The Client interface remains available to existing callers.
type ContextClient interface {
	LookupIPContext(context.Context, string, IPOption) ([]net.IP, uint32, error)
}

func LookupIPContext(ctx context.Context, client Client, domain string, option IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if contextClient, ok := client.(ContextClient); ok {
		return contextClient.LookupIPContext(ctx, domain, option)
	}
	if client == nil {
		return nil, 0, errors.New("DNS client not initialized")
	}
	return client.LookupIP(domain, option)
}
