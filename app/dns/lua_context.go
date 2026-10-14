package dns

import (
	"context"
	"github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
)

type resolverContextKey struct{}

// WithLuaDNS admits native router work with an opaque exact resolver identity.
func WithLuaDNS(ctx context.Context, client featuredns.Client, work func(context.Context, any) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := client.(*DNS)
	if !ok || s == nil {
		return work(ctx, nil)
	}
	r, ctx, finish, err := s.begin(ctx, nil)
	if err != nil {
		return err
	}
	defer finish()
	return work(ctx, r)
}

// query accepts either the native resolver or one exact ordered server. Keeping
// admission here protects saved Lua callbacks used outside the outer operation.
func (r *resolver) query(ctx context.Context, client *Client, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	_, ctx, finish, err := r.owner.begin(ctx, r)
	if err != nil {
		return nil, 0, err
	}
	defer finish()
	if client != nil {
		return client.QueryIP(ctx, domain, option)
	}
	return r.lookupIP(ctx, domain, option)
}
