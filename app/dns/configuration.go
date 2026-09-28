package dns

import (
	"context"
	"fmt"

	featuredns "github.com/xtls/xray-core/features/dns"
)

type ApplyResult struct {
	Applied bool
	Err     error
}

// ApplyConfig prepares and publishes a fresh resolver in the existing DNS feature.
// Applied remains true when old-resource cleanup fails after publication.
func ApplyConfig(ctx context.Context, client featuredns.Client, config *Config) ApplyResult {
	server, ok := client.(*DNS)
	if !ok || server == nil || server.runtime == nil {
		return ApplyResult{Err: fmt.Errorf("DNS client does not support ApplyConfig")}
	}
	return server.applyConfig(ctx, config)
}
