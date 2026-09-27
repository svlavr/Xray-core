package dns

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common/geodata"
	featuredns "github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

type ApplyResult struct {
	Applied bool
	Err     error
}

type readyDependencyError struct{ name string }

func (e *readyDependencyError) Error() string { return "missing ready DNS dependency: " + e.name }

// ApplyConfig prepares and publishes a fresh resolver in the existing DNS feature.
// Applied remains true when old-resource cleanup fails after publication.
func ApplyConfig(ctx context.Context, client featuredns.Client, config *Config) ApplyResult {
	server, ok := client.(*DNS)
	if !ok || server == nil || server.runtime == nil {
		return ApplyResult{Err: fmt.Errorf("DNS client does not support ApplyConfig")}
	}
	return server.applyConfig(ctx, config)
}

func cloneAndValidateConfig(config *Config) (*Config, error) {
	if config == nil {
		return nil, fmt.Errorf("missing DNS config")
	}
	clone := proto.Clone(config).(*Config)
	if _, ok := QueryStrategy_name[int32(clone.QueryStrategy)]; !ok {
		return nil, fmt.Errorf("unexpected query strategy %d", clone.QueryStrategy)
	}
	validateDomainRule := func(rule *geodata.DomainRule) bool {
		if rule == nil || rule.GetValue() == nil {
			return false
		}
		switch value := rule.GetValue().(type) {
		case *geodata.DomainRule_Geosite:
			return value.Geosite != nil
		case *geodata.DomainRule_Custom:
			return value.Custom != nil
		default:
			return false
		}
	}
	for i, ns := range clone.NameServer {
		if ns == nil || ns.Address == nil || ns.Address.Address == nil {
			return nil, fmt.Errorf("nameserver %d has no address", i)
		}
		if _, ok := QueryStrategy_name[int32(ns.QueryStrategy)]; !ok {
			return nil, fmt.Errorf("nameserver %d has unexpected query strategy %d", i, ns.QueryStrategy)
		}
		for j, rule := range ns.Domain {
			if !validateDomainRule(rule) {
				return nil, fmt.Errorf("nameserver %d has malformed domain rule %d", i, j)
			}
		}
		for _, rules := range [][]*geodata.IPRule{ns.ExpectedIp, ns.UnexpectedIp} {
			for j, rule := range rules {
				if rule == nil || rule.GetValue() == nil {
					return nil, fmt.Errorf("nameserver %d has malformed IP rule %d", i, j)
				}
				switch value := rule.GetValue().(type) {
				case *geodata.IPRule_Geoip:
					if value.Geoip == nil {
						return nil, fmt.Errorf("nameserver %d has empty geodata IP rule %d", i, j)
					}
				case *geodata.IPRule_Custom:
					if value.Custom == nil {
						return nil, fmt.Errorf("nameserver %d has empty custom IP rule %d", i, j)
					}
				default:
					return nil, fmt.Errorf("nameserver %d has unsupported IP rule %d", i, j)
				}
			}
		}
	}
	for i, mapping := range clone.StaticHosts {
		if mapping == nil || !validateDomainRule(mapping.Domain) {
			return nil, fmt.Errorf("static host %d has malformed domain rule", i)
		}
	}
	return clone, nil
}
