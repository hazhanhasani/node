package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	tormgr "github.com/pasarguard/node/backend/tor"
	"github.com/pasarguard/node/common"
)

var _ tormgr.XrayAdapter = (*Xray)(nil)

func torOutboundSlice(value any) ([]any, error) {
	if value == nil { return []any{}, nil }
	out, ok := value.([]any)
	if !ok { return nil, fmt.Errorf("xray outbounds has unexpected type %T", value) }
	return out, nil
}

func cloneTorInbound(source *Inbound) (*Inbound, error) {
	if source == nil { return nil, errors.New("base inbound is nil") }
	data, err := json.Marshal(source)
	if err != nil { return nil, fmt.Errorf("clone Tor base inbound: %w", err) }
	var cloned Inbound
	if err := json.Unmarshal(data, &cloned); err != nil { return nil, fmt.Errorf("clone Tor base inbound: %w", err) }
	source.mu.RLock()
	cloned.clients = cloneClients(source.clients)
	source.mu.RUnlock()
	cloned.exclude = false
	return &cloned, nil
}

func stripTorLocation(config *Config, location tormgr.XrayLocation) error {
	filteredInbounds := config.InboundConfigs[:0]
	for _, inbound := range config.InboundConfigs {
		if inbound != nil && inbound.Tag == location.InboundTag { continue }
		filteredInbounds = append(filteredInbounds, inbound)
	}
	config.InboundConfigs = filteredInbounds

	outbounds, err := torOutboundSlice(config.OutboundConfigs)
	if err != nil { return err }
	filteredOutbounds := outbounds[:0]
	for _, raw := range outbounds {
		obj, ok := raw.(map[string]any)
		if ok {
			tag, _ := obj["tag"].(string)
			if tag == location.OutboundTag { continue }
		}
		filteredOutbounds = append(filteredOutbounds, raw)
	}
	config.OutboundConfigs = filteredOutbounds

	if config.RouterConfig != nil {
		filteredRules := config.RouterConfig.RuleList[:0]
		for _, raw := range config.RouterConfig.RuleList {
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil { return fmt.Errorf("decode existing Xray rule: %w", err) }
			ruleTag, _ := obj["ruleTag"].(string)
			outboundTag, _ := obj["outboundTag"].(string)
			if ruleTag == location.RuleTag || outboundTag == location.OutboundTag { continue }
			filteredRules = append(filteredRules, raw)
		}
		config.RouterConfig.RuleList = filteredRules
	}
	return nil
}

// ApplyTorLocation merges only the location-owned inbound/outbound/rule into a
// cloned config. It deliberately reuses the existing base inbound protocol,
// clients, TLS/REALITY and transport settings; only tag/port and egress routing
// are changed. applyConfigWithRestart provides restart health verification and
// rollback to the previous config on any failure.
func (x *Xray) ApplyTorLocation(location tormgr.XrayLocation) error {
	if strings.TrimSpace(location.BaseInboundTag) == "" { return errors.New("Tor base inbound tag is required") }
	candidate, err := x.config.Clone()
	if err != nil { return err }
	if err := stripTorLocation(candidate, location); err != nil { return err }

	var base *Inbound
	for _, inbound := range candidate.InboundConfigs {
		if inbound != nil && inbound.Tag == location.BaseInboundTag { base = inbound; break }
	}
	if base == nil { return fmt.Errorf("Tor base inbound %q not found", location.BaseInboundTag) }
	clone, err := cloneTorInbound(base)
	if err != nil { return err }
	clone.Tag = location.InboundTag
	clone.Port = location.InboundPort
	candidate.InboundConfigs = append(candidate.InboundConfigs, clone)

	outbounds, err := torOutboundSlice(candidate.OutboundConfigs)
	if err != nil { return err }
	outbounds = append(outbounds, map[string]any{
		"tag": location.OutboundTag,
		"protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": location.TorSocksPort}}},
	})
	candidate.OutboundConfigs = outbounds

	if candidate.RouterConfig == nil { return errors.New("xray routing config is nil") }
	ruleBytes, err := json.Marshal(map[string]any{
		"type": "field",
		"inboundTag": []string{location.InboundTag},
		"outboundTag": location.OutboundTag,
		"ruleTag": location.RuleTag,
	})
	if err != nil { return err }
	candidate.RouterConfig.RuleList = append(candidate.RouterConfig.RuleList, json.RawMessage(ruleBytes))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return x.applyConfigWithRestart(ctx, candidate)
}

func (x *Xray) RemoveTorLocation(location tormgr.XrayLocation) error {
	candidate, err := x.config.Clone()
	if err != nil { return err }
	beforeInbounds := len(candidate.InboundConfigs)
	if err := stripTorLocation(candidate, location); err != nil { return err }
	// Removal is idempotent. Avoid restarting Xray when the location was already absent.
	if len(candidate.InboundConfigs) == beforeInbounds {
		outboundExists := false
		if outbounds, err := torOutboundSlice(x.config.OutboundConfigs); err == nil {
			for _, raw := range outbounds {
				if obj, ok := raw.(map[string]any); ok { if tag, _ := obj["tag"].(string); tag == location.OutboundTag { outboundExists = true; break } }
			}
		}
		if !outboundExists { return nil }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return x.applyConfigWithRestart(ctx, candidate)
}

func (x *Xray) VerifyTorRoute(location tormgr.XrayLocation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := x.TestRoute(ctx, &common.TestRouteRequest{
		InboundTag: location.InboundTag,
		Network: "tcp",
		TargetDomain: "example.com",
		TargetPort: 443,
	})
	if err != nil { return err }
	if result.GetOutboundTag() != location.OutboundTag {
		return fmt.Errorf("unexpected Xray route for %s: expected %s, got %s", location.InboundTag, location.OutboundTag, result.GetOutboundTag())
	}
	return nil
}
