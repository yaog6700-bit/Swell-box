package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/swell-app/swellbox/internal/paths"
)

// SwellTunTag is the runtime-injected TUN inbound tag (not written to user config).
const SwellTunTag = "swell-tun"

// PrepareRuntimeConfig reads the user config, injects / normalizes the official
// API + dashboard service, and writes a runtime file the core process will load.
//
// User configs stay untouched; only the generated runtime copy is modified.
// When tunMode is true, a TUN inbound is injected unless the user config already
// has a tun inbound.
func PrepareRuntimeConfig(userConfigPath, runtimePath string, dashboardPort int, tunMode bool) error {
	raw, err := os.ReadFile(userConfigPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse config JSON: %w", err)
	}

	if dashboardPort <= 0 {
		dashboardPort = paths.DefaultPort
	}
	ensureAPIService(root, dashboardPort)
	ensureClashAPI(root, "127.0.0.1:9090")
	ensureCacheFile(root, tunMode)
	// Prefer local rule-set files under workdir (offline-first).
	preferLocalRuleSets(root)
	// sing-box ≥1.14 deprecated the implicit default HTTP client across ALL
	// HTTP-using components (remote rule-sets, DoH DNS, ACME, Clash API, etc.).
	// Always inject an explicit http_clients entry + route.default_http_client.
	ensureHTTPClient(root)
	// sing-box ≥1.12 rejects detour:"direct" on DNS servers.
	stripDirectDNSDetour(root)
	// Empty selector/urltest (common in full templates before subscription fills
	// them) → fill only in this runtime copy. User file on disk is never changed.
	if _, err := sanitizeOutboundGroups(root); err != nil {
		return err
	}
	// URLTest groups with real nodes → selector so Dashboard shows a pickable
	// member list (Singapore → node A / node B), not only the group name.
	convertFilledURLTestToSelector(root)
	// Also surface nested leaves on parent selectors (Manual first row).
	exposeNestedLeavesInSelectors(root)
	applyTunMode(root, tunMode)
	if tunMode {
		disableAAAAInject(root)
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(runtimePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(runtimePath, out, 0o644)
}

// applyTunMode injects or removes TUN inbounds on the runtime config only.
//
// When disabled: strip ALL tun inbounds (including those from imported full
// configs). Otherwise a user JSON with "type":"tun" always requires admin and
// the core never starts → Dashboard cannot open.
// When enabled: keep user tun if present, else inject SwellTunTag.
func applyTunMode(root map[string]any, enabled bool) {
	inbounds, _ := root["inbounds"].([]any)
	var kept []any
	for _, item := range inbounds {
		m, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		// Drop our managed injection always; rebuild below if needed.
		if tag, _ := m["tag"].(string); tag == SwellTunTag {
			continue
		}
		// When tray TUN is off, also drop any imported tun inbound so mixed
		// proxy can start without elevation.
		if !enabled {
			if t, _ := m["type"].(string); t == "tun" {
				continue
			}
		}
		kept = append(kept, item)
	}
	inbounds = kept

	if enabled && !hasUserTun(inbounds) {
		// Align with AnywhereWinUI / Swell Proxy TUN that works with IPv6 MTP:
		//  - dual-stack address (IPv4-only + strict_route blackholes v6 on Windows)
		//  - strict_route=false (WFP "unsupported network unreachable" / WSAEACCES)
		//  - exclude LAN/ULA + bootstrap DNS from the TUN route table
		//  - bind "direct" to the physical NIC (see bindDirectOutbounds)
		tunInbound := map[string]any{
			"type": "tun",
			"tag":  SwellTunTag,
			"address": []any{
				"172.19.0.1/30",
				"fdfe:dcba:9876::1/126",
			},
			"mtu":                        9000,
			"auto_route":                 true,
			"strict_route":               false,
			"stack":                      "mixed",
			"sniff":                      true,
			"sniff_override_destination": true,
			"route_exclude_address": []any{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"100.64.0.0/10",
				"169.254.0.0/16",
				"127.0.0.0/8",
				"fc00::/7",
				"fe80::/10",
				// Bootstrap DNS IPs — keep resolver traffic off the TUN table.
				"223.5.5.5/32",
				"114.114.114.114/32",
				"8.8.8.8/32",
				"1.1.1.1/32",
			},
		}
		// macOS only allows utun* interface names — omit interface_name and
		// let sing-box auto-assign one (it picks the next available utunN).
		inbounds = append(inbounds, tunInbound)
	}

	if enabled {
		// Avoid routing loops when TUN takes over the default route.
		route, _ := root["route"].(map[string]any)
		if route == nil {
			route = map[string]any{}
		}
		route["auto_detect_interface"] = true
		if ifName := defaultOutboundInterface(); ifName != "" {
			// Prefer explicit default when detection works (matches Anywhere).
			route["default_interface"] = ifName
			bindDirectOutbounds(root, ifName)
		}
		root["route"] = route
	}
	root["inbounds"] = inbounds
}

// bindDirectOutbounds sets bind_interface on all outbounds that make real
// network connections so that TUN-mode traffic always leaves via the physical
// NIC instead of re-entering the TUN interface and causing a routing loop.
//
// This covers:
//   - direct outbounds (return-path traffic)
//   - all leaf proxy outbounds (shadowsocks, vmess, vless, trojan, hysteria2,
//     wireguard, tuic, etc.) — their connections to the remote proxy server
//     must bypass TUN or they loop back into sing-box indefinitely.
//
// selector/urltest/block/dns outbounds are skipped because they have no
// network layer of their own.
func bindDirectOutbounds(root map[string]any, ifName string) {
	if ifName == "" {
		return
	}
	// Types that open real sockets and must be bound to the physical NIC.
	isBindable := func(t string) bool {
		switch t {
		case "direct",
			"shadowsocks", "shadowsocksr",
			"vmess", "vless",
			"trojan", "trojan-go",
			"hysteria", "hysteria2",
			"tuic",
			"wireguard",
			"ssh",
			"http", "socks":
			return true
		}
		return false
	}

	outbounds, _ := root["outbounds"].([]any)
	for i, item := range outbounds {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["type"].(string)
		if !isBindable(t) {
			continue
		}
		if _, has := m["bind_interface"]; has {
			continue
		}
		// Windows often fails to route IPv6 sockets bound to an interface index
		// if the default IPv6 route is on a different interface.
		if server, ok := m["server"].(string); ok && strings.Contains(server, ":") {
			continue
		}
		m["bind_interface"] = ifName
		outbounds[i] = m
	}
	root["outbounds"] = outbounds
}

func hasUserTun(inbounds []any) bool {
	for _, item := range inbounds {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t == "tun" {
			return true
		}
	}
	return false
}

func ensureAPIService(root map[string]any, port int) {
	services, _ := root["services"].([]any)
	var found bool
	for i, item := range services {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["type"].(string)
		if t != "api" {
			continue
		}
		found = true
		if _, ok := m["listen"]; !ok {
			m["listen"] = "127.0.0.1"
		}
		m["listen_port"] = port
		dash, _ := m["dashboard"].(map[string]any)
		if dash == nil {
			m["dashboard"] = map[string]any{"enabled": true}
		} else {
			dash["enabled"] = true
			m["dashboard"] = dash
		}
		services[i] = m
	}
	if !found {
		services = append(services, map[string]any{
			"type":        "api",
			"tag":         "api",
			"listen":      "127.0.0.1",
			"listen_port": port,
			"dashboard": map[string]any{
				"enabled": true,
			},
		})
	}
	root["services"] = services
}

// ensureClashAPI injects experimental.clash_api for tray node switching.
func ensureClashAPI(root map[string]any, addr string) {
	exp, _ := root["experimental"].(map[string]any)
	if exp == nil {
		exp = map[string]any{}
	}
	clash, _ := exp["clash_api"].(map[string]any)
	if clash == nil {
		clash = map[string]any{}
	}
	if _, ok := clash["external_controller"]; !ok || clash["external_controller"] == "" {
		clash["external_controller"] = addr
	}
	exp["clash_api"] = clash
	root["experimental"] = exp
}

func ensureCacheFile(root map[string]any, tunMode bool) {
	exp, _ := root["experimental"].(map[string]any)
	if exp == nil {
		exp = map[string]any{}
	}
	cf, _ := exp["cache_file"].(map[string]any)
	if cf == nil {
		cf = map[string]any{}
	}
	if cf["enabled"] == nil {
		cf["enabled"] = true
	}
	// TUN mode runs sing-box as root (macOS). Use a separate cache file so it
	// never contends the SQLite lock with the normal user-mode process.
	// Force-override the path in TUN mode even if the user config set one.
	if tunMode {
		cf["path"] = "cache-tun.db"
	} else if cf["path"] == nil || cf["path"] == "" {
		cf["path"] = "cache.db"
	}
	exp["cache_file"] = cf
	root["experimental"] = exp
}

// stripDirectDNSDetour removes detour:"direct" from DNS servers.
// Newer sing-box: "detour to an empty direct outbound makes no sense".
func stripDirectDNSDetour(root map[string]any) {
	dns, _ := root["dns"].(map[string]any)
	if dns == nil {
		return
	}
	servers, _ := dns["servers"].([]any)
	for i, item := range servers {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if d, _ := m["detour"].(string); d == "direct" {
			delete(m, "detour")
			servers[i] = m
		}
	}
	dns["servers"] = servers
	root["dns"] = dns
}

// preferLocalRuleSets rewrites known remote CN rule-sets to bundled local paths
// when the files exist under ~/.swellbox/rule-set/.
func preferLocalRuleSets(root map[string]any) {
	route, _ := root["route"].(map[string]any)
	if route == nil {
		return
	}
	list, _ := route["rule_set"].([]any)
	if len(list) == 0 {
		return
	}
	home, err := paths.HomeDir()
	if err != nil {
		return
	}
	localMap := map[string]string{
		"geosite-cn": "rule-set/geosite-cn.srs",
		"geoip-cn":   "rule-set/geoip-cn.srs",
	}
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := m["tag"].(string)
		rel, ok := localMap[tag]
		if !ok {
			continue
		}
		full := filepath.Join(home, filepath.FromSlash(rel))
		if st, err := os.Stat(full); err != nil || st.IsDir() || st.Size() == 0 {
			continue
		}
		m["type"] = "local"
		m["format"] = "binary"
		m["path"] = rel
		delete(m, "url")
		delete(m, "download_detour")
		delete(m, "update_interval")
		list[i] = m
	}
	route["rule_set"] = list
	root["route"] = route
}

// ensureHTTPClient implements the sing-box ≥1.14 http_clients API.
//
// sing-box 1.14 deprecated the implicit default HTTP client across ALL
// HTTP-using components: remote rule-sets, DoH/DoT DNS servers, ACME
// certificate providers, Clash API, etc. Even configs with only local
// rule-sets trigger the deprecation if DoH servers are present.
//
// The fix is to always inject an explicit top-level http_clients entry
// and point route.default_http_client at it, whenever a proxy outbound
// is available to use as the detour.
func ensureHTTPClient(root map[string]any) {
	route, _ := root["route"].(map[string]any)
	if route == nil {
		return
	}
	list, _ := route["rule_set"].([]any)
	detour := pickProxyOutboundTag(root)
	if detour == "" {
		return
	}

	const clientTag = "swell-http-client"

	// 1. Ensure http_clients contains our managed entry.
	clients, _ := root["http_clients"].([]any)
	found := false
	for i, item := range clients {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if tag, _ := m["tag"].(string); tag == clientTag {
			// Already present — update detour in case active config changed.
			m["detour"] = detour
			clients[i] = m
			found = true
			break
		}
	}
	if !found {
		clients = append(clients, map[string]any{
			"tag":    clientTag,
			"detour": detour,
		})
	}
	root["http_clients"] = clients

	// 2. Set route.default_http_client (only if not already pointing to a
	//    user-defined client other than the legacy "default" sentinel).
	existing, _ := route["default_http_client"].(string)
	if existing == "" || existing == "default" {
		route["default_http_client"] = clientTag
	}

	// 3. Strip legacy download_detour from individual remote rule-sets — that
	//    option is also deprecated in 1.14 and causes a second FATAL in 1.15.
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t != "remote" {
			continue
		}
		delete(m, "download_detour")
		list[i] = m
	}
	route["rule_set"] = list
	root["route"] = route
}

// pickProxyOutboundTag returns the best outbound tag to use as a download detour
// for remote rule-sets. Priority:
//  1. An outbound with tag "proxy" (the canonical Swell-Box selector)
//  2. The first selector/urltest outbound
//  3. The first leaf proxy outbound (not direct/block/dns/reject)
func pickProxyOutboundTag(root map[string]any) string {
	outbounds, _ := root["outbounds"].([]any)
	var firstSelector, firstLeaf string
	for _, item := range outbounds {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := m["tag"].(string)
		if tag == "" {
			continue
		}
		t, _ := m["type"].(string)
		switch t {
		case "direct", "block", "dns":
			continue
		}
		// Exact match wins immediately.
		if tag == "proxy" {
			return "proxy"
		}
		if (t == "selector" || t == "urltest") && firstSelector == "" {
			firstSelector = tag
		}
		if t != "selector" && t != "urltest" && firstLeaf == "" {
			firstLeaf = tag
		}
	}
	if firstSelector != "" {
		return firstSelector
	}
	return firstLeaf
}

// RuntimeConfigPath returns ~/.swellbox/runtime/config.runtime.json
func RuntimeConfigPath() (string, error) {
	dir, err := paths.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "config.runtime.json"), nil
}

// disableAAAAInject adds a DNS rule to reject AAAA queries in TUN mode.
// This prevents Windows from attempting to route raw IPv6 connections into TUN,
// which proxy servers often lack the capability to handle out-of-band.
func disableAAAAInject(root map[string]any) {
	dns, _ := root["dns"].(map[string]any)
	if dns == nil {
		dns = map[string]any{}
	}
	rules, _ := dns["rules"].([]any)

	rejectRule := map[string]any{
		"query_type": []string{"AAAA"},
		"action":     "reject",
		"method":     "default",
	}
	rules = append([]any{rejectRule}, rules...)
	
	dns["rules"] = rules
	root["dns"] = dns
}
