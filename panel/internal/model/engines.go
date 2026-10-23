package model

// Profiles describe this manager's adapters, independently of Node protocol
// capabilities and independently of what an engine can do with arbitrary config.
type EngineProfile struct {
	ID            string   `json:"id"`
	VersionPolicy string   `json:"version_policy"`
	Validation    string   `json:"validation"`
	Features      []string `json:"features"`
	Limitations   []string `json:"limitations"`
}

func EngineProfiles() []EngineProfile {
	return []EngineProfile{
		{ID: "haproxy", VersionPolicy: "HAProxy 2.4+ / 3.x; native preflight required", Validation: "native", Features: []string{"tcp_passthrough", "weighted_balancing", "tcp_health", "http_health", "checked_failover", "proxy_send", "graceful_reload"}, Limitations: []string{"no_udp", "no_tls_editor", "local_management"}},
		{ID: "realm", VersionPolicy: "Pinned 2.9.6; other 2.x versions unverified", Validation: "schema", Features: []string{"tcp_udp", "weighted_balancing", "network_timeouts", "proxy_both"}, Limitations: []string{"no_active_checks", "no_native_transports", "local_management"}},
		{ID: "nftables", VersionPolicy: "Distribution package; kernel/native preflight required", Validation: "native", Features: []string{"kernel_dnat", "weighted_random", "source_policy", "mss_clamp"}, Limitations: []string{"no_active_checks", "owned_rules_only", "local_management"}},
		{ID: "iptables", VersionPolicy: "Distribution package; kernel/native preflight required", Validation: "native", Features: []string{"kernel_dnat", "weighted_random", "source_policy", "mss_clamp"}, Limitations: []string{"no_active_checks", "owned_rules_only", "local_management"}},
		{ID: "frp", VersionPolicy: "Pinned 0.71.1; frpc and frps versions must match", Validation: "native", Features: []string{"reverse", "tcp_udp", "ws_quic", "wss_gateway", "leased_pair"}, Limitations: []string{"pair_subset"}},
		{ID: "rathole", VersionPolicy: "Pinned 0.5.0", Validation: "schema_startup", Features: []string{"reverse", "tcp_udp", "noise_nk"}, Limitations: []string{"local_management", "no_other_transports"}},
	}
}
