# A small decision guide. Capabilities describe implemented adapters, not every
# upstream feature, and never infer performance from the implementation language.
gtm_catalog() {
    printf 'Connection guide / implemented presets\n\n'
    printf '  Kernel forwarding: iptables / nftables\n    Direct TCP/UDP ports, optional GRE path, weighted random. No target health checks.\n'
    printf '  Checked TCP balancing: HAProxy\n    Round robin, least connections, consistent source hash or primary/backup failover.\n    Timeouts, caps, slow start, health settings, opt-in PROXY, local status and worker reload.\n'
    printf '  TCP/UDP relay: Realm\n    Single target or weighted round robin / source hashing.\n'
    printf '  Reverse connections: FRP\n    TCP, stream mux, WebSocket, verified WSS gateway or QUIC; TCP destination groups.\n'
    printf '  Reverse connections: rathole\n    Authenticated Noise over TCP; TCP/UDP/both services; one destination per instance.\n'
    printf '  Network links: GRE / ip6gre\n    Join IP networks, then forward service ports separately. GRE itself is not encrypted.\n\n'
    printf 'Selection notes\n'
    printf '  Start with kernel NAT when the destination is directly reachable.\n'
    printf '  Use HAProxy when TCP health checks and failover are required.\n'
    printf '  Use a reverse connection when only the destination can initiate the link.\n'
    printf '  For UDP on a lossy path, compare native UDP/GRE and FRP QUIC with TCP transports.\n'
    printf '  TCP Mux means FRP stream mux here, not HTTP CONNECT tcpmux.\n'
    printf '  Encryption, authentication and reachability are separate properties.\n'
    printf '  Measure CPU, RAM, loss, RTT and jitter on the actual route; no engine always wins.\n\n'
    printf 'Planned / not implemented\n'
    printf '  WireGuard/AmneziaWG link provisioning, GOST chains, GRE-over-UDP, IPVS,\n'
    printf '  HTTP CONNECT tcpmux, automatic cross-host deployment and a web dashboard.\n'
}

gtm_reverse_menu() {
    local choice
    gtm_header 'Reverse connections / choose an engine'
    gtm_help reverse
    gtm_option 1 FRP 'TCP / stream mux / WS / WSS / QUIC; destination groups'
    gtm_option 2 rathole 'Noise over TCP; simple authenticated reverse connection'
    gtm_option 3 'Choosing a method' 'Capabilities and practical tradeoffs'
    gtm_option 0 Back
    gtm_read 'Choose: ' choice || return
    case $choice in 1) gtm_frp_menu;; 2) gtm_rathole_menu;; 3) gtm_catalog; gtm_pause;; esac
}
