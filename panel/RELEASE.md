Optional Go web panel with Persian/English, RTL/LTR, responsive shadcn/ui, and the original Nettinx theme.

Manage GRE, iptables/nftables forwarding, HAProxy TCP, Realm TCP/UDP, and FRP/rathole reverse connections. Includes staged forms, multiport creation, grouped operations, engine preinstallation, and optional per-port/interface network counters.

The public HTTP/HTTPS process runs as a restricted user and talks to a local privileged broker. Passwords use bcrypt; authenticated writes require a session and CSRF token. Tunnel engines run independently of the panel. Prebuilt Linux amd64/arm64 packages include the matching Bash manager and embedded frontend; no Go, Node, Docker or database is required on servers.

Supported settings are listed in docs/WEB-PANEL.md. This is not an arbitrary native HAProxy/Realm/firewall configuration editor. The user-selected Nettinx palette is preserved, including its documented contrast limitations. Public two-server, reboot and sustained-load validation remain deployment checks.

Quick/custom setup supports automatic IP discovery, selected/random ports, explicit HTTP/HTTPS and generated administrator credentials. HTTPS remains the default. Existing settings and certificates are preserved; user passwords require eight characters within the bcrypt byte limit. The login page and connection help identify unencrypted HTTP.
