# 0.2.5

- Add an explicit UTC timestamp and severity level to every application log line.
- Retain 0.2.4 full VPN subnet support, verified by ping from two source addresses and HTTP through the tunnel.

# 0.2.4

- Allow a whole tunnel subnet in allowed_ips even when it contains the client tunnel address.
- Keep the client address as a local /32; Linux local delivery takes precedence over the tunnel subnet route.
- Retain default-route, backend/endpoint loop, overlapping-entry and internal-network conflict checks.
- Exercise ping from two tunnel source addresses, HTTP and local route precedence in the real tunnel test.

# 0.2.3

- Add an Ingress diagnostics panel and downloadable JSON report.
- Show live WireGuard counters/handshakes/Allowed IPs, interface counters, addresses, routes, listeners, firewall counters and ICMP/rp_filter settings.
- Add a bounded TCP check to the configured HA backend.
- Add a manual 15-second/60-packet tunnel capture of ICMP echo and TCP connection-control headers, without payloads.
- Request NET_RAW for packet capture; keep capture inside the isolated container.
- Exclude private keys, PSKs, Supervisor tokens and raw options from diagnostics.

# 0.2.2

- Generate and persist a client identity automatically when private_key is empty.
- Allow first start and public key display before pfSense configuration is complete.
- Stay in setup mode without tunnel/network changes until configuration is valid.
- Preserve generated/imported identities across restarts and updates using atomic 0600 storage.
- Add first-start, persistence and setup-mode regression tests.

# 0.2.1

- Explain that required keys must be filled in on the Configuration tab before starting.
- Report safe, field-specific validation and route-conflict errors without logging secrets.
- Log startup stages to distinguish configuration errors from networking failures.
- Accept surrounding whitespace when pasting WireGuard keys.

# 0.2.0

Breaking update: read the migration guide and stop version 0.1.x before upgrading.

- Move WireGuard and routes into the add-on network namespace; remove host networking.
- Relay only tunnel TCP port 8123 to the configured HA Core backend.
- Add homeassistant_host and homeassistant_port, defaulting to homeassistant:8123.
- Block container IP forwarding, enable AppArmor, and remove Supervisor API access.
- Keep the public key page on internal Ingress port 8099 without published host ports.
- Default new installs to manual startup and require manual approval of this update.
- Add real WireGuard/HTTP/stream/restart tests and verify host routes remain unchanged.
- HA now sees the add-on's internal IP as the source of tunnel connections.

# 0.1.4

- Add a custom app icon for the Home Assistant store and repository README.

# 0.1.3

- Add a read-only client public key field and copy button under Open Web UI.
- Derive the public key from the configured private key before endpoint resolution.
- Restrict the page to HA Ingress and use a Supervisor-assigned port.
- Provide English and Swedish page text; keep private keys out of the web server.

# 0.1.2

- Use English for primary documentation and preserve a linked Swedish guide.
- Add English and Swedish configuration labels and descriptions for Home Assistant.
- Keep option names and tunnel behavior unchanged.

# 0.1.1

- Make persistent_keepalive configurable: 0–65535 seconds, default 25; 0 disables it.
- Preserve the default for existing configurations and extend validation tests.

# 0.1.0

- Initial experimental IPv4 client with Home Assistant configuration.
- Host networking, kernel WireGuard and PersistentKeepalive=25.
- Explicit routes, conflict detection, DNS recovery and cleanup.
- pfSense setup guide and future remote LAN routing design.
