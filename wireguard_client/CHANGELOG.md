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
