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
