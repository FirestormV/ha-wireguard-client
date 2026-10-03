# WireGuard Client for Home Assistant OS

[Dokumentation på svenska](DOCS.sv.md)

Version 0.1.4 is experimental. Supports amd64 and aarch64, IPv4 and one pfSense peer.

## Address plan

Replace these examples with non-overlapping networks from your installation:

| Component | Example |
|---|---|
| Home network behind pfSense | 192.168.10.0/24 |
| Public pfSense endpoint | vpn.example.com:51820/UDP |
| pfSense tunnel address | 10.77.0.1/24 |
| HA OS tunnel address | 10.77.0.2/32 |
| Future remote LAN | 192.168.50.0/24 |

Traffic flows from a home computer through pfSense and WireGuard to Home Assistant at `10.77.0.2:8123`. Return traffic to the home network uses the tunnel. The existing internet default route remains unchanged.

The add-on creates `wg-ha-client` in the HA OS host network namespace. Home Assistant must listen on the tunnel address, normally covered by its default all-addresses binding. Use your actual HTTPS scheme and port if configured. No HTTP proxy or `trusted_proxies` change is required.

The remote side initiates outgoing UDP, and keepalive maintains the CGNAT mapping. pfSense needs a reachable public IPv4 address or working UDP port forwarding from its upstream router. If the home side also uses CGNAT without inbound access, another reachable endpoint is required. No port forwarding is needed at the remote site.

## Installation

Add `https://github.com/FirestormV/ha-wireguard-client` in the Home Assistant app/add-on store → menu → Repositories. Install **WireGuard Client**, fill in Configuration, save and start. Enable start on boot and Supervisor Watchdog for process failures. Restart the add-on after configuration changes.

For local installation, copy the `wireguard_client` directory to `/addons/wireguard_client` using Samba or SSH with access to `/addons`. Refresh the store and install it under local add-ons. Supervisor builds the Dockerfile, requiring internet access.

The add-on requires `NET_ADMIN` and kernel WireGuard support. It does not use `/dev/net/tun`, the Docker API or `SYS_MODULE`. AppArmor is disabled in this initial implementation; a tested custom profile is future hardening. If Supervisor denies the required network capability, check Protected mode and disable it for this add-on if needed. Do not run multiple installations sharing the interface name.

## Keys and configuration

Generate a separate client key pair on a trusted system with WireGuard tools:

```sh
umask 077
wg genkey > ha-private.key
wg pubkey < ha-private.key > ha-public.key
```

Put the client private key in the add-on and its public key in the pfSense peer. The add-on's `peer_public_key` is the public key of the pfSense tunnel. An optional preshared key can be generated with `wg genpsk`; both sides must use the same value.

```yaml
private_key: "YOUR_CLIENT_PRIVATE_KEY"
peer_public_key: "YOUR_PFSENSE_PUBLIC_KEY"
preshared_key: ""
endpoint_host: "vpn.example.com"
endpoint_port: 51820
tunnel_address: "10.77.0.2/32"
allowed_ips:
  - "10.77.0.1/32"
  - "192.168.10.0/24"
persistent_keepalive: 25
mtu: 1380
```

| Option | Meaning | Default/example |
|---|---|---|
| `private_key` | Client private key | Required |
| `peer_public_key` | pfSense public key | Required |
| `preshared_key` | Optional shared secret | Empty disables it |
| `endpoint_host` | Public IPv4 address or DNS hostname of pfSense | vpn.example.com |
| `endpoint_port` | pfSense UDP port | 51820 |
| `tunnel_address` | HA tunnel IPv4 address, /32 required | 10.77.0.2/32 |
| `allowed_ips` | Networks reached through pfSense and accepted peer source networks | pfSense tunnel IP and home LAN |
| `persistent_keepalive` | Interval in seconds, 0–65535 | 25; 0 disables keepalive |
| `mtu` | Tunnel MTU, 1280–1420 | 1380 |

Include every home subnet/VLAN that needs access in `allowed_ips` so HA can route replies correctly. Do not add the remote LAN to this client-side list. Default routes, overlapping entries and collisions with existing host networks are rejected. Home LAN, remote LAN, tunnel and HA Docker networks must not overlap. IPv6 and full-tunnel routing are not supported.

Keepalive defaults to 25 seconds, including when upgrading older options without this field. Disabling it can allow the CGNAT mapping to expire. UI labels and help text have English and Swedish translations; the YAML keys remain English.

Secrets are stored in Supervisor options and may appear in backups. Password fields mask values in the UI; they are not separate encryption. The temporary WireGuard configuration uses mode 0600 in `/tmp` and is deleted after loading. Logs show the client public key, never private keys.

## View the client public key

After saving valid configuration and starting the add-on, select **Open Web UI**. The page displays the client public key in a read-only field with a copy button. Paste it into the client peer's Public Key field in pfSense. The page is available while the add-on is running, including during endpoint DNS retries or while waiting for a handshake. It is unavailable when the add-on is stopped or fails to start.

The public key is derived from the configured private key at startup. Restart after changing keys; the page shows the key loaded at startup, not unsaved edits. It does not generate a private key or change your configuration. The private key is passed to `wg pubkey` via stdin and is never passed to the web server.

Home Assistant's standard add-on schema does not expose a computed read-only option, so this page uses HA Ingress. Only connections from the Supervisor Ingress source (172.30.32.2) are accepted; direct LAN access is denied. The add-on uses the Supervisor API to obtain its assigned Ingress port. Do not port-forward it. Choose English or Swedish on the page; the initial choice follows the browser language. If clipboard access is unavailable, the button selects the key for manual copying.

HA Ingress integration still needs verification on a real HA OS installation. After updating, check Open Web UI, copy the key, compare it with the public key in the log, and verify that a configuration restart displays the corresponding new public key.

## pfSense setup

1. Install/enable WireGuard. Create a tunnel listening on UDP `51820`, with address `10.77.0.1/24` and its own key pair.
2. Add a peer with the client public key, **Dynamic Endpoint** enabled, an empty endpoint and Allowed IPs **`10.77.0.2/32` only**. Match the optional PSK.
3. Add a WAN rule allowing UDP to **WAN address**, port `51820`. Restrict the source only if the remote public address is stable. Do not expose HA port 8123 on WAN.
4. On the home LAN/VLAN where connections originate, allow the desired home clients to reach `10.77.0.2` over TCP port `8123`. Place this before policy-routing rules and use normal routing without a selected WAN/VPN gateway. Existing connection state permits replies.
5. Verify a connected route to `10.77.0.0/24` through WireGuard. Home clients must use pfSense as their gateway or have a route to the tunnel through pfSense. Keep WAN as the pfSense default gateway, especially when assigning the WireGuard interface.
6. A broad inbound WireGuard allow-any rule is unnecessary for home-initiated access. Add narrow tunnel-interface rules only if the remote side should initiate connections into the home network. Review existing floating/group rules.
7. NAT between the home network and tunnel is unnecessary. Ensure custom outbound NAT rules do not rewrite this traffic.

This add-on is not a firewall: other host services listening on the tunnel address can be reachable if your rules allow them. To restrict access to HA, add suitable block rules before broad LAN allow-any rules. Existing HA OS forwarding is left untouched; do not add routes to the remote LAN before planning its firewall policy.

## Acceptance checks and troubleshooting

- Wait for **Handshake healthy** in the log. Checks run every 30 seconds; the initial configuration message alone does not prove connectivity.
- Confirm a recent handshake and dynamically learned peer endpoint in pfSense.
- From home, open `http://10.77.0.2:8123`, sign in and check real-time UI updates.
- Test ping from pfSense using source `10.77.0.1`. Pings from home clients also require an appropriate LAN ICMP rule.
- Stop/start the add-on, reboot HA OS and disconnect/reconnect remote internet access. Check recovery and normal HA internet connectivity.
- After a clean stop, confirm that `wg-ha-client` and its routes are gone. SIGTERM triggers cleanup. A hard crash may leave the interface until the next start, which reclaims only an interface with the expected ownership marker.

No handshake: check UDP reachability, endpoint, keys and PSK. Handshake but no HTTP: check the LAN rule, pfSense route, home source subnet in `allowed_ips`, and HA listening address/port. For stalled large transfers, try MTU 1280.

When no recent handshake exists for over 180 seconds, the endpoint is refreshed using DNS every 30 seconds. Initial DNS failures are retried. WireGuard renegotiates after outages. An offline peer does not stop the process; Supervisor Watchdog detects process failures rather than all network failures.

## Future remote LAN routing

Version 0.1.4 does not manage IP forwarding, FORWARD rules or NAT. The routed design preserves client source addresses and supports a future site-to-site extension.

For remote LAN `192.168.50.0/24` and HA OS with reserved LAN address `192.168.50.10`:

1. Add `192.168.50.0/24` to the **pfSense peer's** Allowed IPs, retaining `10.77.0.2/32`.
2. Add a pfSense route for that LAN through peer `10.77.0.2` on an assigned WireGuard interface. Allowed IPs do not replace the operating system route. Do not make this gateway the default.
3. Manage IPv4 forwarding and narrow stateful FORWARD rules between `wg-ha-client` and the correct HA OS LAN interface. Preserve Docker/Supervisor rules, never flush global tables, and use owned chains with defined start/stop and reboot recovery behavior.
4. Add a return route on the remote router: `192.168.10.0/24 via 192.168.50.10`. If that is impossible, narrowly scoped SNAT for home-to-remote-LAN traffic is an alternative but hides the original client address. Prefer routed return traffic.
5. Permit intended traffic in pfSense and remote device firewalls. Test both directions, outages and reboots. Broadcast/mDNS discovery does not automatically cross a routed tunnel.

A dedicated router may be more robust for remote LAN routing if persistent HA OS firewall management is unsuitable. The tunnel address plan and pfSense design can be retained.

## References

- [Home Assistant app configuration and translations](https://developers.home-assistant.io/docs/apps/configuration/)
- [WireGuard Quick Start and keepalive](https://www.wireguard.com/quickstart/)
- [Netgate remote access example](https://docs.netgate.com/pfsense/en/latest/recipes/wireguard-ra.html)
- [Netgate WireGuard routing](https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/routing.html)
