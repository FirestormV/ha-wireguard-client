# WireGuard Client for Home Assistant OS

[Dokumentation på svenska](DOCS.sv.md)

Version 0.3.0 is experimental. IPv4 only; one pfSense peer; amd64 and aarch64.

## Install and create the client identity

1. Add `https://github.com/FirestormV/ha-wireguard-client` under the Home Assistant
   add-on store repository menu, then install **WireGuard Client**.
2. Leave the client private key empty and start the add-on. Open Web UI to copy
   its public key. A working tunnel is not required; incomplete configuration
   leaves the dashboard available without starting a tunnel.
3. Put that public key in the client peer on pfSense. Fill in the pfSense public
   key, endpoint and networks in the add-on Configuration. Save and restart.
4. Complete the acceptance tests below before enabling automatic startup.

The private key is generated once, saved atomically with mode 0600 in
`/data/client-private.key`, and retained across restarts and updates. It is never
shown. Add-on data backups include this identity; keep backups private. To import
an identity, supply `private_key`. Clearing that field later reuses the imported
identity. Invalid saved keys cause an error rather than silently rotating keys.

The pfSense UDP endpoint needs to be reachable from the remote site. CGNAT at the
remote site is fine: the add-on initiates the tunnel. `persistent_keepalive: 25`
maintains the mapping; it is configurable from 0 to 65535 seconds (0 disables it).

## Configuration example

These are example networks. Replace them with your actual address plan.

| Setting | Meaning | Example |
|---|---|---|
| pfSense tunnel IP | VPN gateway | 192.168.101.1 |
| Client tunnel IP | This add-on's VPN identity | 192.168.101.20/32 |
| VPN laptop | Another peer reaching this gateway | 192.168.101.11 |
| Home network behind pfSense | Source network allowed through VPN | 192.168.1.0/24 |
| LAN at the HA installation | Destination network behind this add-on | 192.168.20.0/24 |

```yaml
private_key: ""
peer_public_key: "YOUR_PFSENSE_PUBLIC_KEY"
preshared_key: ""
endpoint_host: "vpn.example.com"
endpoint_port: 51820
tunnel_address: "192.168.101.20/32"
allowed_ips:
  - "192.168.101.0/24"
  - "192.168.1.0/24"
persistent_keepalive: 25
mtu: 1380
homeassistant_host: "homeassistant"
homeassistant_port: 8123
site_to_site: true
local_networks:
  - "192.168.20.0/24"
```

`allowed_ips` describes sources/networks **through pfSense**, used for WireGuard
source authorization and return routing. `local_networks` describes destinations
**at the HA site**. Do not put the local LAN in `allowed_ips`.

`local_networks` may contain multiple IPv4 CIDRs or individual `/32` destinations.
For a first test, prefer one known LAN device `/32`. There is a limit of 32 entries
in each network list. The gateway rejects malformed networks, overlaps with tunnel
or remote networks, internal container networks, loopback, link-local, multicast,
reserved ranges and default routes. Existing routing to the LAN must use a gateway
through `eth0`. The add-on does not add a directly connected LAN route.

If the laptop's directly connected LAN and the remote LAN share the same prefix,
resolve that routing conflict first. The add-on cannot distinguish two sites with
the same destination addresses automatically.

`site_to_site: true` with an empty `local_networks` is a configuration error.
To use only the existing HA relay:

```yaml
site_to_site: false
local_networks: []
```

All schema fields must be present in 0.3.0; there is no legacy fallback parser.
When updating, add these two new fields explicitly, save, and restart. The release
is marked as a breaking update. Back up add-on data to preserve its identity.

## pfSense and other VPN peers

For this add-on's peer on pfSense, use its tunnel `/32` **plus the local LAN
networks behind it**, for example `192.168.101.20/32` and `192.168.20.0/24`.
Do not assign the entire VPN subnet to this peer: other VPN addresses belong to
other peers. Ensure pfSense actually routes the LAN destinations to this tunnel
and that its WireGuard firewall rules allow the intended source/destination flows.

A connecting laptop's WireGuard AllowedIPs/routes must also include the desired
remote destinations. Rules permitting peer-to-peer traffic alone do not create
those client routes. No inbound port forwarding at the remote HA site is needed.

## Isolation and packet flow

```text
VPN source -> pfSense -> WireGuard -> container FORWARD -> restricted SNAT
           -> existing container gateway -> host's existing NAT -> local LAN
```

`host_network: false`, AppArmor and only the existing NET_ADMIN/NET_RAW capabilities
are retained. No Docker socket, host mounts, host route/firewall edits, SYS_ADMIN,
full privileged mode, macvlan, DHCP server or dedicated physical LAN IP is used.
Containers still share the host kernel and resources; this is network isolation.

The add-on never changes `net.ipv4.ip_forward`. Gateway mode requires it already
be `1`, otherwise startup fails closed with a diagnostic. Disabled mode is secured
by `FORWARD DROP`, with no gateway exceptions or gateway NAT, even if the inherited
sysctl is `1`.

Owned chains `WG_HA_S2S_FWD`, `WG_HA_S2S_MARK` and `WG_HA_S2S_NAT` restrict
TCP/UDP/ICMP to configured remote sources and LAN destinations. A conntrack mark
identifies eligible forwarded traffic so locally generated process traffic does
not match gateway NAT. Forwarding is activated last, disabled first during cleanup,
and monitored for missing or changed rules. Cleanup preserves unrelated rules and
does not flush conntrack globally. A stopped tunnel cannot forward lingering flows.

LAN devices normally see the **HA host's LAN address** as the source after double
NAT. They cannot identify individual VPN users by source IP. Apply per-source
restrictions on pfSense. This mode permits VPN-initiated sessions and their replies;
it does not make LAN-initiated connections to VPN networks work automatically.
Broadcast, multicast, mDNS reflection, discovery and IPv6 are out of scope.

## Home Assistant access

`http://192.168.101.20:8123` relays to `homeassistant:8123` in both modes. If Core
uses TLS, use HTTPS and a hostname matching its certificate. The relay transports
TCP bytes without terminating TLS or changing HTTP/WebSocket headers. HA sees the
container as source. The relay does not require a new `trusted_proxies` setting.
Normal HA authentication still applies; avoid broad trusted-network bypasses.
No host ports are published.

## Dashboard and diagnostics

Open Web UI (optionally pin it in the HA menu). Configuration remains in HA options.
The dashboard shows public key, endpoint, peer, latest handshake, keepalive,
WireGuard RX/TX totals and sampled rates, add-on uptime, HA relay and gateway state.
Polling is approximately every three seconds and pauses while the page is hidden.
Rates and totals may reset when the interface or add-on restarts; no history is stored.

Health is Healthy, Idle, Warning or Error. An old handshake with keepalive disabled
is Idle, not proof of disconnection. Rule verification does not prove the LAN
service is reachable. A running relay does not prove HA login works: the manual
backend probe tests only TCP connectivity and displays its last test time.

Advanced diagnostics includes addresses, routes, DNS servers, forwarding state and
firewall/NAT rules. Raw output is separate from the overview. The manual capture
is bounded to 15 seconds/60 packet headers, on the WireGuard interface only; it
covers ICMP echo and HA TCP connection-control packets, not arbitrary LAN traffic.
No scan or subnet probing runs in the background.

Copy diagnostics produces a compact text report with version, architecture,
public peer data, routes and rule-verification state. Private keys, PSKs, HA tokens
and Supervisor tokens are not included. Network addresses and public keys are
included: review the report before posting publicly. Per-LAN byte totals are not
implemented; NAT counters count connection setup rather than all traffic.

Networking failures stop/clean up the tunnel and keep Ingress available whenever
possible. Correct Configuration and restart to retry. If cleanup cannot be verified,
stop the add-on to destroy its container namespace before starting again. Application
logs use UTC timestamps (`Z`) and do not expose raw errors that could contain keys.

## Acceptance test on the fresh HA installation

Docker integration tests use real WireGuard with a simulated host-NAT/LAN fixture.
They do not establish HA OS/Supervisor/AppArmor or physical LAN compatibility.

1. Keep `site_to_site: false`, start, copy the public key and finish pfSense setup.
2. From the VPN peer, reach the add-on's tunnel IP on TCP 8123. Verify HA login and
   normal operation; inspect the handshake and proxy in the dashboard.
3. Enable site-to-site with one known LAN device `/32`. Add that destination to
   the pfSense peer and connecting client's routes/AllowedIPs. Save and restart.
4. Verify forwarding, firewall and NAT in the dashboard. Test a known TCP service,
   UDP service if available, and ICMP if that device permits it. A ping timeout
   alone does not prove routing failure.
5. Check that a reachable device outside `local_networks` cannot be reached through
   the tunnel. Confirm TCP 8123 on the add-on still reaches HA.
6. Restart the add-on and repeat. Disable gateway mode and confirm LAN forwarding
   stops while HA relay access still works. Expand the allowlist only after this.

If forwarding is unavailable or packets stop at the HA host boundary, capture and
report the last observed point. Do not enable host networking or larger privileges
to work around it. Share Copy diagnostics, not private keys or full options files.
