# WireGuard Client for Home Assistant OS

[Dokumentation på svenska](DOCS.sv.md)

Version 0.2.1 is experimental. Supports IPv4, one pfSense peer, amd64 and aarch64.

## Network design

Home computer → pfSense → WireGuard → add-on tunnel address:8123 → TCP relay → Home Assistant Core.

WireGuard, tunnel addresses and routes exist only inside the add-on's network namespace. No host networking or published host ports are used. NET_ADMIN allows changes within that namespace; the add-on does not mount or enter the host namespace. The container's FORWARD policy is DROP. AppArmor is enabled. There is no Supervisor API dependency.

The relay binds only the tunnel address at port 8123 and permits up to 32 concurrent connections. It forwards raw TCP to one configured backend. HTTP, upgraded WebSocket connections and HTTPS/TLS can pass through without HTTP header changes or TLS termination. Normal HA authentication remains required. HA sees the add-on's internal address as the source: review any IP bans or trusted-network authentication; do not enable broad trusted-network access for this container. No new `trusted_proxies` setting is needed for this TCP relay.

Containers still share the host's kernel, CPU and memory. Network isolation limits routing mistakes; it does not guarantee that an add-on can never affect the host.

## Address plan

| Component | Example |
|---|---|
| Home network behind pfSense | 192.168.10.0/24 |
| Public pfSense endpoint | vpn.example.com:51820/UDP |
| pfSense tunnel address | 10.77.0.1/24 |
| Add-on tunnel address | 10.77.0.2/32 |
| HA backend | homeassistant:8123 |

The remote side initiates UDP and keepalive maintains the CGNAT mapping. pfSense must have reachable public IPv4 or upstream UDP port forwarding. If both sides use CGNAT without inbound access, another reachable endpoint is required. No remote-site port forwarding is needed.

## Installation

Add `https://github.com/FirestormV/ha-wireguard-client` to the Home Assistant app/add-on store repositories. Install, configure, save and start **WireGuard Client**. New installations default to manual startup. After acceptance tests, enable start on boot and optionally Supervisor Watchdog. Restart after configuration changes.

For local installation, copy `wireguard_client` into `/addons/wireguard_client` through Samba/SSH and refresh the store. Supervisor builds the Dockerfile and needs internet access. Kernel WireGuard support and NET_ADMIN are required. No SYS_MODULE, host devices or Docker API are requested.

## Upgrading from 0.1.x

Version 0.1.x used host networking. Version 0.2.0 deliberately removes it and is marked as a breaking update to prevent an automatic rollout.

1. While connected through the normal local HA address, disable the old add-on's start on boot and Watchdog, then **stop it before updating**. Its normal shutdown removes the old host interface and routes.
2. If the old add-on previously crashed, check from the HA OS host console whether `wg-ha-client` or its routes remain: `ip link show dev wg-ha-client` and `ip -4 route show dev wg-ha-client`. The new isolated add-on cannot remove leftover host interfaces. If leftovers are confirmed, keep autostart disabled and perform a controlled HA OS reboot before continuing. Do not delete unrelated interfaces or routes.
3. Update to 0.2.0. Existing keys and options are retained. Set `homeassistant_host` and `homeassistant_port` if the default `homeassistant:8123` does not match your Core installation.
4. Start manually and complete the acceptance tests below before re-enabling autostart.

The tunnel URL remains `http://10.77.0.2:8123` with the example settings. Access to other host services or a remote LAN through the old host interface is not provided. If Core uses TLS, use HTTPS with a hostname matching its certificate; the relay does not issue certificates.

## Before the first start

You can edit the **Configuration** tab while the add-on is stopped. Fill in the client private key, pfSense public key, endpoint and network settings, then save and start. The blank default keys are placeholders; no keys are generated automatically. The public key page is available only after valid configuration has been saved and the add-on starts. Version 0.2.1 reports the missing field explicitly and does not modify networking when configuration validation fails.

## Keys and options

Generate the client key pair on a trusted system with WireGuard installed:

```sh
umask 077
wg genkey > ha-private.key
wg pubkey < ha-private.key > ha-public.key
```

The client private key belongs in the add-on. Put the client public key in the pfSense peer. Put the **pfSense tunnel's** public key in `peer_public_key`. An optional PSK generated with `wg genpsk` must match on both sides.

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
homeassistant_host: "homeassistant"
homeassistant_port: 8123
```

| Option | Meaning |
|---|---|
| `private_key` | Required client private key |
| `peer_public_key` | Required pfSense public key |
| `preshared_key` | Optional shared secret; empty disables it |
| `endpoint_host` | pfSense public IPv4 or DNS name |
| `endpoint_port` | pfSense UDP port; default 51820 |
| `tunnel_address` | Add-on tunnel IPv4 /32 |
| `allowed_ips` | Peer source networks and return routes inside the add-on |
| `persistent_keepalive` | 0–65535 seconds, default 25; 0 disables it |
| `mtu` | 1280–1420, default 1380 |
| `homeassistant_host` | Backend IPv4 or DNS name; default `homeassistant` |
| `homeassistant_port` | Backend TCP port; default 8123 |

The tunnel-facing TCP port is always 8123. The backend port may differ. Core must listen on an address reachable from the internal add-on network. Backend DNS is resolved at startup; restart if its address changes. A backend unavailable at startup can accept later connections when it recovers at the same IP.

Include all home subnets that need access in `allowed_ips`. Do not include the remote LAN, backend address or default route. Tunnel and allowed networks must not overlap the container's internal Docker networks. Route conflict checks now inspect the container's routes, not the host's. A bad route can break this add-on's access without rewriting HA's host routes.

Secrets remain in Supervisor options and may be in backups. Password fields mask values; they do not provide separate encryption. Temporary WireGuard configuration uses permissions 0600 and is removed after loading. Logs do not print private keys.

## View the public key

Start with valid configuration, then select **Open Web UI**. A read-only field and copy button display the public key derived at startup. Restart after changing the private key. The page is available during DNS retries and handshake waits, but not when the process is stopped or fails to start. It does not generate private keys.

HA Ingress authenticates access. Only the actual Supervisor source address 172.30.32.2 is allowed. Port 8099 is internal to the container and is not published on the host. Choose English or Swedish on the page; the initial selection follows browser language. If clipboard access is unavailable, the key is selected for manual copying.

## pfSense

1. Create a WireGuard tunnel listening on UDP 51820, address `10.77.0.1/24`, with its own key pair.
2. Add a peer with the client's public key, **Dynamic Endpoint** enabled, empty endpoint, and Allowed IPs `10.77.0.2/32`. Match any PSK.
3. WAN: allow UDP to WAN address port 51820. No WAN opening for HA's 8123 is needed.
4. Home LAN/VLAN: allow desired clients to `10.77.0.2`, TCP 8123, before policy-routing rules and without a selected WAN/VPN gateway. Reply traffic uses connection state.
5. Verify pfSense has a connected tunnel route for `10.77.0.0/24`. Home clients must route this network through pfSense. Keep WAN as pfSense's default gateway.
6. Broad inbound tunnel allow-any rules and NAT between home and tunnel are unnecessary for this direction. Review custom floating, group and outbound NAT rules.

Restrict access with pfSense rules to the intended home clients. IP forwarding is blocked in the add-on; only the TCP relay exposes HA. The Ingress page denies requests arriving from the tunnel.

## Acceptance tests and recovery

- Check for a recent handshake in pfSense and **Handshake healthy** in the add-on log. The startup message alone does not prove connectivity.
- Open the normal local HA URL and `http://10.77.0.2:8123` from home. Check login and live dashboard updates. For TLS, use your matching hostname and HTTPS.
- Open the public key page and compare the key with the log/pfSense peer.
- Stop the add-on: tunnel access should stop while local HA remains reachable. Start it again and check recovery.
- In a controlled test, disconnect/reconnect remote internet, restart the add-on, and reboot HA OS. Check regular HA access throughout. Do not use power cuts for testing.
- Host route tables should be unchanged by tunnel start/stop. The host should not have `wg-ha-client`; it exists only inside the running container.

No handshake: check endpoint, UDP and keys. Handshake but no HTTP: check pfSense rules, the home source subnet in `allowed_ips`, backend address/port and Core's listening configuration. Shared source-IP bans in Core can block all tunnel users. A stopped relay process stops the add-on; failed backend connections alone do not. For stalled large transfers, try MTU 1280.

Endpoint DNS is retried after 180 seconds without a recent handshake, at 30-second intervals. Initial endpoint/backend DNS failures wait and retry. Watchdog detects process failures, not all network failures.

## Future remote LAN routing

This version intentionally provides HA-only TCP access. Do not add remote-LAN routes expecting it to forward packets.

A future LAN gateway should be a separate, explicitly enabled component, ideally on the remote router or a dedicated gateway. It needs remote subnet entries in pfSense peer Allowed IPs, matching pfSense routes, narrow forwarding rules, and a return route on the remote router (or carefully scoped SNAT). It should have its own peer identity so this HA-only add-on can stay isolated. Broadcast/mDNS discovery requires separate handling.

## References

- [HA network communication and the homeassistant alias](https://developers.home-assistant.io/docs/apps/communication/)
- [HA app configuration](https://developers.home-assistant.io/docs/apps/configuration/)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)
- [Netgate remote access](https://docs.netgate.com/pfsense/en/latest/recipes/wireguard-ra.html)
