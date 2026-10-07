# Home Assistant OS WireGuard Client

![WireGuard Client icon](wireguard_client/icon.png)

An outbound IPv4 WireGuard client for pfSense, including CGNAT installations.
Configure it through Home Assistant add-on options; inspect it through Ingress.

**0.3.0 is an experimental breaking update.** It adds an optional restricted LAN
gateway and a status dashboard. HA OS/Supervisor acceptance testing is still
required before relying on it for remote access.

[Add repository to Home Assistant](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FFirestormV%2Fha-wireguard-client)

## Two operating modes

- **Default:** tunnel address TCP port 8123 relays to Home Assistant Core.
  Forwarded traffic is blocked with `FORWARD DROP`; no gateway NAT is installed.
- **Optional gateway:** VPN-initiated TCP, UDP and ICMP can reach explicitly allowed
  local IPv4 destinations through scoped NAT. Replies are allowed. The HA relay
  remains available. This does not provide arbitrary LAN-initiated VPN access.

Both modes use `host_network: false`. WireGuard, routes and firewall rules remain
inside the container. The add-on never writes sysctls, host routes or host firewall
rules, mounts the Docker socket, or requests full privileged access. Gateway mode
requires the container's existing `net.ipv4.ip_forward` value to be `1`.

## Dashboard

The Ingress page shows public key, handshake health, sampled traffic rates,
HA proxy status, gateway rule verification and routing. Advanced diagnostics,
a bounded packet-header capture and a copyable text report help troubleshoot
failures. The page remains available after network startup/runtime errors.
Private keys, PSKs and tokens are excluded from its API and reports.

Code, logs and technical names are English. Configuration labels and dashboard
labels support English and Swedish. Configuration changes require a restart.

[English setup and test guide](wireguard_client/DOCS.md) · [Svensk guide](wireguard_client/DOCS.sv.md)

## Validation

```sh
python3 -m unittest discover -s tests -v
docker build -t ha-wireguard-client:test wireguard_client
# Disposable Linux Docker environment with kernel WireGuard support:
python3 tests/integration/run.py
python3 tests/integration/setup.py
python3 tests/integration/gateway.py
```

The gateway test runs real WireGuard and the actual add-on implementation against
LAN fixtures and a simulated second NAT stage. It checks both modes, multiple
CIDRs, blocked destinations, proxy access, partial startup failure, runtime rule
loss, cleanup and diagnostics. It does not substitute for HA OS/AppArmor testing
or a real pfSense/physical LAN acceptance test. See the setup guide for that test.
