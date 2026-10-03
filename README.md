# Home Assistant OS WireGuard Client

![WireGuard Client icon](wireguard_client/icon.png)

Access Home Assistant through an outbound IPv4 WireGuard tunnel to pfSense, even when the remote site uses CGNAT. Configure keys, endpoint, keepalive, MTU and networks in Home Assistant.

## Isolated networking in 0.2.0

WireGuard and its routes live inside the add-on's own network namespace. The add-on does not use host networking. A TCP relay listens only on the tunnel address, port 8123, and connects to `homeassistant:8123` by default. The HA host's routing table and default gateway are not modified.

The relay carries HTTP, WebSocket and TLS bytes without terminating encryption or changing headers. Home Assistant sees the add-on as the connection source. No host ports are published, IP forwarding is blocked inside the container, AppArmor is enabled, and no Supervisor API access is requested. NET_ADMIN is still required within the container. Containers share the host kernel and resources; this is network isolation, not VM-level isolation.

**Upgrading from 0.1.x:** read the [migration steps](wireguard_client/DOCS.md#upgrading-from-01x) before updating. Version 0.2.0 is marked as a breaking update and requires manual approval. Existing options are retained; the backend defaults to `homeassistant:8123`.

[Add this repository to Home Assistant](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FFirestormV%2Fha-wireguard-client)

Alternatively, add `https://github.com/FirestormV/ha-wireguard-client` under app/add-on store → menu → Repositories. Install **WireGuard Client**, configure it and start it manually.

[English setup guide](wireguard_client/DOCS.md) · [Svensk guide](wireguard_client/DOCS.sv.md)

## Public key and languages

Select **Open Web UI** while the add-on is running to view and copy its public key. This key is derived from the saved or explicitly supplied private key at startup; no private key is shown. A working handshake is not required. On first start, leaving the private key empty generates a persistent key automatically. The public key page opens even before the peer configuration is complete. Copy it to pfSense, complete Configuration, save and restart.

Code, logs and primary documentation are English. Configuration labels and the public key page support English and Swedish. YAML keys always remain English.

## Validation

[Validated on GitHub Actions](https://github.com/FirestormV/ha-wireguard-client/actions/runs/37118241840): 21 unit tests and the Linux integration test passed.

The test suite covers option validation, cleanup, public key display, Ingress access restrictions and TCP relay configuration. CI builds the amd64 image and runs a real WireGuard tunnel between disposable Docker containers, checking HTTP, an upgraded binary TCP stream, stop/start recovery and unchanged host routes.

```sh
python3 -m unittest discover -s tests -v
docker build --build-arg BUILD_ARCH=amd64 -t ha-wireguard-client:test wireguard_client
# Disposable Linux Docker environment with kernel WireGuard support:
python3 tests/integration/run.py
```

Version 0.2.5 remains experimental. HA OS/Supervisor/AppArmor integration, your pfSense/CGNAT connection, aarch64 and actual HA login/WebSocket/TLS behavior require target-system acceptance tests. CI's upgraded binary stream verifies transparent transport, not a complete HA session.

Routing to an entire remote LAN is not implemented. A future gateway should be separate from this HA-only relay and explicitly enabled.
