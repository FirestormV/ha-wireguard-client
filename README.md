# Home Assistant OS WireGuard Client

An outbound IPv4 WireGuard tunnel from Home Assistant OS behind CGNAT to pfSense. Configure keys, endpoint, routes, MTU and PersistentKeepalive (default: 25 seconds) in the Home Assistant add-on configuration UI.

Host networking makes Home Assistant accessible at its tunnel address. Explicit return routes preserve access from your home network without changing the default internet route.

[Add this repository to Home Assistant](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FFirestormV%2Fha-wireguard-client)

Alternatively, open the app/add-on store → menu → Repositories and add `https://github.com/FirestormV/ha-wireguard-client`. Install **WireGuard Client**, configure it and start it.

Read the [setup and pfSense guide](wireguard_client/DOCS.md) or [Swedish guide](wireguard_client/DOCS.sv.md). Addresses are examples; supply your own keys locally in Home Assistant.

## Languages

Source code, logs and primary documentation are in English. Configuration labels and descriptions include English and Swedish translations for Home Assistant. YAML option names stay the same in every language. Markdown documentation has explicit language links; it is not automatically translated.

## Status

Version 0.1.2 is experimental. Twelve unit tests with mocked system commands pass. GitHub Actions has built the amd64 image and checked Python, WireGuard and iproute2 in the container ([initial build](https://github.com/FirestormV/ha-wireguard-client/actions/runs/37113559854)). The aarch64 build, HA OS permissions, real routes and end-to-end tunnel/HTTP access through CGNAT still require validation on the target system.

```sh
python3 -m unittest discover -s tests -v
docker build --build-arg BUILD_ARCH=amd64 -t ha-wireguard-client:0.1.2 wireguard_client
```

The setup guide includes acceptance checks. Remote LAN forwarding is a planned extension, not implemented in this version.
