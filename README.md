# Home Assistant OS WireGuard Client

Utgående IPv4-tunnel genom fjärrsidans CGNAT till pfSense. Konfigureras i HA Add-on Configuration. Konfigurerbar PersistentKeepalive (standard 25 sekunder), host networking och explicita returvägar gör Home Assistant nåbar på sin tunneladress.

Börja med [installations- och pfSense-guiden](wireguard_client/DOCS.md). Adresserna är exempel och måste anpassas. Leveransen innehåller inga riktiga nycklar.

## Installera via GitHub

[Lägg till repository i Home Assistant](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FFirestormV%2Fha-wireguard-client)

Alternativt: öppna tilläggsbutiken → menyn → Repositories och lägg till `https://github.com/FirestormV/ha-wireguard-client`. Installera WireGuard Client, fyll i Configuration och starta.

## Status

Version 0.1.1 är experimentell. Tolv Python-enhetstester med simulerade systemkommandon passerar. Docker-motorn var inte igång i byggmiljön: containerbygge, NET_ADMIN/AppArmor-beteende på HA OS, riktiga routes och tunnel/HTTP genom CGNAT är därför **inte verifierade**. Guiden innehåller acceptanstest att köra på målmiljön.

```sh
python3 -m unittest discover -s tests -v
docker build --build-arg BUILD_ARCH=amd64 -t ha-wireguard-client:0.1.1 wireguard_client
```

Bygg och integrationstest bör göras innan skarp drift. LAN-forwarding är beskrivet som nästa steg och är inte implementerat i denna version.
