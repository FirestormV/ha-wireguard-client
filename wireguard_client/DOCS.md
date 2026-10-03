# WireGuard Client för Home Assistant OS

Version 0.1.1, experimentell. Stöd: amd64 och aarch64, IPv4, en pfSense-peer.

## Adressplan och trafik

Exempelvärden att ersätta med dina egna:

| Del | Adress |
|---|---|
| Hemnät bakom pfSense | 192.168.10.0/24 |
| pfSense offentlig endpoint | vpn.example.com:51820/UDP |
| pfSense tunneladress | 10.77.0.1/24 |
| HA OS tunneladress | 10.77.0.2/32 |
| Framtida fjärr-LAN | 192.168.50.0/24 |

Hemdator → pfSense → WireGuard → 10.77.0.2:8123 → Home Assistant.
Returtrafiken till 192.168.10.0/24 går genom tunneln. Vanlig internettrafik behåller HA OS befintliga default route.

Add-on använder host networking och skapar `wg-ha-client` i HA OS nätverksnamespace. Home Assistant Core nås därför på tunneladressen om HTTP-tjänsten lyssnar på den, normalt via standardbindningen till alla adresser. Ingen HTTP-proxy behövs. Använd HTTPS och motsvarande port om din HA-installation kräver det. Ändra inte `trusted_proxies` för denna direkta anslutning.

CGNAT på fjärrsidan fungerar eftersom add-on skickar utgående UDP och som standard sätter `PersistentKeepalive = 25`. pfSense måste vara nåbar utifrån: publik IPv4 eller fungerande UDP-portvidarebefordran till pfSense. Om även hemsidan sitter bakom CGNAT utan inkommande anslutning krävs en annan nåbar knutpunkt. Fjärrsidans router behöver ingen portvidarebefordran.

## Installation som lokalt add-on

1. Kopiera hela katalogen `wireguard_client` till `/addons/wireguard_client` på HA OS, exempelvis genom Samba-tilläggets addons-delning eller SSH-tillägget med åtkomst till `/addons`.
2. Öppna Inställningar → Tillägg/Apps → butik. Sök efter uppdateringar/läs om butiken via menyn. Installera **WireGuard Client** under lokala tillägg. Supervisor bygger imagen från Dockerfile; internetåtkomst krävs.
3. Ange värden under Configuration/Konfiguration enligt exemplet nedan och spara.
4. Starta, kontrollera loggen och slå på start vid uppstart samt Supervisor Watchdog för processkrascher. Tunneln får ingen separat HTTP-watchdog.
5. Starta om add-on efter konfigurationsändringar.

Det kräver `NET_ADMIN` och kernelstöd för WireGuard på HA OS. Ingen `/dev/net/tun`, Docker-API eller `SYS_MODULE` används. AppArmor är avstängt i denna första version; ett anpassat och HA-testat profilskydd är framtida härdning. Om din Supervisor nekar nätverksbehörigheten, kontrollera Protected mode och stäng av det för just detta add-on om det behövs. Kör aldrig flera installationer samtidigt med samma gränssnittsnamn.

För installation via repository kan denna leverans läggas i ett eget Git-repository, med `repository.yaml` i roten och `wireguard_client` direkt under roten. Lägg sedan till repository-URL i HA-butiken. Repository: https://github.com/FirestormV/ha-wireguard-client.

## Nycklar och konfiguration

Generera ett separat klientnyckelpar på en betrodd dator med WireGuard-verktyg:

```sh
umask 077
wg genkey > ha-private.key
wg pubkey < ha-private.key > ha-public.key
```

Privata klientnyckeln hör hemma i add-on; publika klientnyckeln i pfSense peer. `peer_public_key` är pfSense-tunnelns publika nyckel, inte klientens. En valfri preshared key genereras med `wg genpsk` och måste vara identisk på båda sidor.

```yaml
private_key: "KLISTRA_IN_KLIENTENS_PRIVATA_NYCKEL"
peer_public_key: "KLISTRA_IN_PFSENSE_PUBLIKA_NYCKEL"
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

Alla fält i HA Configuration:

| Fält | Betydelse | Standard/exempel |
|---|---|---|
| `private_key` | Klientens privata WireGuard-nyckel | Måste fyllas i |
| `peer_public_key` | pfSense-tunnelns publika nyckel | Måste fyllas i |
| `preshared_key` | Extra delad nyckel, samma på båda sidor | Tom = används inte |
| `endpoint_host` | pfSense publik IPv4 eller DNS-namn | vpn.example.com |
| `endpoint_port` | pfSense UDP-port | 51820 |
| `tunnel_address` | HA:s IPv4-adress i tunneln, /32 | 10.77.0.2/32 |
| `allowed_ips` | Nät via pfSense, inklusive hemnätets returväg | 10.77.0.1/32 och 192.168.10.0/24 |
| `persistent_keepalive` | Keepalive-intervall, 0–65535 sekunder | 25; 0 = av |
| `mtu` | Tunnelns MTU, 1280–1420 | 1380 |

`allowed_ips` anger nät **på hemsidan** som ska nås genom pfSense och godtas som källadresser från dess peer. Hemnätet måste finnas här för svarstrafik från HA. Ange alla relevanta hem-VLAN uttryckligen. Fjärr-LAN ska inte läggas i denna lista.

`persistent_keepalive` kan ändras i UI: 0–65535 sekunder, standard 25. Värdet 0 stänger av periodisk keepalive; behåll normalt 25 bakom CGNAT så att NAT-mappningen hålls öppen. Äldre konfiguration utan fältet använder 25. `tunnel_address` måste vara /32. Default route, överlappande poster och kollision med värdens befintliga nät avvisas. Använd separata, icke överlappande subnät för hem, fjärr-LAN, tunnel och HA:s interna Docker-nät. IPv6 och full tunnel stöds inte i v0.1.1.

Hemligheter ligger i Supervisors options-lagring och kan finnas i säkerhetskopior. UI-fält av typen password ger maskering, inte separat kryptering. Den tillfälliga WireGuard-konfigurationen skapas med rättigheter 0600 i `/tmp` och tas bort efter inläsning. Loggen innehåller klientens publika nyckel men inga privata nycklar.

## pfSense

1. Installera/aktivera WireGuard-paketet. Skapa en tunnel med port `51820`, adress `10.77.0.1/24` och ett eget nyckelpar.
2. Lägg till klienten som peer: klientens publika nyckel, **Dynamic Endpoint** aktiverat och Allowed IPs **endast `10.77.0.2/32`**. Lämna endpoint tom. Eventuell PSK ska matcha add-on.
3. WAN-regel: tillåt UDP till **WAN address**, port `51820`. Fjärrsidans CGNAT-adress kan ändras; begränsa källan bara om du har en stabil källadress. Ingen portöppning för 8123 på WAN behövs.
4. På hem-LAN/VLAN där anslutningen initieras: tillåt TCP från önskade hemklienter till `10.77.0.2`, port `8123`. Lägg före policy-routingregler; låt regeln använda normal routing utan vald VPN/WAN-gateway. Svar till en tillåten anslutning hanteras av pfSense state table.
5. Kontrollera att pfSense har en ansluten route till `10.77.0.0/24` via sin WireGuard-tunnel. Hemklienterna ska använda pfSense som gateway, eller ha route till tunneln via pfSense. Behåll WAN som pfSense default gateway, särskilt vid interface assignment.
6. För denna anslutningsriktning behövs ingen bred allow-any-regel från WireGuard in till hemnätet. Lägg bara smala regler på WireGuard/assignat tunnelinterface om fjärrsidan också ska få initiera trafik till hemmet. Befintliga floating/group-regler kan påverka resultatet.
7. NAT mellan hemnät och tunnel behövs inte. Kontrollera att egna outbound NAT-regler inte skriver om denna trafik.

Add-on är ingen brandvägg: andra tjänster som lyssnar på HA-värdens tunneladress kan också vara nåbara om nätets regler tillåter det. Begränsa pfSense LAN-regler till önskade klienter/portar; komplettera med en blockregel före breda LAN allow-any-regler om du vill garantera att övrig tunneltrafik blockeras. Befintlig forwarding på HA OS lämnas orörd, så lägg inte routes till fjärr-LAN i pfSense innan dess regler är planerade.

## Verifiering på din installation

- Loggen ska först säga att tunneln är konfigurerad, därefter **Handshake healthy** (kontroll var 30:e sekund). Startmeddelandet ensamt bevisar ingen fungerande tunnel.
- pfSense WireGuard-status ska visa en aktuell handshake och en dynamiskt inlärd endpoint för klienten.
- Från hemnät: öppna `http://10.77.0.2:8123`. Prova inloggning och att gränssnittets realtidsuppdateringar fungerar.
- Från pfSense kan du testa ping med källadress `10.77.0.1`. För ping från hemklient behövs också en tillåtande ICMP-regel på LAN.
- Stoppa/starta add-on, starta om HA OS och bryt/återställ fjärrsidans internet. Kontrollera återanslutning och att vanlig HA-internetåtkomst består.
- Verifiera efter stopp att `wg-ha-client` och dess routes är borta. SIGTERM städar upp; efter en hård processkrasch kan gränssnittet ligga kvar tills nästa start, som återtar endast ett gränssnitt med rätt ägarmarkör.

Utan handshake: kontrollera UDP, endpoint, publik nåbarhet, nycklar och PSK. Med handshake men utan HTTP: kontrollera LAN-regel, pfSense-route, add-on `allowed_ips` för hemklientens verkliga källnät och HA HTTP-bindning/port. Vid hängande större överföringar prova MTU 1280.

Vid utebliven handshake i över 180 sekunder uppdateras endpoint via DNS var 30:e sekund. Initial DNS-brist väntas ut. WireGuard återförhandlar själv efter avbrott; en peer som är offline gör inte att processen avslutas. Watchdog fångar processfel, inte alla nätfel.

## Nästa steg: hela fjärr-LAN

Arkitekturen behåller klienternas källadresser och kan utökas till routad site-to-site. V0.1.1 implementerar inte hantering av forwarding, FORWARD-regler eller NAT.

För exempel-LAN `192.168.50.0/24`, med HA OS på en reserverad LAN-adress `192.168.50.10`, behöver nästa version/design:

1. Utöka **pfSense-peerens** Allowed IPs med `192.168.50.0/24`; behåll `10.77.0.2/32`.
2. Lägg route i pfSense för `192.168.50.0/24` via peer `10.77.0.2` på ett assignat WireGuard-interface. Allowed IPs ersätter inte operativsystemets route. Undvik att denna gateway blir default.
3. Hantera IPv4-forwarding och snäva stateful FORWARD-regler mellan `wg-ha-client` och rätt LAN-interface på HA OS. Bevara Docker/Supervisor-regler; aldrig flush av globala tabeller. Använd egna kedjor och definiera ägarskap, start/stop och återställning efter värdomstart.
4. Lägg returroute på fjärrroutern: `192.168.10.0/24 via 192.168.50.10`. Alternativt krävs smal SNAT för just hem→fjärr-LAN, vilket döljer ursprunglig klientadress. Routad returväg är förstahandsval.
5. Tillåt önskad trafik i pfSense och fjärrenheternas brandväggar. Testa båda riktningar, avbrott och omstarter. mDNS/broadcast-discovery följer inte automatiskt med en routad tunnel.

Det kan vara mer robust att placera framtida LAN-routing på en dedikerad router om HA OS inte lämpar sig för beständig brandväggshantering. Samma tunneladressplan och pfSense-upplägg kan behållas.

## Källor

- [Home Assistant add-on/app-konfiguration](https://developers.home-assistant.io/docs/apps/configuration/)
- [WireGuard Quick Start och keepalive](https://www.wireguard.com/quickstart/)
- [Netgate remote access-exempel](https://docs.netgate.com/pfsense/en/latest/recipes/wireguard-ra.html)
- [Netgate WireGuard-routing](https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/routing.html)
