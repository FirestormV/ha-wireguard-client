# WireGuard Client 0.3.0

Versionen är experimentell. Den behöver verifieras på HA OS/Supervisor och ett
riktigt LAN. [Fullständig teknisk dokumentation på engelska](DOCS.md).

## Första starten

Installera från samma repository. Lämna klientens privata nyckel tom och starta.
Öppna Web UI och kopiera den publika nyckeln till klientens peer i pfSense. Fyll
sedan i pfSense publika nyckel, endpoint och nät under Konfiguration. Spara och
starta om. Den privata nyckeln sparas och visas aldrig. Säkerhetskopior av tillägget
innehåller nyckeln och ska skyddas.

## Gateway till nätet vid HA

```yaml
site_to_site: true
local_networks:
  - "192.168.20.0/24"
```

Nätet ovan är ett exempel: byt till LAN:et där den nya HA-installationen finns.
Börja gärna med en enskild testmaskin, exempelvis `192.168.20.10/32`.

- `tunnel_address`: tilläggets tunnel-IP, exempelvis `192.168.101.20/32`.
- `allowed_ips`: VPN-adresser och källnät via pfSense, exempelvis
  `192.168.101.0/24`. Lägg till hemnätet här om trafik kommer med hemnätets käll-IP.
- `local_networks`: tillåtna destinationer på HA-sidan. Lägg inte samma nät i
  `allowed_ips`. Nät på båda sidor får inte överlappa.

På pfSense ska tilläggets peer ha sin tunneladress `/32` och LAN-destinationerna
bakom tillägget i AllowedIPs. Se även till att pfSense faktiskt routar dessa nät
till tunneln och att brandväggen tillåter trafiken. Andra VPN-klienter behöver
motsvarande destinationsnät i sina routes/AllowedIPs.

För bara HA-åtkomst:

```yaml
site_to_site: false
local_networks: []
```

HA nås fortfarande på exempelvis `http://192.168.101.20:8123` i båda lägena.
Alla konfigurationsfält krävs i 0.3.0. Lägg till de två nya fälten vid uppdatering,
spara och starta om. Ingen äldre konfigurationsparser används.

## Isolering

`host_network: false` är kvar. Tillägget ändrar inga hostroutes, hostbrandväggar
eller sysctl-värden och får inget eget fysiskt LAN-IP. Gatewayläget kräver att
containerns befintliga `ip_forward` redan är `1`. Annars visas ett fel och tunneln
stoppas. Avstängt läge blockerar vidarebefordran med `FORWARD DROP` och har inga
site-to-site-undantag eller NAT-regler.

Gatewayläget släpper fram TCP, UDP och ICMP från godkända VPN-källor till explicita
LAN-destinationer och tillåter svarstrafik. Det är inte automatisk routing för nya
anslutningar från LAN mot VPN. Efter dubbel NAT ser LAN-enheter normalt HA-hostens
LAN-IP som källa. Kontrollera behörighet per VPN-källa på pfSense.

## Webbpanelen

Panelen visar handshake, trafikmängd och hastighet, publik nyckel, HA-proxy,
gatewayregler och routing. Inställningar ändras fortfarande i HA Configuration.
En gammal handshake med keepalive avstängt visas som Idle, inte automatiskt som
avbrott. Verifierade NAT-regler bevisar inte att en viss LAN-tjänst svarar.

Kopiera diagnostik ger en textrapport utan privata nycklar, PSK eller token.
Publika nycklar och nätadresser ingår. Avancerad diagnostik innehåller rå nätstatus
och en begränsad manuell paketfångst. Inget LAN skannas. Panelen finns kvar vid
nätverksfel; rätta inställningarna och starta om för ett nytt försök.

## Test på din nya HA

1. Börja med gateway avstängd. Kontrollera handshake och HA-inloggning via tunneln.
2. Aktivera gateway för en enda känd LAN-adress `/32`. Uppdatera routing i pfSense
   och den anslutande VPN-klienten.
3. Kontrollera forwarding/brandvägg/NAT i panelen. Testa en känd TCP-tjänst, UDP om
   tillgängligt och ping om målet tillåter det.
4. Kontrollera att en adress utanför listan blockeras och att HA-proxyn fungerar.
5. Starta om och upprepa. Stäng av gatewayläget och verifiera att LAN-trafiken
   blockeras men HA fortsätter fungera genom proxyn.

Om det inte fungerar: kopiera diagnostiken. Höj inte behörigheterna och aktivera
inte host networking för att kringgå ett fel.
