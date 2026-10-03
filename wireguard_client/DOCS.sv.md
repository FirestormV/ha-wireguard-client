# WireGuard Client för Home Assistant OS

[Full documentation in English](DOCS.md)

Version 0.2.2 är experimentell. IPv4, en pfSense-peer, amd64 och aarch64.

## Isolerat nätverk

Hemdator → pfSense → WireGuard → tilläggets tunneladress:8123 → TCP-proxy → HA Core.

Tunnelgränssnittet och dess routes finns nu bara i tilläggets nätverksnamespace. Host networking används inte och inga portar publiceras på värden. NET_ADMIN gäller tilläggets nätverk. Vidarebefordran av IP-paket blockeras inne i containern, AppArmor är aktiverat och inget Supervisor-API behövs.

TCP-proxyn lyssnar bara på tunneladressen, port 8123, och ansluter till ett konfigurerat mål, normalt `homeassistant:8123`. Den hanterar upp till 32 samtidiga anslutningar och vidarebefordrar rå TCP: HTTP, WebSocket och TLS kan passera utan ändrade HTTP-headers eller avslutad TLS-kryptering. HA:s vanliga inloggning behövs.

HA ser tilläggets interna IP som källa, inte hemklientens ursprungliga adress. Kontrollera eventuella IP-blockeringar och trusted-network-inloggning; ge inte containern bred lösenordsfri åtkomst. Ingen ny `trusted_proxies`-inställning behövs för TCP-proxyn.

Containern delar fortfarande kärna, CPU och minne med värden. Det här begränsar risken för routingfel men är inte samma isolering som en separat virtuell maskin.

## Uppgradering från 0.1.x

0.1.x använde värdens nätverk. 0.2.0 är därför markerad som en ändring som kräver manuell uppdatering.

1. Anslut via HA:s vanliga lokala adress. Stäng av det gamla tilläggets **Start vid uppstart** och **Watchdog**, och **stoppa det före uppdateringen**. Normalt stopp tar bort det gamla tunnelgränssnittet och dess routes.
2. Om tillägget tidigare kraschade: kontrollera från HA OS värdkonsol om något finns kvar med `ip link show dev wg-ha-client` och `ip -4 route show dev wg-ha-client`. Nya versionen kan inte städa bort gamla gränssnitt på värden. Om sådana finns kvar, håll autostart avstängd och gör en kontrollerad HA OS-omstart innan du fortsätter. Ta inte bort andra nätverksgränssnitt eller routes.
3. Uppdatera till 0.2.0. Nycklar och inställningar behålls. Anpassa `homeassistant_host` och `homeassistant_port` om Core inte nås på `homeassistant:8123`.
4. Starta manuellt och testa både lokal åtkomst och tunneln. Aktivera autostart först efter fungerande tester.

Tunneladressen fungerar som tidigare för HA, exempelvis `http://10.77.0.2:8123`. Andra tjänster på HA-värden och hela fjärr-LAN exponeras inte. Om Core använder TLS måste du använda HTTPS med värdnamn som matchar dess certifikat. Proxyn skapar inga certifikat.

## Första start: inga nycklar behövs

1. Lämna `private_key` och `peer_public_key` tomma och starta tillägget.
2. Välj **Öppna webbgränssnitt**. Tillägget skapar ett klientnyckelpar och visar den publika nyckeln. Med ofärdig tunnelkonfiguration stannar det i installationsläge utan att skapa tunnel eller ändra routes/brandvägg.
3. Kopiera den publika nyckeln till klientens peer i pfSense.
4. Fyll i pfSense publika nyckel, endpoint och nät under **Konfiguration**. Lämna `private_key` tom för att använda den sparade nyckeln. Spara och starta om.

Privata nyckeln sparas atomiskt med rättigheter 0600 i `/data/client-private.key`, behålls vid omstart/uppdatering och ingår i säkerhetskopior av tilläggets data. Den visas aldrig i webbsidan eller loggen. Skydda säkerhetskopiorna. Ominstallation utan återställda data ger en ny identitet; använd inte samma identitet på flera samtidiga klienter.

En egen privat nyckel i konfigurationen används och sparas som aktuell identitet. Om fältet sedan töms återanvänds den sist sparade nyckeln. En skadad sparad nyckel ersätts inte automatiskt. Felaktiga tunnelinställningar lämnar webbsidan tillgänglig i installationsläge. Rätta dem, spara och starta om; ändringar tillämpas inte automatiskt under körning.

## Installation och nycklar

Lägg till `https://github.com/FirestormV/ha-wireguard-client` i tilläggsbutikens Repositories, installera, konfigurera och starta manuellt. Lokalt kan katalogen `wireguard_client` kopieras till `/addons/wireguard_client` via Samba/SSH. Supervisor bygger imagen och behöver internetåtkomst.

Automatisk nyckelhantering rekommenderas. Om du vill importera egna nycklar kan du generera dem på en betrodd dator eller i pfSense Shell:

```sh
umask 077
wg genkey > ha-private.key
wg pubkey < ha-private.key > ha-public.key
```

Privata klientnyckeln hör hemma i tillägget. Publika klientnyckeln ska till klientens peer i pfSense. pfSense-tunnelns publika nyckel ska till `peer_public_key`. Valfri delad PSK från `wg genpsk` måste matcha på båda sidor.

```yaml
private_key: ""  # Skapa/återanvänd sparad klientnyckel automatiskt
peer_public_key: "PFSENSE_PUBLIKA_NYCKEL"
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

Byt exempelnäten till dina egna. `allowed_ips` innehåller pfSense tunnel-IP och hemnäten som behöver nå HA. Dessa blir returvägar inne i tillägget. Ange inte fjärr-LAN, Core-målets adress eller default route. Överlapp med containerns Docker-nät avvisas.

Keepalive kan vara 0–65535 sekunder; standard 25 passar CGNAT, 0 stänger av. MTU kan vara 1280–1420, standard 1380. `tunnel_address` måste vara IPv4 /32. IPv6 och full tunnel stöds inte. `homeassistant_host` är DNS-namn eller IPv4 för Core, och `homeassistant_port` dess TCP-port. Porten på tunnelsidan är alltid 8123.

Core måste lyssna på en adress som är nåbar från det interna tilläggsnätet. Målets DNS-adress läses vid start; starta om tillägget om adressen ändras. Om Core tillfälligt är nere kan nya anslutningar fungera när det kommer tillbaka på samma IP.

Nycklarna lagras i Supervisors inställningar och kan ingå i säkerhetskopior. UI-maskering innebär inte separat kryptering. Den tillfälliga WireGuard-konfigurationen har rättigheter 0600 och raderas efter inläsning.

## Visa publik nyckel

Med startat tillägg, även när nyckelfälten är tomma: välj **Öppna webbgränssnitt**. Sidan visar den publika nyckeln i ett skrivskyddat fält med kopieringsknapp. Den härleds från privata nyckeln vid start; starta om efter ändring. Privata nyckeln skapas vid första start om den saknas, men visas aldrig på sidan.

Sidan fungerar under DNS-väntan och utan handshake, men inte om processen är stoppad eller misslyckas vid start. HA Ingress ger åtkomst; endast Supervisors källadress 172.30.32.2 tillåts. Port 8099 finns bara i tillägget. Engelska/svenska kan väljas på sidan. Vid nekad automatisk kopiering markeras nyckeln för manuell kopiering.

## pfSense

1. Tunnel med exempeladress `10.77.0.1/24`, lyssningsport UDP 51820 och eget nyckelpar.
2. Peer med klientens publika nyckel, **Dynamic Endpoint**, tom endpoint och Allowed IPs `10.77.0.2/32`. PSK ska matcha om den används.
3. WAN-regel som tillåter UDP till WAN-adressen på port 51820. Öppna inte HA-port 8123 på WAN.
4. Hem-LAN/VLAN: tillåt avsedda klienter till `10.77.0.2` TCP 8123, före policy-routingregler och utan vald WAN/VPN-gateway.
5. Kontrollera route till `10.77.0.0/24` via tunneln och att hemklienterna använder pfSense för det nätet. Behåll WAN som default gateway.
6. Bred allow-any från tunneln och NAT mellan hemnät och tunnel behövs inte för hemifrån initierade anslutningar. Granska egna floating/group- och NAT-regler.

pfSense måste vara nåbar via publik IPv4 eller fungerande UDP-portvidarebefordran. CGNAT på fjärrsidan fungerar med utgående trafik och keepalive. Om båda sidor saknar inkommande nåbarhet behövs en annan knutpunkt. Ingen portvidarebefordran krävs på fjärrsidan.

## Test och felsökning

- Kontrollera aktuell handshake i pfSense och **Handshake healthy** i loggen.
- Prova HA:s vanliga lokala adress samt tunneladressen. Testa inloggning och realtidsuppdateringar. HTTPS kräver rätt certifikatnamn.
- Kontrollera publika nyckeln på webbsidan mot logg och pfSense.
- Stoppa tillägget: tunneln ska sluta fungera medan lokal HA-åtkomst består. Starta och kontrollera återhämtning.
- Prova kontrollerat internetavbrott, tilläggsomstart och HA OS-omstart. Använd inte strömavbrott som test.
- Värdens routes ska inte ändras av tunnelstart/stopp. `wg-ha-client` ska bara finnas inne i tillägget.

Utan handshake: kontrollera UDP, endpoint och nycklar. Med handshake men utan HTTP: kontrollera pfSense-regler, hemklientens nät i `allowed_ips`, Core-adress/port och lyssningsinställningar. En IP-blockering av tilläggets adress i Core påverkar alla tunnelklienter. Om stora överföringar fastnar, prova MTU 1280.

Efter 180 sekunder utan aktuell handshake uppdateras endpoint via DNS var 30:e sekund. DNS-fel vid start väntas ut. Watchdog upptäcker processfel, inte alla nätfel. HA OS/Supervisor/AppArmor, riktig HA-inloggning/WebSocket/TLS, pfSense/CGNAT och aarch64 behöver verifieras i målmiljön även efter godkända CI-tester.

## Framtida fjärr-LAN

Denna version är avsiktligt en TCP-väg till HA. Den vidarebefordrar inte IP-paket till hela fjärr-LAN.

En framtida LAN-gateway bör vara separat, helst på fjärrroutern eller en dedikerad gateway, med egen peer-identitet. Då behövs fjärrsubnät i pfSense-peerens Allowed IPs, matchande routes, smala forwardingregler och returroute på fjärrroutern eller begränsad SNAT. HA-tillägget kan då behålla isoleringen. Broadcast/mDNS kräver separat hantering.

Källor och fullständiga tekniska detaljer finns i [den engelska guiden](DOCS.md).
