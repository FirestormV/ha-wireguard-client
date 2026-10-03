"""Read-only public key page, accessible exclusively through HA Ingress."""
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

INGRESS_SOURCE = "172.30.32.2"


def render(public_key, setup_error=None):
    message = html.escape(setup_error or "", quote=True)
    return ('''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireGuard Client</title>
<style>
:root { color-scheme: light dark; font: 16px system-ui, sans-serif; }
body { max-width: 760px; margin: 8vh auto; padding: 24px; }
label { display: block; margin-top: 28px; font-weight: 600; }
input { box-sizing: border-box; width: 100%; padding: 14px; margin: 12px 0; font: 14px monospace; }
button, select { padding: 10px 16px; font: inherit; }
#feedback { min-height: 1.5em; }
</style>
<select id="language" aria-label="Language"><option value="en">English</option><option value="sv">Svenska</option></select>
<h1>WireGuard Client</h1>
<p id="steps">Your client key is ready. Copy the public key to the pfSense peer, then fill in the pfSense public key, endpoint and networks in Configuration. Save and restart the add-on. Leave Client private key empty to keep using the saved key.</p>
<p role="status">''' + message + '''</p>
<label id="label" for="key">Client public key</label>
<input id="key" readonly spellcheck="false" value="''' + html.escape(public_key, quote=True) + '''">
<button id="copy" type="button">Copy public key</button>
<p id="feedback" role="status"></p>
<p id="help">Paste this into the Public Key field of the client peer in pfSense.</p>
<p id="note">Derived from the private key loaded at startup. Restart the add-on after changing its configuration. A working tunnel is not required to view this key.</p>
<hr><h2 id="diagTitle">Diagnostics</h2>
<p id="diagHelp">Refresh shows container network state. Start a 15-second capture, then ping the tunnel address from pfSense or open HA through the tunnel. No packet payloads are displayed.</p>
<button id="refresh">Refresh diagnostics</button>
<button id="probe">Test HA backend TCP</button>
<button id="capture">Capture 15 seconds</button>
<button id="download">Download report</button>
<p id="diagStatus" role="status"></p>
<pre id="diagOutput" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
<script>
const texts = {
en: {diagTitle:'Diagnostics',diagHelp:'Refresh shows container network state. Start a 15-second capture, then ping the tunnel address from pfSense or open HA through the tunnel. No packet payloads are displayed.',refresh:'Refresh diagnostics',probe:'Test HA backend TCP',capture:'Capture 15 seconds',download:'Download report',steps:'Your client key is ready. Copy the public key to the pfSense peer, then fill in the pfSense public key, endpoint and networks in Configuration. Save and restart the add-on. Leave Client private key empty to keep using the saved key.',label:'Client public key',copy:'Copy public key',help:'Paste this into the Public Key field of the client peer in pfSense.',note:'Derived from the private key loaded at startup. Restart the add-on after changing its configuration. A working tunnel is not required to view this key.',copied:'Copied.',manual:'Key selected. Use your device’s copy command.'},
sv: {diagTitle:'Diagnostik',diagHelp:'Uppdatera visar tilläggets nätverksstatus. Starta 15 sekunders fångst och pinga sedan tunneladressen från pfSense eller öppna HA via tunneln. Inget paketinnehåll visas.',refresh:'Uppdatera diagnostik',probe:'Testa TCP till HA',capture:'Fånga 15 sekunder',download:'Ladda ner rapport',steps:'Din klientnyckel är klar. Kopiera den publika nyckeln till klientens peer i pfSense. Fyll sedan i pfSense publika nyckel, endpoint och nät under Konfiguration. Spara och starta om tillägget. Lämna Klientens privata nyckel tom för att fortsätta använda den sparade nyckeln.',label:'Klientens publika nyckel',copy:'Kopiera publik nyckel',help:'Klistra in den i fältet Public Key för klientens peer i pfSense.',note:'Beräknad från den privata nyckel som lästes in vid start. Starta om tillägget efter konfigurationsändringar. Tunneln behöver inte ha kontakt för att visa nyckeln.',copied:'Kopierad.',manual:'Nyckeln är markerad. Använd enhetens kopieringskommando.'}
};
const language = document.getElementById('language');
language.value = navigator.language.toLowerCase().startsWith('sv') ? 'sv' : 'en';
function update() {
 document.documentElement.lang = language.value;
 for (const id of ['steps','label','copy','help','note','diagTitle','diagHelp','refresh','probe','capture','download']) document.getElementById(id).textContent = texts[language.value][id];
 document.getElementById('feedback').textContent = '';
}
language.onchange = update; update();
document.getElementById('copy').onclick = async () => {
 const key = document.getElementById('key');
 try { await navigator.clipboard.writeText(key.value); document.getElementById('feedback').textContent = texts[language.value].copied; }
 catch (_) { key.focus(); key.select(); document.getElementById('feedback').textContent = texts[language.value].manual; }
};
let report = {};
async function requestReport(path, section, active=false) {
 const status = document.getElementById('diagStatus');
 status.textContent = language.value === 'sv' ? 'Arbetar… Kör ping nu om fångst valdes.' : 'Working… Send ping now if capturing.';
 try {
  const response = await fetch('./' + path, active ? {method:'POST',headers:{'X-Diagnostics-Action':'1'}} : {cache:'no-store'});
  if (!response.ok) throw new Error('HTTP ' + response.status);
  report[section] = await response.json();
  document.getElementById('diagOutput').textContent = JSON.stringify(report,null,2);
  status.textContent = language.value === 'sv' ? 'Klart. Rapporten innehåller nätadresser; granska före delning.' : 'Done. Report contains network addresses; review before sharing.';
 } catch (error) { status.textContent = 'Error: ' + error.message; }
}
document.getElementById('refresh').onclick = () => requestReport('diagnostics','snapshot');
document.getElementById('probe').onclick = () => requestReport('probe-backend','backend_test',true);
document.getElementById('capture').onclick = async () => {
 const button=document.getElementById('capture'); button.disabled=true;
 try { await requestReport('capture','capture',true); } finally { button.disabled=false; }
};
document.getElementById('download').onclick = () => {
 const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
 const link=document.createElement('a'); link.href=url; link.download='wireguard-diagnostics.json'; link.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
};
</script></html>''').encode()


def handler_for(public_key, setup_error=None, diagnostics=None):
    page = render(public_key, setup_error)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Trust only the socket peer, never forwarded headers.
            if self.client_address[0] != INGRESS_SOURCE:
                self.send_error(403)
                return
            if self.path == "/diagnostics" and diagnostics is not None:
                self.send_json(diagnostics.snapshot())
                return
            if self.path not in ("/", "/index.html"):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(page)

        def send_json(self, data):
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.client_address[0] != INGRESS_SOURCE or self.headers.get("X-Diagnostics-Action") != "1":
                self.send_error(403)
                return
            if diagnostics is None:
                self.send_error(503)
            elif self.path == "/capture":
                self.send_json(diagnostics.capture())
            elif self.path == "/probe-backend":
                self.send_json(diagnostics.probe_backend())
            else:
                self.send_error(404)

        def log_message(self, *_):
            pass  # Do not log ingress paths or request metadata.

    return Handler


def start(public_key, setup_error=None, diagnostics=None):
    # Port 8099 exists only inside this add-on network; no host port is published.
    server = ThreadingHTTPServer(("0.0.0.0", 8099), handler_for(public_key, setup_error, diagnostics))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
