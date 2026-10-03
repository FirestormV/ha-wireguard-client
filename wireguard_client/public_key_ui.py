"""Read-only public key page, accessible exclusively through HA Ingress."""
import html
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
<script>
const texts = {
en: {steps:'Your client key is ready. Copy the public key to the pfSense peer, then fill in the pfSense public key, endpoint and networks in Configuration. Save and restart the add-on. Leave Client private key empty to keep using the saved key.',label:'Client public key',copy:'Copy public key',help:'Paste this into the Public Key field of the client peer in pfSense.',note:'Derived from the private key loaded at startup. Restart the add-on after changing its configuration. A working tunnel is not required to view this key.',copied:'Copied.',manual:'Key selected. Use your device’s copy command.'},
sv: {steps:'Din klientnyckel är klar. Kopiera den publika nyckeln till klientens peer i pfSense. Fyll sedan i pfSense publika nyckel, endpoint och nät under Konfiguration. Spara och starta om tillägget. Lämna Klientens privata nyckel tom för att fortsätta använda den sparade nyckeln.',label:'Klientens publika nyckel',copy:'Kopiera publik nyckel',help:'Klistra in den i fältet Public Key för klientens peer i pfSense.',note:'Beräknad från den privata nyckel som lästes in vid start. Starta om tillägget efter konfigurationsändringar. Tunneln behöver inte ha kontakt för att visa nyckeln.',copied:'Kopierad.',manual:'Nyckeln är markerad. Använd enhetens kopieringskommando.'}
};
const language = document.getElementById('language');
language.value = navigator.language.toLowerCase().startsWith('sv') ? 'sv' : 'en';
function update() {
 document.documentElement.lang = language.value;
 for (const id of ['steps','label','copy','help','note']) document.getElementById(id).textContent = texts[language.value][id];
 document.getElementById('feedback').textContent = '';
}
language.onchange = update; update();
document.getElementById('copy').onclick = async () => {
 const key = document.getElementById('key');
 try { await navigator.clipboard.writeText(key.value); document.getElementById('feedback').textContent = texts[language.value].copied; }
 catch (_) { key.focus(); key.select(); document.getElementById('feedback').textContent = texts[language.value].manual; }
};
</script></html>''').encode()


def handler_for(public_key, setup_error=None):
    page = render(public_key, setup_error)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Trust only the socket peer, never forwarded headers.
            if self.client_address[0] != INGRESS_SOURCE:
                self.send_error(403)
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
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *_):
            pass  # Do not log ingress paths or request metadata.

    return Handler


def start(public_key, setup_error=None):
    # Port 8099 exists only inside this add-on network; no host port is published.
    server = ThreadingHTTPServer(("0.0.0.0", 8099), handler_for(public_key, setup_error))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
