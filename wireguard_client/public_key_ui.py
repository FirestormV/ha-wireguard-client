"""Read-only public key page, accessible exclusively through HA Ingress."""
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
from urllib.request import Request, build_opener, ProxyHandler

INGRESS_SOURCE = "172.30.32.2"


def ingress_port():
    request = Request("http://supervisor/addons/self/info", headers={
        "Authorization": "Bearer " + os.environ["SUPERVISOR_TOKEN"]})
    # Never route the Supervisor token through an environment HTTP proxy.
    with build_opener(ProxyHandler({})).open(request, timeout=10) as response:
        result = json.load(response)
    port = result["data"]["ingress_port"]
    if result.get("result") != "ok" or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Supervisor did not provide a valid ingress port")
    return port


def render(public_key):
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
<label id="label" for="key">Client public key</label>
<input id="key" readonly spellcheck="false" value="''' + html.escape(public_key, quote=True) + '''">
<button id="copy" type="button">Copy public key</button>
<p id="feedback" role="status"></p>
<p id="help">Paste this into the Public Key field of the client peer in pfSense.</p>
<p id="note">Derived from the private key loaded at startup. Restart the add-on after changing its configuration. A working tunnel is not required to view this key.</p>
<script>
const texts = {
en: {label:'Client public key',copy:'Copy public key',help:'Paste this into the Public Key field of the client peer in pfSense.',note:'Derived from the private key loaded at startup. Restart the add-on after changing its configuration. A working tunnel is not required to view this key.',copied:'Copied.',manual:'Key selected. Use your device’s copy command.'},
sv: {label:'Klientens publika nyckel',copy:'Kopiera publik nyckel',help:'Klistra in den i fältet Public Key för klientens peer i pfSense.',note:'Beräknad från den privata nyckel som lästes in vid start. Starta om tillägget efter konfigurationsändringar. Tunneln behöver inte ha kontakt för att visa nyckeln.',copied:'Kopierad.',manual:'Nyckeln är markerad. Använd enhetens kopieringskommando.'}
};
const language = document.getElementById('language');
language.value = navigator.language.toLowerCase().startsWith('sv') ? 'sv' : 'en';
function update() {
 document.documentElement.lang = language.value;
 for (const id of ['label','copy','help','note']) document.getElementById(id).textContent = texts[language.value][id];
 document.getElementById('feedback').textContent = '';
}
language.onchange = update; update();
document.getElementById('copy').onclick = async () => {
 const key = document.getElementById('key');
 try { await navigator.clipboard.writeText(key.value); document.getElementById('feedback').textContent = texts[language.value].copied; }
 catch (_) { key.focus(); key.select(); document.getElementById('feedback').textContent = texts[language.value].manual; }
};
</script></html>''').encode()


def handler_for(public_key):
    page = render(public_key)

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


def start(public_key):
    # HA host-network add-ons use a Supervisor-assigned port to avoid collisions.
    server = ThreadingHTTPServer(("0.0.0.0", ingress_port()), handler_for(public_key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
