"""Read-only status dashboard, accessible exclusively through HA Ingress."""
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from pathlib import Path

INGRESS_SOURCE = "172.30.32.2"


def render(public_key, setup_error=None):
    template = Path(__file__).with_name('dashboard.html').read_text()
    return template.replace('{{PUBLIC_KEY}}', html.escape(public_key, quote=True)).replace(
        '{{SETUP_ERROR}}', html.escape(setup_error or '', quote=True)).encode()


def handler_for(public_key, setup_error=None, diagnostics=None):
    page = render(public_key, setup_error)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Trust only the socket peer, never forwarded headers.
            if self.client_address[0] != INGRESS_SOURCE:
                self.send_error(403)
                return
            if self.path == "/api/status" and diagnostics is not None:
                self.send_json(diagnostics.status())
                return
            if self.path == "/api/report" and diagnostics is not None:
                self.send_json(diagnostics.report())
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
