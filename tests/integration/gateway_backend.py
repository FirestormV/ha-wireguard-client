"""Controlled LAN/HA backend fixture. No access to real devices or credentials."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = bytes(range(256)) * 1024 if self.path == '/bulk' else json.dumps({
            'source': self.client_address[0], 'fixture': True}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', 9999))
        while True:
            data, address = sock.recvfrom(4096)
            sock.sendto(json.dumps({'source': address[0], 'echo': data.decode()}).encode(), address)


threading.Thread(target=udp, daemon=True).start()
ThreadingHTTPServer(('0.0.0.0', 8123), Handler).serve_forever()
