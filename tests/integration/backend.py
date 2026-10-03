"""HTTP plus opaque upgraded TCP fixture; no HA credentials or live HA needed."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Upgrade') == 'wireguard-test':
            self.send_response(101)
            self.send_header('Connection', 'Upgrade')
            self.send_header('Upgrade', 'wireguard-test')
            self.end_headers()
            data = self.rfile.read(256)
            self.wfile.write(data)
            self.wfile.flush()
            return
        data = b'HA backend fixture OK'
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

ThreadingHTTPServer(('0.0.0.0',8123),Handler).serve_forever()
