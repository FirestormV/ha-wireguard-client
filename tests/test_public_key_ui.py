import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('public_key_ui', ROOT / 'wireguard_client/public_key_ui.py')
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
PUBLIC = 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg='


class UITests(unittest.TestCase):
    def request(self, address, path='/', forwarded=None):
        handler = object.__new__(ui.handler_for(PUBLIC))
        handler.client_address = (address, 1234)
        handler.path = path
        handler.headers = {'X-Forwarded-For': forwarded} if forwarded else {}
        handler.wfile = io.BytesIO()
        with patch.object(handler, 'send_response') as response, patch.object(handler, 'send_header') as header, patch.object(handler, 'end_headers'), patch.object(handler, 'send_error') as error:
            handler.do_GET()
        return handler.wfile.getvalue(), response, header, error

    def test_ingress_gets_readonly_public_key(self):
        body, response, header, error = self.request(ui.INGRESS_SOURCE)
        response.assert_called_once_with(200)
        error.assert_not_called()
        self.assertIn(PUBLIC.encode(), body)
        self.assertIn(b'readonly', body)
        header.assert_any_call('Cache-Control', 'no-store')

    def test_direct_access_and_spoofed_headers_denied(self):
        for source in ('127.0.0.1', '192.168.10.1', '10.77.0.1'):
            body, response, _, error = self.request(source, forwarded=ui.INGRESS_SOURCE)
            error.assert_called_once_with(403)
            response.assert_not_called()
            self.assertEqual(body, b'')

    def test_no_file_access(self):
        for path in ('/data/options.json', '/../client.py', '/?private_key=yes'):
            body, _, _, error = self.request(ui.INGRESS_SOURCE, path)
            error.assert_called_once_with(404)
            self.assertEqual(body, b'')

    def test_render_escapes_input(self):
        body = ui.render('\"><script>alert(1)</script>')
        self.assertNotIn(b'\"><script>alert(1)</script>', body)
        self.assertIn(b'&lt;script&gt;', body)

    def test_supervisor_port(self):
        with patch.dict(ui.os.environ, {'SUPERVISOR_TOKEN': 'test-token'}), patch.object(ui, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value = io.StringIO('{"result":"ok","data":{"ingress_port":12345}}')
            self.assertEqual(ui.ingress_port(), 12345)
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, 'http://supervisor/addons/self/info')
            self.assertEqual(req.get_header('Authorization'), 'Bearer test-token')

    def test_invalid_supervisor_ports(self):
        for port in (0, 65536, True, '12345'):
            with self.subTest(port=port), patch.dict(ui.os.environ, {'SUPERVISOR_TOKEN': 'test-token'}), patch.object(ui, 'build_opener') as opener:
                opener.return_value.open.return_value.__enter__.return_value = io.StringIO(ui.json.dumps({'result':'ok','data':{'ingress_port':port}}))
                with self.assertRaises(ValueError): ui.ingress_port()

if __name__ == '__main__': unittest.main()
