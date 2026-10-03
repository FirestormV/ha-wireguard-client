import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('client', ROOT / 'wireguard_client/client.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def options():
    return dict(private_key=base64.b64encode(b'x'*32).decode(), peer_public_key=base64.b64encode(b'y'*32).decode(), preshared_key='', endpoint_host='vpn.example.com', endpoint_port=51820, tunnel_address='10.77.0.2/32', allowed_ips=['10.77.0.1/32','192.168.10.0/24'], mtu=1380, persistent_keepalive=25)


class ClientTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(c.validate(options()), options())

    def test_legacy_options_default(self):
        o = options()
        del o['persistent_keepalive']
        self.assertEqual(c.validate(o)['persistent_keepalive'], 25)

    def test_keepalive_validation(self):
        for value in (0, 1, 25, 60, 65535):
            with self.subTest(value=value):
                o = options(); o['persistent_keepalive'] = value
                self.assertEqual(c.validate(o)['persistent_keepalive'], value)
        for value in (-1, 65536, True, 25.5, '25', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                o = options(); o['persistent_keepalive'] = value
                c.validate(o)

    def test_invalid_config(self):
        cases = [('private_key','bad'), ('peer_public_key','x\nPostUp=bad'), ('endpoint_host','x\nPostUp=bad'), ('endpoint_port',0), ('mtu',9000), ('tunnel_address','10.77.0.2/24'), ('allowed_ips',['0.0.0.0/0']), ('allowed_ips',['192.168.10.1/24']), ('allowed_ips',['10.77.0.2/32']), ('allowed_ips',['::/0']), ('allowed_ips',['10.0.0.0/8','10.1.0.0/16'])]
        for field, value in cases:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                o = options(); o[field] = value; c.validate(o)

    def test_endpoint_recursion(self):
        with patch.object(c.socket, 'getaddrinfo', return_value=[(None,None,None,None,('192.168.10.20',51820))]), self.assertRaises(ValueError):
            c.resolve(options())

    def test_foreign_interface_preserved(self):
        with patch.object(c,'links',return_value=[{'ifname':c.IFACE}]), patch.object(c,'run') as run, self.assertRaises(RuntimeError):
            c.remove_owned()
        run.assert_not_called()

    def test_crash_cleanup(self):
        with patch.object(c,'links',return_value=[{'ifname':c.IFACE,'ifalias':c.OWNER}]), patch.object(c,'run') as run:
            c.remove_owned()
        run.assert_called_once_with('ip','link','delete','dev',c.IFACE)

    def test_route_collision(self):
        with patch.object(c,'run',return_value=json.dumps([{'dst':'192.168.10.0/24'}])), self.assertRaises(ValueError):
            c.check_routes(options())

    def test_default_route_permitted(self):
        with patch.object(c,'run',return_value=json.dumps([{'dst':'default'},{'dst':'172.30.32.0/23'}])):
            c.check_routes(options())

    def test_start_and_keepalive(self):
        commands=[]; configs=[]
        def run(*args, **kwargs):
            commands.append(args)
            if args[:2] == ('wg','setconf'):
                p=Path(args[-1]); configs.append(p.read_text())
                self.assertEqual(p.stat().st_mode & 0o777,0o600)
            return ''
        with patch.object(c,'remove_owned'), patch.object(c,'check_routes'), patch.object(c,'run',side_effect=run):
            for value in (0, 25, 60, 65535):
                o = options(); o['persistent_keepalive'] = value
                c.start(o,'203.0.113.1')
        for value, config in zip((0, 25, 60, 65535), configs):
            self.assertIn(f'PersistentKeepalive = {value}\n', config)
        self.assertIn(('ip','-4','route','add','192.168.10.0/24','dev',c.IFACE),commands)
        self.assertFalse(any('replace' in cmd for cmd in commands))

    def test_partial_failure_cleanup(self):
        commands=[]
        def run(*args,**kwargs):
            commands.append(args)
            if args[:2] == ('wg','setconf'): raise RuntimeError('failure')
            return ''
        with patch.object(c,'remove_owned'), patch.object(c,'check_routes'), patch.object(c,'run',side_effect=run), self.assertRaises(RuntimeError):
            c.start(options(),'203.0.113.1')
        self.assertEqual(commands[-1],('ip','link','delete','dev',c.IFACE))

    def test_public_key_ui_lifecycle(self):
        import sys
        ui = Mock()
        o = options()
        public = o['peer_public_key']
        with patch.object(c.Path, 'read_text', return_value=json.dumps(o)), patch.object(c.signal, 'signal'), patch.object(c.os, 'umask'), patch.object(c, 'run', return_value=public) as run, patch.dict(sys.modules, {'public_key_ui':ui}), patch.object(c, 'resolve', return_value='203.0.113.1'), patch.object(c, 'start'), patch.object(c, 'monitor'), patch.object(c, 'remove_owned') as cleanup, patch('builtins.print'):
            c.main()
        run.assert_called_once_with('wg', 'pubkey', input=o['private_key'] + '\n')
        ui.start.assert_called_once_with(public)
        ui.start.return_value.shutdown.assert_called_once()
        ui.start.return_value.server_close.assert_called_once()
        cleanup.assert_called_once()

    def test_secret_not_in_error(self):
        import subprocess
        with patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','SECRET')), self.assertRaises(RuntimeError) as caught:
            c.run('wg','setconf','secret')
        self.assertNotIn('SECRET',str(caught.exception))

if __name__ == '__main__': unittest.main()
