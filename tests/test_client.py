import base64
import sys
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'wireguard_client'))
spec = importlib.util.spec_from_file_location('client', ROOT / 'wireguard_client/client.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def options():
    return dict(private_key=base64.b64encode(b'x'*32).decode(), peer_public_key=base64.b64encode(b'y'*32).decode(), preshared_key='', endpoint_host='vpn.example.com', endpoint_port=51820, tunnel_address='10.77.0.2/32', allowed_ips=['10.77.0.1/32','192.168.10.0/24'], mtu=1380, persistent_keepalive=25, homeassistant_host="homeassistant", homeassistant_port=8123)


class ClientTests(unittest.TestCase):
    def test_log_has_utc_timestamp_and_level(self):
        import io
        stream=io.StringIO()
        original_handlers=c.LOG.handlers[:]
        original_level=c.LOG.level
        original_propagate=c.LOG.propagate
        try:
            with patch.object(c.sys,'stdout',stream):
                c.configure_logging()
            c.LOG.info('Handshake healthy')
            self.assertRegex(stream.getvalue(), r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \[INFO\] Handshake healthy\n$')
            self.assertIs(c.LOG.handlers[0].formatter.converter,c.time.gmtime)
        finally:
            c.LOG.handlers=original_handlers
            c.LOG.setLevel(original_level)
            c.LOG.propagate=original_propagate

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

    def test_whole_tunnel_subnet_supported(self):
        o = options()
        o['tunnel_address'] = '192.168.101.20/32'
        o['allowed_ips'] = ['192.168.101.0/24']
        self.assertEqual(c.validate(o)['allowed_ips'], ['192.168.101.0/24'])
        with patch.object(c,'run',return_value='[{"dst":"default"},{"dst":"172.30.32.0/23"}]'):
            c.check_routes(o)

    def test_whole_subnet_still_rejects_backend_and_endpoint_loops(self):
        o = options(); o['tunnel_address']='192.168.101.20/32'; o['allowed_ips']=['192.168.101.0/24']
        with patch.object(c.socket,'getaddrinfo',return_value=[(None,None,None,None,('192.168.101.1',51820))]):
            with self.assertRaises(c.ConfigurationError): c.resolve(o)
            with self.assertRaises(c.ConfigurationError): c.resolve_backend(o)

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
        with patch.object(c.Path, 'read_text', return_value=json.dumps(o)), patch.object(c.signal, 'signal'), patch.object(c.os, 'umask'), patch.object(c, 'prepare_identity', return_value=(o,public)), patch.object(c, 'run', return_value=public) as run, patch.dict(sys.modules, {'public_key_ui':ui}), patch.object(c, 'resolve', return_value='203.0.113.1'), patch.object(c, 'resolve_backend', return_value='172.30.32.1'), patch.object(c, 'start'), patch.object(c, 'start_proxy'), patch.object(c, 'stop_proxy'), patch.object(c, 'monitor'), patch.object(c, 'remove_owned') as cleanup, patch('builtins.print'):
            c.main()
        run.assert_any_call('iptables', '-w', '5', '-P', 'FORWARD', 'DROP')
        self.assertEqual(ui.start.call_args.args[:2], (public, None))
        ui.start.return_value.shutdown.assert_called_once()
        ui.start.return_value.server_close.assert_called_once()
        cleanup.assert_called_once()

    def test_backend_tunnel_loop_rejected(self):
        for address in ('10.77.0.2', '192.168.10.42'):
            with patch.object(c.socket, 'getaddrinfo', return_value=[(None,None,None,None,(address,8123))]), self.assertRaises(ValueError):
                c.resolve_backend(options())

    def test_backend_valid(self):
        with patch.object(c.socket, 'getaddrinfo', return_value=[(None,None,None,None,('172.30.32.1',8123))]):
            self.assertEqual(c.resolve_backend(options()), '172.30.32.1')

    def test_backend_options_reject_injection(self):
        for field, value in [('homeassistant_host','ha,exec=bad'), ('homeassistant_port',0), ('homeassistant_port',True)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                o = options(); o[field] = value; c.validate(o)

    def test_proxy_binds_tunnel_only(self):
        with patch.object(c.subprocess, 'Popen') as popen:
            c.start_proxy(options(), '172.30.32.1')
        args = popen.call_args.args[0]
        self.assertEqual(args[1], 'TCP4-LISTEN:8123,bind=10.77.0.2,reuseaddr,fork,max-children=32')
        self.assertEqual(args[2], 'TCP4:172.30.32.1:8123,connect-timeout=10')
        self.assertTrue(popen.call_args.kwargs['start_new_session'])

    def test_empty_keys_explain_configuration_before_start(self):
        for field in ('private_key', 'peer_public_key'):
            with self.subTest(field=field):
                o = options(); o[field] = ''
                with self.assertRaises(c.ConfigurationError) as caught:
                    c.validate(o)
                message = c.failure_message(caught.exception)
                self.assertIn(field + ' is empty', message)
                self.assertIn('Configuration tab', message)
                self.assertNotIn('NET_ADMIN', message)

    def test_validation_errors_never_echo_input_secrets(self):
        secret = 'SECRET_DO_NOT_LOG'
        for field in ('private_key','peer_public_key','preshared_key','endpoint_host','homeassistant_host','tunnel_address','allowed_ips','mtu'):
            o = options(); o[field] = [secret] if field == 'allowed_ips' else secret + '!'
            with self.subTest(field=field), self.assertRaises(c.ConfigurationError) as caught:
                c.validate(o)
            self.assertNotIn(secret, c.failure_message(caught.exception))
        self.assertNotIn(secret, c.failure_message(ValueError(secret)))

    def test_key_paste_whitespace_is_accepted(self):
        o = options(); o['private_key'] = '  ' + o['private_key'] + '\n'
        self.assertEqual(c.validate(o)['private_key'], options()['private_key'])

    def test_route_error_names_networks(self):
        with patch.object(c, 'run', return_value='[{"dst":"192.168.10.0/24"}]'), self.assertRaises(c.ConfigurationError) as caught:
            c.check_routes(options())
        self.assertIn('192.168.10.0/24', c.failure_message(caught.exception))
        self.assertIn('container route', c.failure_message(caught.exception))

    def test_empty_configuration_stays_in_setup_without_network_changes(self):
        import sys
        o = options(); o['peer_public_key'] = ''
        ui = Mock()
        with patch.object(c.Path,'read_text',return_value=json.dumps(o)), patch.object(c.signal,'signal'), patch.object(c.os,'umask'), patch.object(c, 'prepare_identity', return_value=(o, options()['peer_public_key'])), patch.object(c,'run') as run, patch.object(c,'start') as start, patch.object(c.STOP, 'wait') as wait, patch.dict(sys.modules, {'public_key_ui':ui}), patch('builtins.print'):
            c.main()
        run.assert_not_called()
        start.assert_not_called()
        wait.assert_called_once_with()
        self.assertIn('peer_public_key is empty', ui.start.call_args.args[1])
        ui.start.return_value.shutdown.assert_called_once()

    def test_identity_generated_once_and_persisted(self):
        import tempfile
        private = options()['private_key']; public = options()['peer_public_key']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client-private.key'
            with patch.object(c, 'run', side_effect=[private,public]) as run:
                first, first_public = c.prepare_identity({'private_key':''}, path)
            run.assert_any_call('wg','genkey')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text().strip(), private)
            with patch.object(c, 'run', return_value=public) as run:
                second, second_public = c.prepare_identity({'private_key':''}, path)
            run.assert_called_once_with('wg','pubkey',input=private+'\n')
            self.assertEqual((first,first_public), (second,second_public))

    def test_supplied_identity_is_preserved_when_field_cleared(self):
        import tempfile
        private = options()['private_key']; public = options()['peer_public_key']
        with tempfile.TemporaryDirectory() as directory, patch.object(c, 'run', return_value=public) as run:
            path = Path(directory) / 'client-private.key'
            c.prepare_identity({'private_key':private}, path)
            result, _ = c.prepare_identity({'private_key':''}, path)
            self.assertEqual(result['private_key'],private)
            self.assertFalse(any(call.args == ('wg','genkey') for call in run.call_args_list))

    def test_corrupt_saved_identity_never_silently_rotates(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory, patch.object(c, 'run') as run:
            path = Path(directory) / 'client-private.key'; path.write_text('corrupted-secret')
            with self.assertRaises(c.ConfigurationError):
                c.prepare_identity({'private_key':''},path)
            run.assert_not_called()
            self.assertEqual(path.read_text(),'corrupted-secret')

    def test_secret_not_in_error(self):
        import subprocess
        with patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','SECRET')), self.assertRaises(RuntimeError) as caught:
            c.run('wg','setconf','secret')
        self.assertNotIn('SECRET',str(caught.exception))

if __name__ == '__main__': unittest.main()
