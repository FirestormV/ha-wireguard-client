import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'wireguard_client'))
import gateway as g


def options():
    return {'site_to_site': True, 'local_networks': ['192.168.1.0/24'],
            'allowed_ips': ['10.77.0.0/24'], 'tunnel_address': '10.77.0.2/32'}


class GatewayTests(unittest.TestCase):
    def test_valid_multiple_and_host_destinations(self):
        o = options(); o['local_networks'] += ['192.168.20.0/24', '192.168.30.5/32']
        g.validate(o)
        self.assertEqual(len(o['local_networks']), 3)

    def test_invalid_destinations(self):
        cases = [[], ['bad'], ['::/0'], ['192.168.1.5/24'], ['192.168.1.5'],
                 ['0.0.0.0/0'], ['0.1.0.0/16'], ['127.0.0.0/8'], ['224.0.0.0/4'],
                 ['240.1.1.1/32'], ['169.254.0.0/16'], ['10.77.0.0/24'],
                 ['192.168.1.0/24', '192.168.1.5/32'], None, '192.168.1.0/24']
        for value in cases:
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                o = options(); o['local_networks'] = value; g.validate(o)

    def test_disabled_allows_empty_but_not_invalid_networks(self):
        o = options(); o.update(site_to_site=False, local_networks=[]); g.validate(o)
        o['local_networks'] = ['SECRET']
        with self.assertRaises(g.GatewayError) as caught: g.validate(o)
        self.assertNotIn('SECRET', str(caught.exception))

    def test_mode_requires_boolean(self):
        for mode in ('true', 1, None):
            o = options(); o['site_to_site'] = mode
            with self.assertRaises(g.GatewayError): g.validate(o)

    def test_disabled_does_not_require_or_write_sysctl(self):
        o = options(); o['site_to_site'] = False
        gateway = g.Gateway(o)
        with patch.object(gateway, 'cleanup') as cleanup, patch.object(g, 'forwarding') as forwarding:
            gateway.start()
        cleanup.assert_called_once(); forwarding.assert_not_called()

    def test_enabled_without_forwarding_fails_closed(self):
        gateway = g.Gateway(options())
        with patch.object(gateway, 'cleanup') as cleanup, patch.object(g, 'forwarding', return_value=False), patch.object(gateway, 'iptables') as iptables:
            with self.assertRaisesRegex(g.GatewayError, 'No sysctl'): gateway.start()
        cleanup.assert_called_once(); iptables.assert_not_called()

    def test_internal_and_wrong_egress_routes_rejected(self):
        for routes, lookup in [([{'dst': '192.168.1.0/24', 'dev': 'eth0'}], []),
                               ([{'dst': '172.30.32.0/23', 'dev': 'eth0'}], [{'dev': 'wg-ha-client'}]),
                               ([], [{'dev': 'eth0'}])]:
            with patch.object(g, 'execute', side_effect=[subprocess.CompletedProcess([], 0, json.dumps(routes)), subprocess.CompletedProcess([], 0, json.dumps(lookup))]), self.assertRaises(g.GatewayError):
                g.Gateway(options()).check_routes()

    def test_existing_gateway_route_accepted_without_route_mutation(self):
        results = [[], [{'dev': 'eth0', 'gateway': '172.30.32.1'}]]
        gateway = g.Gateway(options())
        with patch.object(g, 'execute', side_effect=[subprocess.CompletedProcess([], 0, json.dumps(r)) for r in results]) as execute:
            gateway.check_routes()
        self.assertEqual(gateway.routes[0]['gateway'], '172.30.32.1')
        self.assertFalse(any('add' in call.args or 'replace' in call.args for call in execute.call_args_list))

    def test_foreign_chain_is_not_modified(self):
        gateway = g.Gateway(options())
        with patch.object(gateway, 'iptables', return_value=subprocess.CompletedProcess([], 0, '-N WG_HA_S2S_FWD')) as run:
            with self.assertRaisesRegex(g.GatewayError, 'another owner'): gateway.cleanup()
        self.assertFalse(any('-F' in call.args or '-X' in call.args or '-D' in call.args for call in run.call_args_list))

    def test_command_errors_hide_stderr(self):
        with patch.object(g.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'SECRET')):
            with self.assertRaises(g.GatewayError) as caught: g.execute('iptables')
        self.assertNotIn('SECRET', str(caught.exception))
