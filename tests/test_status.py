import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'wireguard_client'))
from diagnostics import Diagnostics
import status as s
from health import peer_health


class StatusTests(unittest.TestCase):
    def setup_reader(self):
        self.diag = Diagnostics({'private_key': 'PRIVATE_SECRET', 'preshared_key': 'PSK_SECRET',
            'SUPERVISOR_TOKEN': 'TOKEN_SECRET', 'site_to_site': True, 'local_networks': ['192.168.1.0/24'],
            'tunnel_address': '10.77.0.2/32', 'homeassistant_host': 'homeassistant', 'homeassistant_port': 8123})
        self.diag.stage = 'running'
        self.diag.proxy = Mock(); self.diag.proxy.poll.return_value = None
        self.state = {'enabled': True, 'active': True, 'ip_forward': True, 'firewall': True, 'nat': True,
                      'local_networks': ['192.168.1.0/24'], 'routes': []}
        self.diag.gateway = Mock(); self.diag.gateway.inspect.side_effect = lambda: self.state
        self.fields = {'endpoints': 'PUBLIC\t203.0.113.1:51820', 'allowed-ips': 'PUBLIC\t10.77.0.0/24',
                       'latest-handshakes': 'PUBLIC\t990', 'persistent-keepalive': 'PUBLIC\t25',
                       'transfer': 'PUBLIC\t1000\t2000'}
        self.interface = True
        return self.diag.status_reader

    def command(self, *args):
        if args[0] == 'wg': return self.fields[args[-1]]
        if 'address' in args: return json.dumps([{'ifname': 'wg-ha-client'}] if self.interface else [])
        return '[]'

    def test_health_idle_keepalive_and_never_handshaken(self):
        self.assertEqual(peer_health(0, 0, 1000, 1000)[0], 'Idle')
        self.assertEqual(peer_health(100, 0, 1000, 1000)[0], 'Idle')
        self.assertEqual(peer_health(0, 25, 1000, 10)[0], 'Idle')
        self.assertEqual(peer_health(0, 25, 1000, 1000)[0], 'Warning')
        self.assertEqual(peer_health(990, 25, 1000, 1000)[0], 'Healthy')
        self.assertEqual(peer_health(100, 65535, 1000, 1000)[0], 'Idle')

    def test_rates_and_reset_without_persisted_history(self):
        with patch.object(s.time, 'monotonic', return_value=0) as clock, patch.object(s.time, 'time', return_value=1000):
            reader = self.setup_reader()
            result = reader.collect(self.command)
            self.assertEqual(result['health'], 'Healthy')
            self.assertIsNone(result['wireguard']['peers'][0]['rx_bits_per_second'])
            clock.return_value = 4
            self.fields['transfer'] = 'PUBLIC\t2000\t2500'
            peer = reader.collect(self.command)['wireguard']['peers'][0]
            self.assertEqual(peer['rx_bits_per_second'], 2000)
            self.assertEqual(peer['tx_bits_per_second'], 1000)
            clock.return_value = 8
            self.fields['transfer'] = 'PUBLIC\t1\t1'
            self.assertIsNone(reader.collect(self.command)['wireguard']['peers'][0]['rx_bits_per_second'])

    def test_allowed_ips_supports_wireguard_machine_format(self):
        reader = self.setup_reader()
        self.fields['allowed-ips'] = 'PUBLIC\t10.77.0.0/24 192.168.1.0/24'
        peer = reader.collect(self.command)['wireguard']['peers'][0]
        self.assertEqual(peer['allowed_ips'], ['10.77.0.0/24','192.168.1.0/24'])

    def test_missing_nat_forwarding_and_interface(self):
        for field in ('nat', 'firewall', 'ip_forward', 'interface'):
            reader = self.setup_reader()
            if field == 'interface': self.interface = False
            else: self.state[field] = False
            with patch.object(s.time, 'time', return_value=1000):
                self.assertEqual(reader.collect(self.command)['health'], 'Error')

    def test_disabled_forwarding_zero_is_valid(self):
        reader = self.setup_reader(); self.state.update(enabled=False, active=False, ip_forward=False)
        with patch.object(s.time, 'time', return_value=1000):
            self.assertEqual(reader.collect(self.command)['health'], 'Healthy')

    def test_unavailable_stats_not_fake_zero(self):
        reader = self.setup_reader(); self.fields['transfer'] = 'Unavailable (command failed)'
        with patch.object(s.time, 'time', return_value=1000): result = reader.collect(self.command)
        self.assertEqual(result['health'], 'Warning')
        self.assertIsNone(result['wireguard']['peers'][0]['rx_bits_per_second'])

    def test_status_and_report_never_include_secrets(self):
        reader = self.setup_reader()
        with patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'ENV_SECRET'}):
            result = reader.collect(self.command)
            text = s.text_report(result)
        self.assertNotIn('SECRET', json.dumps(result) + text)
        self.assertIn('PUBLIC', text)

    def test_failure_remains_visible_without_interface(self):
        reader = self.setup_reader(); self.interface = False
        self.diag.stage = 'error'; self.diag.setup_error = 'Firewall failed; tunnel stopped.'
        result = reader.collect(self.command)
        self.assertEqual(result['health'], 'Error')
        self.assertIn('Firewall failed', result['message'])
