import sys
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'wireguard_client'))

spec=importlib.util.spec_from_file_location('diag_test',Path(__file__).resolve().parents[1]/'wireguard_client/diagnostics.py')
d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)

class DiagnosticsTests(unittest.TestCase):
    def test_no_secrets_or_unsafe_wg_commands(self):
        diag=d.Diagnostics({'private_key':'SECRET1','preshared_key':'SECRET2','SUPERVISOR_TOKEN':'SECRET3','allowed_ips':['192.168.101.1/32']})
        with patch.object(d,'command',return_value='') as command, patch.object(d.Path,'read_text',return_value='0'):
            report=diag.snapshot()
        self.assertNotIn('SECRET',json.dumps(report))
        self.assertFalse(any('dump' in call.args or 'showconf' in call.args or 'private-key' in call.args for call in command.call_args_list))
        self.assertIn('192.168.101.1',report['return_route_examples'])

    def test_capture_bounded_no_payload_flags(self):
        diag=d.Diagnostics({}); diag.stage='running'
        proc=Mock(); proc.communicate.return_value=('ICMP echo request',''); proc.returncode=0
        with patch.object(d.subprocess,'Popen',return_value=proc) as popen:
            self.assertIn('echo request',diag.capture()['summary'])
        args=popen.call_args.args[0]
        self.assertIn('wg-ha-client',args)
        self.assertIn('60',args)
        self.assertNotIn('-A',args); self.assertNotIn('-X',args); self.assertNotIn('-w',args)
        proc.communicate.assert_called_once_with(timeout=15)

    def test_capture_timeout_stops_process(self):
        diag=d.Diagnostics({}); diag.stage='running'
        proc=Mock(); proc.communicate.side_effect=[subprocess.TimeoutExpired('tcpdump',15),('','')]; proc.returncode=-15
        with patch.object(d.subprocess,'Popen',return_value=proc):
            self.assertIn('No matching',diag.capture()['summary'])
        proc.terminate.assert_called_once()

    def test_capture_requires_running_tunnel(self):
        with patch.object(d.subprocess,'Popen') as popen:
            self.assertIn('error',d.Diagnostics({}).capture())
        popen.assert_not_called()

    def test_probe_has_no_arbitrary_destination(self):
        diag=d.Diagnostics({'homeassistant_port':8123}); diag.backend='172.30.32.1'
        with patch.object(d.socket,'create_connection') as connect:
            self.assertTrue(diag.probe_backend()['ok'])
        connect.assert_called_once_with(('172.30.32.1',8123),timeout=3)
