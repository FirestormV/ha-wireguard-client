"""Bounded diagnostics. Never request wg dump/showconf, options files or secrets."""
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import threading
import time

IFACE = 'wg-ha-client'


def command(*args, timeout=3):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return p.stdout.strip()[:24000] if p.returncode == 0 else 'Unavailable (command failed)'
    except (OSError, subprocess.TimeoutExpired):
        return 'Unavailable (missing tool or timeout)'


class Diagnostics:
    def __init__(self, options, setup_error=None):
        # Explicit allowlist: never retain keys, PSK, raw options or Supervisor tokens.
        self.config = {k: options[k] for k in ('tunnel_address','allowed_ips','persistent_keepalive','mtu','homeassistant_host','homeassistant_port') if k in options}
        self.setup_error = setup_error
        self.backend = None
        self.stage = 'setup' if setup_error else 'starting'
        self.lock = threading.Lock()
        self.capture_lock = threading.Lock()
        self.cached = None
        self.cached_at = 0

    def snapshot(self):
        if not self.lock.acquire(blocking=False):
            return self.cached or {'status':'Collecting diagnostics; try again shortly'}
        try:
            if self.cached and time.monotonic()-self.cached_at < 5:
                return self.cached
            result = {'collected_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'stage':self.stage,'setup_error':self.setup_error,'configuration':self.config,'backend_ip':self.backend,
                      'scope':'Inside the add-on container only. No host-network inspection.',
                      'sharing_notice':'Contains network addresses, routes and public peer keys. Review before sharing. No private keys or PSKs.'}
            result['wireguard'] = {field:command('wg','show',IFACE,field) for field in ('public-key','endpoints','allowed-ips','latest-handshakes','transfer','persistent-keepalive','listen-port')}
            stamps=result['wireguard']['latest-handshakes'].splitlines()
            result['handshake_age_seconds'] = [int(time.time())-int(line.split()[1]) if int(line.split()[1]) else None for line in stamps if len(line.split())==2 and line.split()[1].isdigit()]
            result['addresses']=command('ip','-j','-4','address','show')
            result['link_counters']=command('ip','-j','-s','link','show','dev',IFACE)
            result['routes']=command('ip','-4','route','show','table','all')
            result['routing_rules']=command('ip','-4','rule','show')
            result['tcp_listeners']=command('ss','-lnt')
            result['firewall']={chain:command('iptables','-w','1','-n','-v','-L',chain) for chain in ('INPUT','OUTPUT','FORWARD')}
            result['kernel_settings']={}
            for setting in ('icmp_echo_ignore_all','ip_forward','conf/all/rp_filter','conf/default/rp_filter',f'conf/{IFACE}/rp_filter','conf/eth0/rp_filter'):
                try:
                    result['kernel_settings'][setting]=Path('/proc/sys/net/ipv4',setting).read_text().strip()
                except OSError:
                    result['kernel_settings'][setting]='Unavailable'
            result['return_route_examples']={}
            for net in self.config.get('allowed_ips',[])[:32]:
                network=ipaddress.IPv4Network(net)
                target=network.network_address if network.prefixlen==32 else network.network_address+1
                result['return_route_examples'][str(target)]=command('ip','-4','route','get',str(target))
            if self.backend:
                result['backend_route']=command('ip','-4','route','get',self.backend)
            self.cached=result
            self.cached_at=time.monotonic()
            return result
        finally:
            self.lock.release()

    def probe_backend(self):
        if not self.backend:
            return {'ok':False,'message':'Backend not resolved yet; check setup/DNS stage.'}
        started=time.monotonic()
        try:
            with socket.create_connection((self.backend,self.config['homeassistant_port']),timeout=3):
                return {'ok':True,'message':'TCP connection to HA backend succeeded. This does not verify HTTP, TLS or login.','duration_ms':round((time.monotonic()-started)*1000)}
        except OSError:
            return {'ok':False,'message':'Cannot connect to HA backend TCP port (refused, unreachable or timed out). Check Core listener and port.'}

    def capture(self):
        if not self.capture_lock.acquire(blocking=False):
            return {'error':'A capture is already running. Wait for it to finish.'}
        try:
            if self.stage != 'running':
                return {'error':'Tunnel not running. Complete configuration and check the startup log.'}
            # No payloads, pcap files, other interfaces, user-supplied filters or commands.
            args=['tcpdump','-i',IFACE,'-p','-nn','-tttt','-l','-s','96','-c','60',
                  '(icmp and (icmp[0] = 8 or icmp[0] = 0)) or (tcp port 8123 and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0))']
            p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                output,_=p.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                p.terminate()
                try:
                    output,_=p.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill(); output,_=p.communicate()
            if p.returncode not in (0,-15) and not output:
                return {'error':'Capture failed. Verify NET_RAW permission, tcpdump and tunnel interface.'}
            return {'duration_limit_seconds':15,'packet_limit':60,'interface':IFACE,
                    'summary':output[:24000] or 'No matching decrypted ICMP echo or TCP connection-control packets seen.',
                    'interpretation':'Requests without replies: inspect INPUT/OUTPUT counters, return routes and rp_filter. No packets: inspect pfSense routing/peer selection and WireGuard transfer counters. SYN and SYN-ACK: tunnel TCP listener responds; check backend TCP next.'}
        except OSError:
            return {'error':'Cannot start tcpdump.'}
        finally:
            self.capture_lock.release()
