"""Small structured status collector. No configuration secrets are retained."""
import json
import os
import platform
import threading
import time
from health import peer_health


def rows(value):
    return [line.split() for line in value.splitlines()]


def number(value):
    try:
        return max(0, int(value))
    except (ValueError, TypeError):
        return None


def json_list(value):
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except (ValueError, TypeError):
        return []


class Status:
    def __init__(self, diagnostics):
        self.diagnostics = diagnostics
        self.began = time.monotonic()
        self.previous = {}
        self.cached = None
        self.at = 0
        self.lock = threading.Lock()

    def collect(self, command):
        if not self.lock.acquire(blocking=False):
            return self.cached or {'health': 'Idle', 'message': 'Collecting status.'}
        try:
            tick = time.monotonic()
            if self.cached and tick - self.at < 3:
                return self.cached
            d = self.diagnostics
            now = time.time()
            uptime = int(tick - self.began)
            config = d.config
            links = json_list(command('ip', '-j', '-4', 'address', 'show'))
            interface = next((item for item in links if item.get('ifname') == 'wg-ha-client'), None)
            peers = {}
            available = True
            if interface:
                for field in ('endpoints', 'allowed-ips', 'latest-handshakes', 'transfer', 'persistent-keepalive'):
                    value = command('wg', 'show', 'wg-ha-client', field)
                    if value.startswith('Unavailable'):
                        available = False
                        continue
                    for row in rows(value):
                        if len(row) < 2:
                            continue
                        peer = peers.setdefault(row[0], {'public_key': row[0]})
                        if field == 'endpoints':
                            peer['endpoint'] = None if row[1] == '(none)' else row[1]
                        elif field == 'allowed-ips':
                            peer['allowed_ips'] = ' '.join(row[1:]).replace(',', ' ').split()
                        elif field == 'latest-handshakes':
                            peer['latest_handshake_epoch'] = number(row[1])
                        elif field == 'persistent-keepalive':
                            peer['persistent_keepalive'] = 0 if row[1] == 'off' else number(row[1])
                        elif len(row) == 3:
                            peer['rx_bytes'], peer['tx_bytes'] = number(row[1]), number(row[2])
            for key, peer in peers.items():
                stamp = peer.get('latest_handshake_epoch')
                keepalive = peer.get('persistent_keepalive')
                peer['handshake_age_seconds'] = max(0, int(now - stamp)) if stamp else None
                peer['health'], peer['message'] = peer_health(stamp, keepalive, now, uptime)
                if stamp is None or keepalive is None or not available:
                    peer['health'], peer['message'] = 'Warning', 'Some WireGuard status fields are unavailable.'
                previous = self.previous.get(key)
                for counter, rate in (('rx_bytes', 'rx_bits_per_second'), ('tx_bytes', 'tx_bits_per_second')):
                    current = peer.get(counter)
                    old = previous.get(counter) if previous else None
                    peer[rate] = round((current - old) * 8 / (tick - previous['tick'])) if current is not None and old is not None and current >= old and tick > previous['tick'] else None
                self.previous[key] = {'tick': tick, 'rx_bytes': peer.get('rx_bytes'), 'tx_bytes': peer.get('tx_bytes')}
            self.previous = {key: value for key, value in self.previous.items() if key in peers}
            gateway = {'enabled': config.get('site_to_site', False), 'active': False,
                       'local_networks': config.get('local_networks', []), 'ip_forward': None,
                       'firewall': False, 'nat': False, 'routes': []}
            if d.gateway:
                try:
                    gateway = d.gateway.inspect()
                except ValueError:
                    gateway['error'] = 'Unable to inspect gateway firewall state.'
            proxy_running = d.proxy is not None and d.proxy.poll() is None
            health, message = 'Idle', 'Waiting for configuration or tunnel startup.'
            if d.stage == 'running':
                if not interface or not peers or not proxy_running:
                    health, message = 'Error', 'WireGuard interface, peer or HA proxy is missing.'
                elif not gateway['firewall'] or not gateway['nat'] or (gateway['enabled'] and gateway['ip_forward'] is not True):
                    health, message = 'Error', 'Forwarding, firewall or NAT state does not match the configured mode.'
                else:
                    selected = max(peers.values(), key=lambda p: {'Idle': 0, 'Healthy': 1, 'Warning': 2, 'Error': 3}[p['health']])
                    health, message = selected['health'], selected['message']
            if d.setup_error:
                health, message = 'Error', d.setup_error
            routes = json_list(command('ip', '-j', '-4', 'route', 'show'))
            result = {'version': os.environ.get('ADDON_VERSION', 'development'),
                      'architecture': platform.machine(), 'collected_at': int(now), 'uptime_seconds': uptime,
                      'stage': d.stage, 'health': health, 'message': message,
                      'wireguard': {'interface': 'wg-ha-client', 'present': interface is not None,
                                    'tunnel_address': config.get('tunnel_address'), 'peers': list(peers.values())},
                      'proxy': {'running': proxy_running, 'listen': config.get('tunnel_address', '').split('/')[0] + ':8123',
                                'target': f"{config.get('homeassistant_host', 'unconfigured')}:{config.get('homeassistant_port', '')}",
                                'backend_ip': d.backend, 'last_probe': d.last_probe},
                      'site_to_site': gateway,
                      'routes': [r for r in routes if r.get('dev') == 'wg-ha-client' or r.get('dst') == 'default'],
                      'container_addresses': [entry.get('local') for item in links if item.get('ifname') == 'eth0'
                                              for entry in item.get('addr_info', []) if entry.get('family') == 'inet']}
            self.cached, self.at = result, time.monotonic()
            return result
        finally:
            self.lock.release()


def text_report(status):
    lines = ['WireGuard Client Diagnostics', f"Addon version: {status.get('version')}",
             f"Architecture: {status.get('architecture')}", f"Status: {status.get('health')} — {status.get('message')}"]
    wg = status.get('wireguard', {})
    lines.extend([f"Interface: {wg.get('interface')}", f"Tunnel IP: {wg.get('tunnel_address')}"])
    for peer in wg.get('peers', []):
        lines.extend([f"Peer: {peer.get('public_key')}", f"Endpoint: {peer.get('endpoint')}",
                      f"Handshake age seconds: {peer.get('handshake_age_seconds')}",
                      f"RX bytes: {peer.get('rx_bytes')}; TX bytes: {peer.get('tx_bytes')}",
                      f"Allowed IPs: {', '.join(peer.get('allowed_ips', []))}"])
    proxy, gateway = status.get('proxy', {}), status.get('site_to_site', {})
    lines.extend([f"HA proxy: {'running' if proxy.get('running') else 'stopped'}",
                  f"Listen: {proxy.get('listen')}; target: {proxy.get('target')}",
                  f"Site-to-site: {'enabled' if gateway.get('enabled') else 'disabled'}",
                  f"Local networks: {', '.join(gateway.get('local_networks', []))}",
                  f"IPv4 forwarding: {gateway.get('ip_forward')} (never modified)",
                  f"Firewall verified: {gateway.get('firewall')}; NAT verified: {gateway.get('nat')}",
                  'Routes: ' + json.dumps(status.get('routes', [])),
                  'LAN routes at startup: ' + json.dumps(gateway.get('routes', []))])
    return '\n'.join(lines) + '\n'
