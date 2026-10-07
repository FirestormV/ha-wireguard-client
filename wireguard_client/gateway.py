"""Restricted IPv4 gateway. Every operation runs in the add-on namespace."""
import ipaddress as ip
import json
from pathlib import Path
import shlex
import subprocess

IFACE = 'wg-ha-client'
OWNER = 'ha-wireguard-gateway-v1'
MARK = '0x530/0xfff'
CHAINS = [('mangle', 'FORWARD', 'WG_HA_S2S_MARK'),
          ('nat', 'POSTROUTING', 'WG_HA_S2S_NAT'),
          ('filter', 'FORWARD', 'WG_HA_S2S_FWD')]


class GatewayError(ValueError):
    """Curated diagnostic message, safe for logs and Ingress."""


def execute(*args, check=True):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        raise GatewayError('Gateway command unavailable or timed out; check container capabilities.') from None
    if check and result.returncode:
        raise GatewayError('Gateway command failed; check NET_ADMIN and kernel firewall support.')
    return result


def forwarding():
    try:
        return Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1'
    except OSError:
        return None


def validate(options):
    if type(options['site_to_site']) is not bool:
        raise GatewayError('site_to_site must be true or false.')
    values = options['local_networks']
    if not isinstance(values, list) or len(values) > 32:
        raise GatewayError('local_networks must be a list of at most 32 IPv4 CIDRs.')
    if options['site_to_site'] and not values:
        raise GatewayError('site_to_site is enabled but local_networks is empty. Specify explicit LAN destinations.')
    networks = []
    remote = [ip.IPv4Network(n) for n in options['allowed_ips']]
    remote.append(ip.IPv4Network(options['tunnel_address']))
    restricted = [ip.IPv4Network(n) for n in ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/3')]
    for value in values:
        try:
            if not isinstance(value, str) or '/' not in value:
                raise ValueError()
            net = ip.IPv4Network(value, strict=True)
        except ValueError:
            raise GatewayError('local_networks must contain valid IPv4 network CIDRs or host /32 addresses.') from None
        if any(net.overlaps(other) for other in restricted + remote + networks):
            raise GatewayError(f'Local network {net} overlaps a restricted, tunnel, remote or duplicate network.')
        networks.append(net)
    options['local_networks'] = [str(net) for net in networks]


def normalized(line):
    tokens = shlex.split(line)
    if '--ctstate' in tokens:
        index = tokens.index('--ctstate') + 1
        tokens[index] = ','.join(sorted(tokens[index].split(',')))
    return tokens


class Gateway:
    def __init__(self, options):
        self.enabled = options['site_to_site']
        self.networks = options['local_networks']
        self.sources = options['allowed_ips']
        self.routes = []
        self.expected = {}
        self.active = False
        self.owned_chains = set()

    def iptables(self, table, *args, check=True):
        return execute('iptables', '-w', '2', '-t', table, *args, check=check)

    def check_routes(self):
        routes = json.loads(execute('ip', '-j', '-4', 'route', 'show', 'table', 'all').stdout)
        # A directly connected container subnet (including its local addresses)
        # must never become a LAN destination. Routed networks via eth0 are fine.
        internal = [ip.IPv4Network(r['dst'], strict=False) for r in routes
                    if r.get('dst', 'default') != 'default' and not r.get('gateway')
                    and r.get('dev') != IFACE]
        self.routes = []
        for value in self.networks:
            net = ip.IPv4Network(value)
            if any(net.overlaps(n) for n in internal):
                raise GatewayError(f'Local network {net} overlaps an internal container network.')
            target = str(net.network_address if net.prefixlen == 32 else net.network_address + 1)
            route = json.loads(execute('ip', '-j', '-4', 'route', 'get', target).stdout)[0]
            if route.get('dev') != 'eth0' or route.get('type', 'unicast') != 'unicast' or not route.get('gateway'):
                raise GatewayError(f'Local network {net} needs an existing gateway route through eth0.')
            self.routes.append({'network': value, 'interface': 'eth0', 'gateway': route['gateway']})

    def owned(self, table, chain):
        result = self.iptables(table, '-S', chain, check=False)
        if result.returncode:
            return False
        if (table, chain) in self.owned_chains:
            return True
        marker = ['-A', chain, '-m', 'comment', '--comment', OWNER, '-j', 'RETURN']
        if marker not in [normalized(line) for line in result.stdout.splitlines()]:
            raise GatewayError(f'Firewall chain {chain} belongs to another owner; refusing to modify it.')
        return True

    def cleanup(self):
        self.active = False
        self.iptables('filter', '-P', 'FORWARD', 'DROP')
        # Block first, then remove NAT/marking. Never flush unrelated rules or conntrack.
        for table, hook, chain in reversed(CHAINS):
            if not self.owned(table, chain):
                continue
            for _ in range(16):
                if self.iptables(table, '-D', hook, '-j', chain, check=False).returncode:
                    break
            self.iptables(table, '-F', chain)
            self.iptables(table, '-X', chain)
            self.owned_chains.discard((table, chain))

    def start(self):
        self.cleanup()
        if not self.enabled:
            return
        if forwarding() is not True:
            raise GatewayError('IPv4 forwarding is disabled or unreadable in this container. No sysctl or host settings were changed.')
        self.check_routes()
        rules = {chain: [] for _, _, chain in CHAINS}
        for net in self.networks:
            for source in self.sources:
                base = ['-s', source, '-d', net, '-i', IFACE, '-o', 'eth0']
                for protocol in ('tcp', 'udp', 'icmp'):
                    match = base + ['-p', protocol, '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED']
                    rules['WG_HA_S2S_MARK'].append(match + ['-j', 'CONNMARK', '--set-xmark', MARK])
                    rules['WG_HA_S2S_FWD'].append(match + ['-j', 'ACCEPT'])
                rules['WG_HA_S2S_NAT'].append(['-s', source, '-d', net, '-o', 'eth0',
                    '-m', 'connmark', '--mark', MARK, '-j', 'MASQUERADE'])
        for source in self.sources:
            rules['WG_HA_S2S_FWD'].append(['-d', source, '-i', 'eth0', '-o', IFACE,
                '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
        # Do not let later unrelated ACCEPT rules bypass the gateway allowlist.
        rules['WG_HA_S2S_FWD'].append(['-j', 'DROP'])
        created = []
        try:
            for table, hook, chain in CHAINS:
                self.iptables(table, '-N', chain)
                created.append((table, chain))
                self.owned_chains.add((table, chain))
                for rule in rules[chain]:
                    self.iptables(table, '-A', chain, *rule)
                marker = ['-m', 'comment', '--comment', OWNER, '-j', 'RETURN']
                self.iptables(table, '-A', chain, *marker)
                self.expected[chain] = [normalized(shlex.join(['-A', chain] + r)) for r in rules[chain] + [marker]]
            # Activate forwarding LAST. A failure before this point stays closed.
            for table, hook, chain in CHAINS:
                self.iptables(table, '-I', hook, '1', '-j', chain)
            self.active = True
            state = self.inspect()
            if not state['firewall'] or not state['nat']:
                raise GatewayError('Gateway rules could not be verified after installation.')
        except BaseException:
            self.iptables('filter', '-P', 'FORWARD', 'DROP')
            for table, chain in reversed(created):
                hook = 'POSTROUTING' if table == 'nat' else 'FORWARD'
                self.iptables(table, '-D', hook, '-j', chain, check=False)
                self.iptables(table, '-F', chain, check=False)
                self.iptables(table, '-X', chain, check=False)
                self.owned_chains.discard((table, chain))
            self.active = False
            raise

    def inspect(self):
        data = {table: self.iptables(table, '-S', check=False) for table in ('filter', 'mangle', 'nat')}
        lines = {table: [normalized(line) for line in result.stdout.splitlines()]
                 if result.returncode == 0 else [] for table, result in data.items()}
        checks = {}
        for table, hook, chain in CHAINS:
            actual = [line for line in lines[table] if line[:2] == ['-A', chain]]
            hooks = [line for line in lines[table] if line[:2] == ['-A', hook]]
            checks[chain] = bool(self.expected.get(chain)) and actual == self.expected[chain] and bool(hooks) and hooks[0] == ['-A', hook, '-j', chain]
        policy = ['-P', 'FORWARD', 'DROP'] in lines['filter']
        no_gateway = all(not any(chain in line for line in lines[table]) for table, _, chain in CHAINS)
        return {'enabled': self.enabled, 'active': self.active, 'local_networks': self.networks,
                'ip_forward': forwarding(), 'firewall': policy and (checks['WG_HA_S2S_FWD'] if self.enabled else no_gateway),
                'nat': checks['WG_HA_S2S_NAT'] and checks['WG_HA_S2S_MARK'] if self.enabled else no_gateway,
                'routes': self.routes}
