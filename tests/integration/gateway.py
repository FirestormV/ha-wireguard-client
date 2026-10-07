"""Disposable network experiment. Run the harness on the Docker client machine.

All ip/iptables operations are docker exec inside owned test containers.
The second NAT is a fixture, NOT the HA OS host or Docker host namespace.
No sysctl writes, privileged mode, host mounts/networking, or published ports.
"""
import json
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent
IMAGE = 'ha-wireguard-client:test'
PREFIX = 'wg-poc-' + uuid.uuid4().hex[:8]
TRANSIT, LAN = PREFIX + '-transit', PREFIX + '-lan'
ADDON_IP, PEER_IP, HOST_IN, BACKEND_IP = '198.18.10.10', '198.18.10.20', '198.18.10.254', '198.18.10.30'
HOST_OUT, TARGET_IP, BLOCKED_IP = '198.18.20.254', '198.18.20.10', '198.18.20.11'
CLIENT_WG, PEER_WG, WRONG_SOURCE = '10.203.0.20', '10.203.0.1', '10.203.0.11'
MARK = '0x530/0xfff'
containers, networks = [], []
report = {'scope': 'Docker Linux, simulated host NAT and LAN; not HA OS',
          'tests': [], 'prefix': PREFIX, 'sysctl_writes': False}


def command(*args, input=None, check=True, timeout=40):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        # Neither stdin nor command output is included: WireGuard keys may be present.
        raise RuntimeError(f'{args[0]} operation failed with status {p.returncode}')
    return p


def docker(*args, **kwargs):
    return command('docker', *args, **kwargs).stdout.strip()


def ex(role, *args, input=None, check=True):
    return command('docker', 'exec', '-i', PREFIX + '-' + role, *args, input=input, check=check)


def out(role, *args, **kwargs):
    return ex(role, *args, **kwargs).stdout.strip()


def ipt(role, *args, check=True):
    return ex(role, 'iptables', '-w', '5', *args, check=check)


def rules(role):
    # iptables-save timestamps are not configuration changes.
    return '\n'.join(line for line in out(role, 'iptables-save').splitlines()
                     if not line.startswith('#'))


def passed(name, detail=None):
    report['tests'].append({'name': name, 'passed': True, 'detail': detail})
    print('PASS:', name, flush=True)


def create(role, network, address):
    name = PREFIX + '-' + role
    docker('run', '-d', '--name', name, '--label', 'wg.poc=' + PREFIX,
           '--network', network, '--ip', address, '--cap-add', 'NET_ADMIN',
           '--cap-add', 'NET_RAW', IMAGE, 'sleep', 'infinity')
    containers.append(name)


def write(role, destination, content):
    ex(role, 'python3', '-c', 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); '
       'p.parent.mkdir(parents=True,exist_ok=True); p.write_text(sys.stdin.read()); p.chmod(0o600)',
       destination, input=content)


def fixture(role):
    write(role, '/tmp/fixture.py', (ROOT / 'gateway_backend.py').read_text())
    docker('exec', '-d', PREFIX + '-' + role, 'python3', '/tmp/fixture.py')


def http(role, address, *, expect=True, bulk=False):
    code = ('import urllib.request,json; data=urllib.request.urlopen(' +
            repr('http://' + address + ':8123/' + ('bulk' if bulk else '')) +
            ',timeout=2).read(); ' +
            ("assert data==bytes(range(256))*1024; print(len(data))" if bulk else 'print(data.decode())'))
    p = ex(role, 'python3', '-c', code, check=False)
    assert (p.returncode == 0) == expect, f'HTTP expectation failed: {role} -> {address}'
    return (int(p.stdout) if bulk else json.loads(p.stdout)) if expect else None


def udp(role, address, *, expect=True, fixed_port=False):
    code = ('import socket,json; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
            + ('s.bind(("0.0.0.0",19999)); ' if fixed_port else '') +
            's.settimeout(2); s.sendto(b"poc",(' + repr(address) +
            ',9999)); r=json.loads(s.recv(4096)); assert r["echo"]=="poc"; print(json.dumps(r))')
    p = ex(role, 'python3', '-c', code, check=False)
    assert (p.returncode == 0) == expect, f'UDP expectation failed: {role} -> {address}'
    return json.loads(p.stdout) if expect else None


def ping(role, address, *, expect=True, source=None):
    args = ['ping', '-c', '1', '-W', '2']
    if source:
        args.extend(['-I', source])
    args.append(address)
    p = ex(role, *args, check=False)
    assert (p.returncode == 0) == expect, f'ICMP expectation failed: {role} -> {address}'


def status(path='/api/status'):
    return json.loads(out('addon', 'python3', '-c',
        "import http.client; c=http.client.HTTPConnection('127.0.0.1',8099,timeout=20,source_address=('172.30.32.2',0)); "
        "c.request('GET'," + repr(path) + "); r=c.getresponse(); assert r.status==200; print(r.read().decode())"))


def start_app(options, inject_failure=False):
    write('addon', '/data/options.json', json.dumps(options))
    script = "import sys,os,pathlib; sys.path.insert(0,'/opt'); import client,gateway; pathlib.Path('/tmp/app.pid').write_text(str(os.getpid())); client.configure_logging(); "
    if inject_failure:
        script += '''
original = gateway.Gateway.iptables
def fail(self, table, *args, **kwargs):
    if table == 'filter' and args[:2] == ('-I', 'FORWARD'):
        raise gateway.GatewayError('Injected failure before forwarding activation.')
    return original(self, table, *args, **kwargs)
gateway.Gateway.iptables = fail
'''
    script += '\nclient.main()'
    docker('exec', '-d', PREFIX + '-addon', 'python3', '-u', '-c', script)
    expected = 'error' if inject_failure else 'running'
    for _ in range(30):
        try:
            result = status()
            if result['stage'] == expected:
                return result
            if result['stage'] == 'error':
                raise AssertionError(result['message'])
        except (RuntimeError, json.JSONDecodeError):
            pass
        time.sleep(.5)
    raise AssertionError('Application did not reach ' + expected)


def stop_app():
    out('addon', 'python3', '-c', "import os,signal,pathlib; os.kill(int(pathlib.Path('/tmp/app.pid').read_text()),signal.SIGTERM)")
    for _ in range(30):
        closed = ex('addon', 'python3', '-c', "import socket; s=socket.socket(); s.settimeout(.2); assert s.connect_ex(('127.0.0.1',8099))!=0", check=False)
        if closed.returncode == 0 and out('addon','wg','show','interfaces') == '': return
        time.sleep(.2)
    raise AssertionError('Application did not stop')


try:
    for name, subnet in [(TRANSIT, '198.18.10.0/24'), (LAN, '198.18.20.0/24')]:
        docker('network','create','--label','wg.poc='+PREFIX,'--subnet',subnet,name)
        networks.append(name)
    for role,network,address in [('addon',TRANSIT,ADDON_IP),('peer',TRANSIT,PEER_IP),
            ('host-fixture',TRANSIT,HOST_IN),('backend',TRANSIT,BACKEND_IP),
            ('target',LAN,TARGET_IP),('target2',LAN,'198.18.20.12'),('blocked',LAN,BLOCKED_IP)]:
        create(role,network,address)
    docker('network','connect','--ip',HOST_OUT,LAN,PREFIX+'-host-fixture')
    for role in ('backend','target','target2','blocked'): fixture(role)
    assert out('addon','cat','/proc/sys/net/ipv4/ip_forward') == '1'
    ex('addon','ip','route','add','198.18.20.0/24','via',HOST_IN)
    ex('addon','ip','addr','add','172.30.32.2/32','dev','lo')  # Emulate trusted Ingress source.
    host_iface=json.loads(out('host-fixture','ip','-j','route','get',TARGET_IP))[0]['dev']
    ipt('host-fixture','-P','FORWARD','DROP')
    ipt('host-fixture','-A','FORWARD','-s',ADDON_IP+'/32','-d','198.18.20.0/24','-j','ACCEPT')
    ipt('host-fixture','-A','FORWARD','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    ipt('host-fixture','-t','nat','-A','POSTROUTING','-s',ADDON_IP+'/32','-d','198.18.20.0/24','-o',host_iface,'-j','MASQUERADE')
    host_rules=rules('host-fixture')
    host_routes=out('host-fixture','ip','-j','-4','route','show','table','all')
    for target in (TARGET_IP, '198.18.20.12', BLOCKED_IP):
        assert http('addon',target)['source']==HOST_OUT
    private_peer=out('peer','wg','genkey'); public_peer=out('peer','wg','pubkey',input=private_peer+'\n')
    private_client=out('peer','wg','genkey'); public_client=out('peer','wg','pubkey',input=private_client+'\n')
    ex('peer','ip','link','add','wg-test','type','wireguard')
    ex('peer','wg','setconf','wg-test','/dev/stdin',input=(
        f'[Interface]\nPrivateKey = {private_peer}\nListenPort = 51820\n'
        f'[Peer]\nPublicKey = {public_client}\nAllowedIPs = {CLIENT_WG}/32,198.18.20.0/24\n'))
    ex('peer','ip','addr','add',PEER_WG+'/24','dev','wg-test')
    ex('peer','ip','addr','add',WRONG_SOURCE+'/32','dev','lo')
    ex('peer','ip','link','set','wg-test','mtu','1380','up')
    ex('peer','ip','route','add','198.18.20.0/24','dev','wg-test')
    options=dict(private_key=private_client,peer_public_key=public_peer,preshared_key='',
        endpoint_host=PEER_IP,endpoint_port=51820,tunnel_address=CLIENT_WG+'/32',
        allowed_ips=[PEER_WG+'/32'],persistent_keepalive=25,mtu=1380,
        homeassistant_host=BACKEND_IP,homeassistant_port=8123,site_to_site=False,local_networks=[])
    start_app(options)
    assert http('peer',CLIENT_WG)['source']==ADDON_IP
    for fn in (http,udp,ping): fn('peer',TARGET_IP,expect=False)
    assert status()['site_to_site']['firewall'] is True
    passed('Disabled mode: HA proxy works; TCP/UDP/ICMP forwarding blocked with inherited ip_forward=1')
    stop_app()
    options.update(site_to_site=True,local_networks=[TARGET_IP+'/32','198.18.20.12/32'])
    start_app(options)
    for target in (TARGET_IP,'198.18.20.12'):
        for fn in (http,udp): assert fn('peer',target)['source']==HOST_OUT
        ping('peer',target)
    http('peer',TARGET_IP,bulk=True)
    http('peer',CLIENT_WG)
    udp('peer',TARGET_IP,fixed_port=True)
    passed('Enabled mode: multiple destinations, double NAT, TCP/UDP/ICMP, large payload and HA proxy')
    for fn in (http,udp,ping): fn('peer',BLOCKED_IP,expect=False)
    ping('peer',TARGET_IP,source=WRONG_SOURCE,expect=False)
    passed('Unlisted destination and unauthorized WireGuard source blocked')
    counters=[line for line in out('addon','iptables','-t','nat','-L','WG_HA_S2S_NAT','-nvx').splitlines() if 'MASQUERADE' in line]
    http('addon',TARGET_IP); udp('addon',TARGET_IP)
    assert [line for line in out('addon','iptables','-t','nat','-L','WG_HA_S2S_NAT','-nvx').splitlines() if 'MASQUERADE' in line]==counters
    passed('Process-originated traffic is not matched by gateway NAT')
    data=status(); diagnostic=status('/diagnostics'); text=status('/api/report')['text']
    assert data['site_to_site']['firewall'] and data['site_to_site']['nat']
    assert data['proxy']['running'] and len(data['wireguard']['peers'])==1
    assert data['wireguard']['peers'][0]['rx_bytes']>0
    for secret in (private_client,private_peer):
        assert secret not in json.dumps(data)+json.dumps(diagnostic)+text
    assert public_peer in text
    passed('Live status, rule verification, counters and safe diagnostics report')
    ipt('addon','-N','FOREIGN_TEST')
    stop_app()
    assert out('addon','cat','/proc/sys/net/ipv4/ip_forward')=='1'
    assert 'WG_HA_S2S' not in rules('addon')
    assert ':FOREIGN_TEST ' in rules('addon')
    # Real module cleanup can safely be called twice after application shutdown.
    out('addon','python3','-c',"import sys,json; sys.path.insert(0,'/opt'); from gateway import Gateway; g=Gateway(json.load(open('/data/options.json'))); g.cleanup(); g.cleanup()")
    passed('Shutdown and repeated cleanup preserve unrelated firewall state and sysctl')
    start_app(options,inject_failure=True)
    assert status()['health']=='Error'
    assert out('addon','wg','show','interfaces')==''
    assert 'WG_HA_S2S' not in rules('addon')
    http('peer',TARGET_IP,expect=False)
    passed('Partial activation failure closes tunnel and keeps Ingress status available')
    stop_app()
    start_app(options)
    http('peer',TARGET_IP)
    ipt('addon','-t','nat','-F','WG_HA_S2S_NAT')
    for _ in range(30):
        if status()['stage']=='error': break
        time.sleep(.5)
    else: raise AssertionError('Missing NAT rules did not trigger safe shutdown')
    assert out('addon','wg','show','interfaces')==''
    assert status()['health']=='Error'
    passed('Runtime NAT rule loss stops tunnel; Ingress continues reporting the failure')
    stop_app()
    options.update(site_to_site=False,local_networks=[])
    start_app(options)
    http('peer',CLIENT_WG)
    udp('peer',TARGET_IP,fixed_port=True,expect=False)
    stop_app()
    assert rules('host-fixture')==host_rules
    assert out('host-fixture','ip','-j','-4','route','show','table','all')==host_routes
    passed('Recovery to disabled mode blocks previous UDP flow; simulated host state unchanged')
    report['passed']=True
finally:
    for name in reversed(containers): command('docker','rm','-f',name,check=False)
    for name in reversed(networks): command('docker','network','rm',name,check=False)
