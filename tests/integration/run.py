"""Run on a disposable Linux Docker runner; touches only dedicated test containers."""
import json
from pathlib import Path
import subprocess
import tempfile
import time

IMAGE = 'ha-wireguard-client:test'
NETWORK = 'wg-ha-ci'
NAMES = ['wg-ha-peer','wg-ha-backend','wg-ha-client']


def cmd(*args, input=None):
    p = subprocess.run(args,input=input,text=True,capture_output=True,timeout=60)
    if p.returncode:
        # Do not print input: it may contain ephemeral private keys.
        raise RuntimeError(f'{args[0]} failed: {p.stderr}')
    return p.stdout.strip()


def execute(name, *args, input=None):
    return cmd('docker','exec','-i',name,*args,input=input)


def address(name):
    return json.loads(cmd('docker','inspect',name))[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']


def wait_http():
    for _ in range(30):
        try:
            result=execute('wg-ha-peer','python3','-c', "import urllib.request; print(urllib.request.urlopen('http://192.168.101.20:8123', timeout=2).read().decode())")
            if result == 'HA backend fixture OK': return
        except RuntimeError:
            time.sleep(1)
    raise RuntimeError('HTTP through the real WireGuard tunnel did not recover')


try:
    cmd('docker','network','create',NETWORK)
    cmd('docker','run','-d','--name','wg-ha-peer','--network',NETWORK,'--cap-add','NET_ADMIN',IMAGE,'sleep','infinity')
    fixture=Path(__file__).with_name('backend.py').resolve()
    cmd('docker','run','-d','--name','wg-ha-backend','--network',NETWORK,'-v',f'{fixture}:/backend.py:ro',IMAGE,'python3','/backend.py')
    peer_private=execute('wg-ha-peer','wg','genkey')
    peer_public=execute('wg-ha-peer','wg','pubkey',input=peer_private+'\n')
    client_private=execute('wg-ha-peer','wg','genkey')
    client_public=execute('wg-ha-peer','wg','pubkey',input=client_private+'\n')
    execute('wg-ha-peer','ip','link','add','wg-test','type','wireguard')
    peer_conf=f'[Interface]\nPrivateKey = {peer_private}\nListenPort = 51820\n[Peer]\nPublicKey = {client_public}\nAllowedIPs = 192.168.101.20/32\n'
    execute('wg-ha-peer','wg','setconf','wg-test','/dev/stdin',input=peer_conf)
    execute('wg-ha-peer','ip','address','add','192.168.101.1/24','dev','wg-test')
    execute('wg-ha-peer','ip','link','set','wg-test','up')
    execute('wg-ha-peer','ip','address','add','192.168.101.11/32','dev','lo')
    with tempfile.TemporaryDirectory() as temp:
        options=dict(private_key=client_private,peer_public_key=peer_public,preshared_key='',endpoint_host=address('wg-ha-peer'),endpoint_port=51820,tunnel_address='192.168.101.20/32',allowed_ips=['192.168.101.0/24'],persistent_keepalive=25,mtu=1380,homeassistant_host='wg-ha-backend',homeassistant_port=8123)
        p=Path(temp)/'options.json'; p.write_text(json.dumps(options)); p.chmod(0o600)
        before=cmd('ip','-j','-4','route','show','table','all')
        cmd('docker','run','-d','--name','wg-ha-client','--network',NETWORK,'--cap-add','NET_ADMIN','-v',f'{temp}:/data',IMAGE)
        wait_http()
        assert cmd('ip','-j','-4','route','show','table','all') == before, 'Host routes changed'
        assert 'wg-ha-client' not in cmd('ip','-j','link','show'), 'Tunnel leaked into host namespace'
        assert execute('wg-ha-client','iptables','-S','FORWARD') == '-P FORWARD DROP'
        bridge_ip=address('wg-ha-client')
        execute('wg-ha-peer','python3','-c',f"import socket; s=socket.socket(); s.settimeout(2); assert s.connect_ex(('{bridge_ip}',8123)) != 0; s.close()")
        # Ingress denies a direct request from a peer on the Docker network.
        status=execute('wg-ha-peer','python3','-c',f"import urllib.request,urllib.error\ntry: urllib.request.urlopen('http://{bridge_ip}:8099')\nexcept urllib.error.HTTPError as e: print(e.code)")
        assert status == '403'
        # Verify a bidirectional binary stream after HTTP protocol upgrade.
        execute('wg-ha-peer','python3','-c',r"""import socket
s=socket.create_connection(('192.168.101.20',8123),timeout=5)
s.sendall(b'GET / HTTP/1.1\r\nHost: ha\r\nConnection: Upgrade\r\nUpgrade: wireguard-test\r\n\r\n')
f=s.makefile('rb'); assert b'101' in f.readline()
while f.readline() != b'\r\n': pass
payload=bytes(range(256)); s.sendall(payload); assert f.read(256)==payload
s.close()
""")
        # Exercise the exported diagnostics against this real tunnel.
        snapshot=json.loads(execute('wg-ha-client','python3','-c',"import sys,json; sys.path.insert(0,'/opt'); from diagnostics import Diagnostics; d=Diagnostics(json.load(open('/data/options.json'))); print(json.dumps(d.snapshot()))"))
        assert client_private not in json.dumps(snapshot)
        assert peer_private not in json.dumps(snapshot)
        assert snapshot['wireguard']['latest-handshakes']
        capture=subprocess.Popen(['docker','exec','wg-ha-client','python3','-c',"import sys,json; sys.path.insert(0,'/opt'); from diagnostics import Diagnostics; d=Diagnostics({}); d.stage='running'; print(json.dumps(d.capture()))"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            time.sleep(1)
            execute('wg-ha-peer','ping','-c','2','-W','2','192.168.101.20')
            execute('wg-ha-peer','ping','-I','192.168.101.11','-c','2','-W','2','192.168.101.20')
            output,error=capture.communicate(timeout=20)
            assert capture.returncode==0, error
            summary=json.loads(output)['summary']
            assert 'echo request' in summary and 'echo reply' in summary, summary
        finally:
            if capture.poll() is None:
                capture.kill(); capture.wait()
        local_route=execute('wg-ha-client','ip','-4','route','get','192.168.101.20')
        assert local_route.startswith('local '), local_route
        # Stop/start must recover without leaving host routes or requiring a new key.
        cmd('docker','stop','wg-ha-client')
        assert cmd('ip','-j','-4','route','show','table','all') == before
        cmd('docker','start','wg-ha-client')
        wait_http()
        assert cmd('ip','-j','-4','route','show','table','all') == before
        print('PASS: real WireGuard handshake, HTTP, upgraded binary stream, scoped listener, ingress denial, restart, unchanged host routes')
finally:
    for name in NAMES:
        subprocess.run(['docker','rm','-f',name],capture_output=True)
    subprocess.run(['docker','network','rm',NETWORK],capture_output=True)
