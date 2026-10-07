"""Verify first-start onboarding and persisted identity using the built image."""
import json
import uuid
from pathlib import Path
import subprocess
import tempfile
import time

NAME='wg-ha-setup-'+uuid.uuid4().hex[:8]

def cmd(*args):
    return subprocess.check_output(args,text=True,stderr=subprocess.PIPE,timeout=30).strip()

def public_key():
    return cmd('docker','exec',NAME,'python3','-c',"from pathlib import Path; import subprocess; p=Path('/data/client-private.key'); assert p.stat().st_mode & 0o777 == 0o600; print(subprocess.check_output(['wg','pubkey'],input=p.read_bytes()).decode().strip())")

def wait_ready():
    for _ in range(30):
        try:
            value=public_key()
            # The web server is alive; local direct access is still denied.
            code=cmd('docker','exec',NAME,'python3','-c',"import urllib.request,urllib.error\ntry: urllib.request.urlopen('http://127.0.0.1:8099',timeout=2)\nexcept urllib.error.HTTPError as e: print(e.code)")
            if code=='403': return value
        except subprocess.CalledProcessError:
            pass
        time.sleep(1)
    raise RuntimeError('Setup page did not start')

try:
    with tempfile.TemporaryDirectory() as directory:
        # All tunnel fields may be absent at this stage; no network config is needed.
        Path(directory,'options.json').write_text(json.dumps({'private_key':'','peer_public_key':''}))
        cmd('docker','create','--name',NAME,'--cap-add','NET_ADMIN','ha-wireguard-client:test')
        cmd('docker','cp',f'{directory}/.',f'{NAME}:/data')
        cmd('docker','start',NAME)
        first=wait_ready()
        assert len(first)==44
        assert cmd('docker','exec',NAME,'wg','show','interfaces') == ''
        assert cmd('docker','exec',NAME,'iptables','-S','FORWARD') == '-P FORWARD DROP'
        cmd('docker','restart',NAME)
        assert wait_ready()==first
        assert cmd('docker','exec',NAME,'wg','show','interfaces') == ''
        print('PASS: blank first start, persistent key with mode 0600, setup page, no tunnel, forwarding policy DROP, restart identity preserved')
finally:
    subprocess.run(['docker','rm','-f',NAME],capture_output=True)
