"""One peer, IPv4 split tunnel. No shell hooks or host firewall mutations."""
import base64
import ipaddress as ip
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time

IFACE = "wg-ha-client"
OWNER = "ha-wireguard-client-v1"
STOP = threading.Event()


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=15)
    if result.returncode:
        # wg errors can include configuration secrets; never print stderr or argv.
        raise RuntimeError(f"{args[0]} operation failed (exit {result.returncode})")
    return result.stdout.strip()


def key(value):
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or not any(raw):
            raise ValueError()
    except Exception:
        raise ValueError("WireGuard keys must be nonzero 32-byte base64 keys") from None
    return value


def validate(o):
    o = dict(o)
    o.setdefault("persistent_keepalive", 25)  # Backward-compatible v0.1.0 options.
    for name in ("private_key", "peer_public_key"):
        o[name] = key(o[name])
    if o.get("preshared_key"):
        o["preshared_key"] = key(o["preshared_key"])
    host = o["endpoint_host"]
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise ValueError("endpoint_host must be an IPv4 address or DNS hostname")
    for field, low, high in (("endpoint_port", 1, 65535), ("mtu", 1280, 1420), ("persistent_keepalive", 0, 65535)):
        if type(o[field]) is not int or not low <= o[field] <= high:
            raise ValueError(f"Invalid {field}")
    addr = ip.IPv4Interface(o["tunnel_address"])
    if addr.network.prefixlen != 32 or addr.ip.is_unspecified or addr.ip.is_multicast:
        raise ValueError("tunnel_address must be a unicast IPv4 /32")
    if not isinstance(o["allowed_ips"], list) or not o["allowed_ips"]:
        raise ValueError("allowed_ips must be a nonempty list")
    nets = [ip.IPv4Network(n, strict=True) for n in o["allowed_ips"]]
    for index, net in enumerate(nets):
        if net.prefixlen == 0 or addr.ip in net or net.overlaps(ip.IPv4Network('127.0.0.0/8')) or net.overlaps(ip.IPv4Network('224.0.0.0/3')):
            raise ValueError("Allowed networks must exclude default, local tunnel, loopback and multicast/reserved ranges")
        if any(net.overlaps(other) for other in nets[:index]):
            raise ValueError("allowed_ips entries overlap")
    o["allowed_ips"] = [str(n) for n in nets]
    o["tunnel_address"] = str(addr)
    return o


def resolve(o):
    address = socket.getaddrinfo(o["endpoint_host"], o["endpoint_port"], socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    if any(ip.IPv4Address(address) in ip.IPv4Network(n) for n in o["allowed_ips"]):
        raise ValueError("Endpoint would be routed into its own tunnel")
    return address


def links():
    return json.loads(run("ip", "-j", "link", "show"))


def remove_owned():
    for link in links():
        if link["ifname"] == IFACE:
            if link.get("ifalias") != OWNER:
                raise RuntimeError("Interface name is in use by another owner")
            run("ip", "link", "delete", "dev", IFACE)


def check_routes(o):
    # Refuse collisions rather than replacing routes belonging to HA OS/Docker.
    routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "all"))
    wanted = [ip.IPv4Network(n) for n in o["allowed_ips"]]
    wanted.append(ip.IPv4Network(o["tunnel_address"]))
    for route in routes:
        dst = route.get("dst", "default")
        if dst == "default":
            continue
        if any(ip.IPv4Network(dst).overlaps(n) for n in wanted):
            raise ValueError("Tunnel or allowed network overlaps an existing host route")


def start(o, endpoint):
    remove_owned()  # Recover our own interface after a container crash.
    check_routes(o)
    run("ip", "link", "add", "dev", IFACE, "type", "wireguard")
    try:
        run("ip", "link", "set", "dev", IFACE, "alias", OWNER)
        config = f'[Interface]\nPrivateKey = {o["private_key"]}\n[Peer]\nPublicKey = {o["peer_public_key"]}\n'
        if o.get("preshared_key"):
            config += f'PresharedKey = {o["preshared_key"]}\n'
        config += f'Endpoint = {endpoint}:{o["endpoint_port"]}\nAllowedIPs = {", ".join(o["allowed_ips"])}\nPersistentKeepalive = {o["persistent_keepalive"]}\n'
        with tempfile.NamedTemporaryFile(mode="w", dir="/tmp") as f:
            os.chmod(f.name, 0o600)
            f.write(config)
            f.flush()
            run("wg", "setconf", IFACE, f.name)
        run("ip", "address", "add", o["tunnel_address"], "dev", IFACE)
        run("ip", "link", "set", "dev", IFACE, "mtu", str(o["mtu"]), "up")
        for net in o["allowed_ips"]:
            run("ip", "-4", "route", "add", net, "dev", IFACE)
    except BaseException:
        run("ip", "link", "delete", "dev", IFACE)
        raise


def monitor(o):
    state = None
    while not STOP.wait(30):
        stamp = int(run("wg", "show", IFACE, "latest-handshakes").split()[-1])
        healthy = stamp > 0 and time.time() - stamp < 180
        if healthy != state:
            print("Handshake healthy" if healthy else "No recent handshake; check endpoint, peer keys and pfSense WAN rule", flush=True)
            state = healthy
        if not healthy:
            try:
                endpoint = resolve(o)
                run("wg", "set", IFACE, "peer", o["peer_public_key"], "endpoint", f'{endpoint}:{o["endpoint_port"]}')
            except (OSError, ValueError, RuntimeError):
                print("Endpoint refresh failed; retrying in 30 seconds", flush=True)


def main():
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    os.umask(0o077)
    o = validate(json.loads(Path("/data/options.json").read_text()))
    # Derive through stdin: the private key never appears in process arguments.
    public_key = key(run("wg", "pubkey", input=o["private_key"] + "\n"))
    import public_key_ui
    ui = public_key_ui.start(public_key)
    started = False
    try:
        while not STOP.is_set():
            try:
                endpoint = resolve(o)
                break
            except socket.gaierror:
                print("Waiting for endpoint DNS; retrying in 30 seconds", flush=True)
                STOP.wait(30)
        else:
            return
        start(o, endpoint)
        started = True
        print(f'Tunnel configured; waiting for handshake. PersistentKeepalive={o["persistent_keepalive"]}', flush=True)
        print("Client public key: " + public_key, flush=True)
        monitor(o)
    finally:
        try:
            if started:
                remove_owned()
        finally:
            ui.shutdown()
            ui.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Deliberately do not expose parser errors, options, keys or subprocess output.
        print(f"Startup/runtime failure ({type(exc).__name__}); verify configuration, route overlap and NET_ADMIN/kernel WireGuard support", flush=True)
        raise SystemExit(1)
