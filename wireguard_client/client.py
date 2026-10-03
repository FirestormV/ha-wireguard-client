"""Isolated IPv4 tunnel with a single TCP relay to Home Assistant."""
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


class ConfigurationError(ValueError):
    """A curated message safe to show without exposing raw configuration values."""


def failure_message(exc):
    if isinstance(exc, ConfigurationError):
        return "Configuration error: " + str(exc)
    return f"Startup/runtime failure ({type(exc).__name__}); see the last startup stage. Raw error details are hidden to protect secrets."


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=15)
    if result.returncode:
        # wg errors can include configuration secrets; never print stderr or argv.
        raise RuntimeError(f"{args[0]} operation failed (exit {result.returncode})")
    return result.stdout.strip()


def key(value, field="WireGuard key"):
    if isinstance(value, str) and not value.strip():
        raise ConfigurationError(f"{field} is empty. Open the add-on Configuration tab, enter this key, save, then start. Configuration is available while the add-on is stopped.")
    try:
        if not isinstance(value, str):
            raise ValueError()
        value = value.strip()
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or not any(raw):
            raise ValueError()
    except Exception:
        raise ConfigurationError(f"{field}: enter a nonzero 32-byte base64 WireGuard key (44 characters). Key value hidden.") from None
    return value


def validate(o):
    if not isinstance(o, dict):
        raise ConfigurationError("Configuration must be an object.")
    o = dict(o)
    for field in ("private_key", "peer_public_key", "endpoint_host", "endpoint_port", "tunnel_address", "allowed_ips", "mtu"):
        if field not in o:
            raise ConfigurationError(f"Missing required option: {field}.")
    o.setdefault("homeassistant_host", "homeassistant")
    o.setdefault("homeassistant_port", 8123)
    o.setdefault("persistent_keepalive", 25)  # Backward-compatible v0.1.0 options.
    for name in ("private_key", "peer_public_key"):
        o[name] = key(o[name], name)
    if o.get("preshared_key"):
        o["preshared_key"] = key(o["preshared_key"], "preshared_key")
    for field in ("endpoint_host", "homeassistant_host"):
        host = o[field]
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
            raise ConfigurationError(f"{field}: enter an IPv4 address or DNS hostname without a scheme, port or path.")
    for field, low, high in (("endpoint_port", 1, 65535), ("homeassistant_port", 1, 65535), ("mtu", 1280, 1420), ("persistent_keepalive", 0, 65535)):
        if type(o[field]) is not int or not low <= o[field] <= high:
            raise ConfigurationError(f"{field}: enter an integer from {low} to {high}.")
    try:
        if not isinstance(o["tunnel_address"], str):
            raise ValueError()
        addr = ip.IPv4Interface(o["tunnel_address"])
    except ValueError:
        raise ConfigurationError("tunnel_address: enter an IPv4 address with /32, for example 10.77.0.2/32.") from None
    if addr.network.prefixlen != 32 or addr.ip.is_unspecified or addr.ip.is_multicast:
        raise ConfigurationError("tunnel_address must be a unicast IPv4 /32; use /32 rather than the tunnel subnet mask.")
    if not isinstance(o["allowed_ips"], list) or not o["allowed_ips"]:
        raise ConfigurationError("allowed_ips must be a nonempty list of IPv4 networks.")
    nets = []
    for index, value in enumerate(o["allowed_ips"], 1):
        try:
            if not isinstance(value, str):
                raise ValueError()
            nets.append(ip.IPv4Network(value, strict=True))
        except ValueError:
            raise ConfigurationError(f"allowed_ips entry {index}: enter an IPv4 network with network bits only, e.g. 192.168.10.0/24, or a single address with /32. IPv6 is not supported.") from None
    for index, net in enumerate(nets):
        if net.prefixlen == 0 or addr.ip in net or net.overlaps(ip.IPv4Network('127.0.0.0/8')) or net.overlaps(ip.IPv4Network('224.0.0.0/3')):
            raise ConfigurationError(f"allowed_ips entry {index + 1} ({net}): contains the client tunnel address or a restricted range; do not include the client tunnel IP, default route, loopback or multicast/reserved networks.")
        if any(net.overlaps(other) for other in nets[:index]):
            raise ConfigurationError(f"allowed_ips entry {index + 1} ({net}) overlaps an earlier entry. Remove overlapping or duplicate networks.")
    o["allowed_ips"] = [str(n) for n in nets]
    o["tunnel_address"] = str(addr)
    return o


def resolve(o):
    address = socket.getaddrinfo(o["endpoint_host"], o["endpoint_port"], socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    if any(ip.IPv4Address(address) in ip.IPv4Network(n) for n in o["allowed_ips"]):
        raise ConfigurationError(f"endpoint_host resolves to {address}, inside allowed_ips. Use a reachable endpoint outside the tunnel routes.")
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
        existing = ip.IPv4Network(dst)
        for network in wanted:
            if existing.overlaps(network):
                raise ConfigurationError(f"Tunnel/allowed network {network} overlaps container route {existing}. Choose networks outside the internal add-on network.")


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


def resolve_backend(o):
    address = socket.getaddrinfo(o["homeassistant_host"], o["homeassistant_port"], socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    target = ip.IPv4Address(address)
    if target == ip.IPv4Interface(o["tunnel_address"]).ip or any(target in ip.IPv4Network(n) for n in o["allowed_ips"]):
        raise ConfigurationError(f"homeassistant_host resolves to {target}, inside the tunnel address/allowed_ips. Use the internal homeassistant hostname or correct allowed_ips to include only networks behind pfSense.")
    return address


def start_proxy(o, backend):
    address = str(ip.IPv4Interface(o["tunnel_address"]).ip)
    return subprocess.Popen([
        "socat",
        f"TCP4-LISTEN:8123,bind={address},reuseaddr,fork,max-children=32",
        f"TCP4:{backend}:{o['homeassistant_port']},connect-timeout=10",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL, start_new_session=True)


def stop_proxy(proxy):
    # Stop active relay children as well as the listener.
    try:
        os.killpg(proxy.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proxy.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proxy.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proxy.wait(timeout=5)


def monitor(o, proxy):
    state = None
    while not STOP.wait(30):
        if proxy.poll() is not None:
            raise RuntimeError("Home Assistant relay exited")
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
    print("Startup stage: validating add-on configuration", flush=True)
    try:
        raw_options = json.loads(Path("/data/options.json").read_text())
    except json.JSONDecodeError:
        raise ConfigurationError("Cannot parse options.json. Save the add-on configuration again.") from None
    o = validate(raw_options)
    # Derive through stdin: the private key never appears in process arguments.
    print("Startup stage: deriving client public key", flush=True)
    public_key = key(run("wg", "pubkey", input=o["private_key"] + "\n"), "Derived public key")
    import public_key_ui
    print("Startup stage: starting Ingress public key page", flush=True)
    ui = public_key_ui.start(public_key)
    started = False
    proxy = None
    try:
        print("Startup stage: resolving endpoint and Home Assistant backend", flush=True)
        while not STOP.is_set():
            try:
                endpoint = resolve(o)
                backend = resolve_backend(o)
                break
            except socket.gaierror:
                print("Waiting for endpoint/backend DNS; retrying in 30 seconds", flush=True)
                STOP.wait(30)
        else:
            return
        # Only this container network namespace is affected. No IP forwarding.
        print("Startup stage: applying container forwarding policy", flush=True)
        run("iptables", "-w", "5", "-P", "FORWARD", "DROP")
        print("Startup stage: checking routes and creating WireGuard interface", flush=True)
        start(o, endpoint)
        started = True
        print("Startup stage: starting Home Assistant TCP relay", flush=True)
        proxy = start_proxy(o, backend)
        print(f'Tunnel configured; waiting for handshake. PersistentKeepalive={o["persistent_keepalive"]}', flush=True)
        print("Client public key: " + public_key, flush=True)
        monitor(o, proxy)
    finally:
        try:
            try:
                if proxy is not None:
                    stop_proxy(proxy)
            finally:
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
        print(failure_message(exc), flush=True)
        raise SystemExit(1)
