"""Isolated IPv4 tunnel with a single TCP relay to Home Assistant."""
import base64
import ipaddress as ip
import json
import logging
import sys
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from gateway import Gateway, GatewayError, validate as validate_gateway
from health import peer_health

IFACE = "wg-ha-client"
OWNER = "ha-wireguard-client-v1"
STOP = threading.Event()
LOG = logging.getLogger("wireguard_client")


def configure_logging():
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    formatter.converter = time.gmtime
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    LOG.propagate = False


class ConfigurationError(ValueError):
    """A curated message safe to show without exposing raw configuration values."""


def failure_message(exc):
    if isinstance(exc, (ConfigurationError, GatewayError)):
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


def prepare_identity(options, path=Path("/data/client-private.key")):
    """Retain the last selected identity across restarts, updates and options edits."""
    if not isinstance(options, dict):
        raise ConfigurationError("Configuration must be an object.")
    o = dict(options)
    supplied = o.get("private_key", "")
    if not isinstance(supplied, str):
        raise ConfigurationError("private_key must be text or empty for automatic key management.")
    if supplied.strip():
        private = key(supplied, "private_key")
    elif path.exists():
        private = key(path.read_text(), "Saved client private key")
    else:
        private = key(run("wg", "genkey"), "Generated client private key")
    public = key(run("wg", "pubkey", input=private + "\n"), "Derived public key")
    # Atomic, durable replacement avoids truncated identities after a power failure.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
            temporary = Path(f.name)
            os.fchmod(f.fileno(), 0o600)
            f.write(private + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    o["private_key"] = private
    return o, public


def validate(o):
    if not isinstance(o, dict):
        raise ConfigurationError("Configuration must be an object.")
    o = dict(o)
    for field in ("private_key", "peer_public_key", "preshared_key", "endpoint_host", "endpoint_port", "tunnel_address", "allowed_ips", "mtu", "homeassistant_host", "homeassistant_port", "persistent_keepalive", "site_to_site", "local_networks"):
        if field not in o:
            raise ConfigurationError(f"Missing required option: {field}.")
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
    if not isinstance(o["allowed_ips"], list) or not 1 <= len(o["allowed_ips"]) <= 32:
        raise ConfigurationError("allowed_ips must contain 1 to 32 IPv4 networks.")
    nets = []
    for index, value in enumerate(o["allowed_ips"], 1):
        try:
            if not isinstance(value, str):
                raise ValueError()
            nets.append(ip.IPv4Network(value, strict=True))
        except ValueError:
            raise ConfigurationError(f"allowed_ips entry {index}: enter an IPv4 network with network bits only, e.g. 192.168.10.0/24, or a single address with /32. IPv6 is not supported.") from None
    for index, net in enumerate(nets):
        if net.prefixlen == 0 or (net.prefixlen == 32 and addr.ip in net) or net.overlaps(ip.IPv4Network('127.0.0.0/8')) or net.overlaps(ip.IPv4Network('224.0.0.0/3')):
            raise ConfigurationError(f"allowed_ips entry {index + 1} ({net}): is the client address alone or a restricted range; do not use the client /32 alone, default route, loopback or multicast/reserved networks. A broader tunnel subnet is supported.")
        if any(net.overlaps(other) for other in nets[:index]):
            raise ConfigurationError(f"allowed_ips entry {index + 1} ({net}) overlaps an earlier entry. Remove overlapping or duplicate networks.")
    o["allowed_ips"] = [str(n) for n in nets]
    o["tunnel_address"] = str(addr)
    validate_gateway(o)
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


def monitor(o, proxy, diagnostics, gateway):
    state = None
    began = time.monotonic()
    while not STOP.wait(10):
        if proxy.poll() is not None:
            raise RuntimeError("Home Assistant relay exited")
        gateway_state = gateway.inspect()
        if not gateway_state['firewall'] or not gateway_state['nat'] or (gateway.enabled and gateway_state['ip_forward'] is not True):
            raise GatewayError('Gateway safety check failed: forwarding, firewall or NAT state changed. Tunnel stopped; inspect diagnostics.')
        stamp = int(run("wg", "show", IFACE, "latest-handshakes").split()[-1])
        health, message = peer_health(stamp, o['persistent_keepalive'], time.time(), time.monotonic() - began)
        if health != state:
            LOG.info('%s: %s', health, message)
            state = health
        if health == 'Warning':
            try:
                endpoint = resolve(o)
                run("wg", "set", IFACE, "peer", o["peer_public_key"], "endpoint", f'{endpoint}:{o["endpoint_port"]}')
            except (OSError, ValueError, RuntimeError):
                LOG.info("Endpoint refresh failed; retrying in 30 seconds")


def main():
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    os.umask(0o077)
    LOG.info("Startup stage: validating add-on configuration")
    try:
        raw_options = json.loads(Path("/data/options.json").read_text())
    except json.JSONDecodeError:
        raise ConfigurationError("Cannot parse options.json. Save the add-on configuration again.") from None
    LOG.info("Startup stage: loading or creating client identity")
    raw_options, public_key = prepare_identity(raw_options)
    setup_error = None
    try:
        o = validate(raw_options)
    except (ConfigurationError, GatewayError) as exc:
        setup_error = str(exc)
    import public_key_ui
    LOG.info("Startup stage: starting Ingress status dashboard")
    from diagnostics import Diagnostics
    diagnostics = Diagnostics(o if setup_error is None else {}, setup_error)
    gateway = Gateway(o if setup_error is None else {'site_to_site': False, 'local_networks': [], 'allowed_ips': []})
    diagnostics.gateway = gateway
    ui = public_key_ui.start(public_key, setup_error, diagnostics)
    started = False
    proxy = None
    try:
        gateway.cleanup()
        if setup_error is not None:
            LOG.info("Setup mode: " + setup_error)
            LOG.info("Open Web UI to copy the client public key. Complete Configuration, save and restart. No tunnel has been started.")
            STOP.wait()
            return
        LOG.info("Startup stage: resolving endpoint and Home Assistant backend")
        while not STOP.is_set():
            try:
                endpoint = resolve(o)
                backend = resolve_backend(o)
                diagnostics.backend = backend
                break
            except socket.gaierror:
                LOG.info("Waiting for endpoint/backend DNS; retrying in 30 seconds")
                STOP.wait(30)
        else:
            return
        LOG.info("Startup stage: checking routes and creating WireGuard interface")
        start(o, endpoint)
        started = True
        LOG.info("Startup stage: starting Home Assistant TCP relay")
        proxy = start_proxy(o, backend)
        diagnostics.proxy = proxy
        LOG.info('HA TCP proxy started')
        gateway.start()
        LOG.info('Site-to-site gateway %s', 'enabled; local networks: ' + ', '.join(gateway.networks) if gateway.enabled else 'disabled')
        diagnostics.stage = "running"
        LOG.info(f'Tunnel configured; waiting for handshake. PersistentKeepalive={o["persistent_keepalive"]}')
        LOG.info("Client public key: " + public_key)
        monitor(o, proxy, diagnostics, gateway)
    except Exception as exc:
        diagnostics.stage = 'error'
        diagnostics.setup_error = failure_message(exc)
        LOG.error(diagnostics.setup_error)
    finally:
        try:
            try:
                gateway.cleanup()
            finally:
                try:
                    if proxy is not None:
                        stop_proxy(proxy)
                finally:
                    if started:
                        remove_owned()
        except Exception:
            diagnostics.stage = 'error'
            diagnostics.setup_error = 'Network cleanup failed. Stop the add-on to destroy its network namespace before retrying.'
            LOG.error(diagnostics.setup_error)
        finally:
            if diagnostics.stage == 'error' and not STOP.is_set():
                LOG.info('Ingress remains available for diagnostics. Save configuration and restart to retry.')
                STOP.wait()
            ui.shutdown()
            ui.server_close()


if __name__ == "__main__":
    configure_logging()
    try:
        main()
    except Exception as exc:
        # Deliberately do not expose parser errors, options, keys or subprocess output.
        LOG.error(failure_message(exc))
        raise SystemExit(1)
