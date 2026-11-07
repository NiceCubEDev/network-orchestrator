#!/usr/bin/env python3
"""Exercise daemon-owned Xray TUN against a disposable VLESS peer."""

import json
import os
import re
import sys
import tempfile
import time
import uuid
from pathlib import Path

import xray_scenarios as proxy_fixture


client_name, server_name = sys.argv[1:3]
XRAY_DIR = "/usr/lib/network-orchestrator/xray/v26.10.31"
GEO_DIR = Path(
    os.environ.get("XRAY_E2E_GEO_DIR", str(proxy_fixture.XRAY.parent))
)


def docker_exec(container, *args, input_text=None):
    return proxy_fixture.docker_exec(container, *args, input_text=input_text)


def rpc(method, params):
    code = (
        "import json,sys; "
        "sys.path.insert(0, '/opt/netorch/e2e'); "
        "from client import call; "
        "print(json.dumps(call(sys.argv[1], json.load(sys.stdin))))"
    )
    response = json.loads(
        docker_exec(
            client_name,
            "python3",
            "-c",
            code,
            method,
            input_text=json.dumps(params),
        )
    )
    if not response.get("ok"):
        error = response.get("error", {})
        stage = error.get("message", "")
        if method != "xray.connect" or not stage.startswith("Xray "):
            stage = ""
        raise RuntimeError(f"{method} failed: {error.get('code')} {stage}")
    return response["result"]


def ipv6_scenarios(directory, vless_id):
    """IPv6 transport, payload and DNS stay inside disposable namespaces."""
    client_ip, peer_ip = "fd73:6e65:746f::1", "fd73:6e65:746f::2"
    endpoint, payload_ip = "fd79:6e65:746f::3", "fd75:6e65:746f::1"
    scope = "fd75:6e65:746f::/64"
    previous_defaults = docker_exec(client_name, "ip", "-6", "route", "show", "default")
    added = []
    fixture_pid = "/run/xray-ipv6-fixture.pid"
    fixture_count = "/run/xray-ipv6-dns-count"
    observer_pid = "/run/xray-ipv6-observer.pid"
    observer_stats = "/run/xray-ipv6-observer.json"
    observer = r"""
import json, os, signal, socket, sys
from pathlib import Path
stats = {"endpoint": 0, "direct_payload": 0}
destination = socket.inet_pton(socket.AF_INET6, "fd75:6e65:746f::1")
endpoint = socket.inet_pton(socket.AF_INET6, "fd79:6e65:746f::3")
path = Path("/run/xray-ipv6-observer.json")
def save():
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(stats))
    os.replace(temporary, path)
def stop(*_):
    save()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as capture:
    capture.bind(("eth0", 0))
    save()
    Path("/run/xray-ipv6-observer.pid").write_text(str(os.getpid()))
    while True:
        packet, address = capture.recvfrom(65535)
        if address[2] != socket.PACKET_OUTGOING or len(packet) < 54:
            continue
        if packet[12:14] != b"\x86\xdd":
            continue
        target = packet[38:54]
        if target == destination:
            stats["direct_payload"] += 1
            save()
        elif target == endpoint:
            stats["endpoint"] += 1
            save()
"""
    fixture = r"""
import http.server, os, socket, struct, threading
from pathlib import Path
class HTTP6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/opt/netorch/e2e", **kwargs)
    def do_GET(self):
        if self.client_address[0] != "fd75:6e65:746f::1":
            self.send_error(403, "payload must arrive through the proxy")
            return
        super().do_GET()
http = HTTP6(("fd75:6e65:746f::1", 8766), Handler)
threading.Thread(target=http.serve_forever, daemon=True).start()
dns = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
dns.bind(("fd75:6e65:746f::1", 53))
count = 0
Path("/run/xray-ipv6-dns-count").write_text("0")
Path("/run/xray-ipv6-fixture.pid").write_text(str(os.getpid()))
while True:
    packet, address = dns.recvfrom(4096)
    if address[0] != "fd75:6e65:746f::1":
        continue
    offset = 12
    labels = []
    while packet[offset]:
        size = packet[offset]
        labels.append(packet[offset + 1:offset + 1 + size].decode("ascii").lower())
        offset += size + 1
    offset += 1
    kind, cls = struct.unpack_from("!HH", packet, offset)
    answer = labels == ["xray-ipv6-e2e", "test"] and kind == 28 and cls == 1
    response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, int(answer), 0, 0)
    response += packet[12:offset + 4]
    if answer:
        response += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 30, 16)
        response += socket.inet_pton(socket.AF_INET6, "fd75:6e65:746f::1")
        count += 1
        Path("/run/xray-ipv6-dns-count").write_text(str(count))
    dns.sendto(response, address)
"""
    active = None

    def addresses(interface):
        links = json.loads(docker_exec(client_name, "ip", "-j", "addr", "show", "dev", interface))
        return {
            (item["family"], item["local"], item["prefixlen"])
            for item in links[0]["addr_info"] if item["scope"] == "global"
        }

    def payload(interface, dual):
        route = docker_exec(client_name, "ip", "-6", "route", "get", payload_ip)
        assert f"dev {interface}" in route, "IPv6 payload escaped TUN"
        body = docker_exec(
            client_name, "curl", "-g", "-6", "--noproxy", "*", "--fail",
            "--silent", "--show-error", "--max-time", "8",
            f"http://[{payload_ip}]:8766/server-health.txt",
        )
        assert body == "netorch-e2e-server", "IPv6 HTTP did not cross Xray"
        if dual:
            route4 = docker_exec(client_name, "ip", "-4", "route", "get", "10.75.0.1")
            assert f"dev {interface}" in route4
            body4 = docker_exec(
                client_name, "curl", "--noproxy", "*", "--fail", "--silent",
                "--show-error", "--max-time", "8", "http://10.75.0.1:8765/server-health.txt",
            )
            assert body4 == "netorch-e2e-server"

    def dns(interface, full):
        resolved = docker_exec(client_name, "resolvectl", "status", interface)
        expected_domain = "~." if full else "xray-ipv6-e2e.test"
        assert payload_ip in resolved and expected_domain in resolved
        route = docker_exec(client_name, "ip", "-6", "route", "get", payload_ip)
        assert f"dev {interface}" in route, "IPv6 DNS escaped TUN"
        before = int(docker_exec(server_name, "cat", fixture_count))
        docker_exec(client_name, "resolvectl", "flush-caches")
        answer = docker_exec(client_name, "resolvectl", "--type=AAAA", "query", "xray-ipv6-e2e.test")
        assert payload_ip in answer
        assert int(docker_exec(server_name, "cat", fixture_count)) > before

    def cleaned(interface, assigned, full):
        assert not any(owner["owner"] == f"xray:{active}" for owner in rpc("owned.list", None)["owners"])
        links = json.loads(docker_exec(client_name, "ip", "-j", "addr", "show"))
        assert all(link["ifname"] != interface for link in links), "IPv6 TUN survived cleanup"
        remaining = {
            (item["family"], item["local"], item["prefixlen"])
            for link in links for item in link["addr_info"]
        }
        assert not assigned & remaining, "Xray addresses survived cleanup"
        for family in ("-4", "-6"):
            routes = docker_exec(client_name, "ip", family, "route", "show", "table", "all", "proto", "79")
            rules = docker_exec(client_name, "ip", family, "rule", "show")
            assert interface not in routes and endpoint not in routes
            assert "proto 79" not in rules, "Xray policy rule survived cleanup"
        assert payload_ip not in docker_exec(client_name, "resolvectl", "dns"), "IPv6 DNS server survived cleanup"
        assert "xray-ipv6-e2e.test" not in docker_exec(client_name, "resolvectl", "domain"), "Xray DNS domain survived cleanup"
        if full:
            assert "~." not in docker_exec(client_name, "resolvectl", "domain").split(), "Xray default DNS domain survived cleanup"
        try:
            docker_exec(client_name, "pgrep", "-x", "xray")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Xray child survived IPv6 cleanup")

    try:
        for container in (client_name, server_name):
            for interface in ("all", "eth0", "lo"):
                docker_exec(container, "sysctl", "-q", "-w", f"net.ipv6.conf.{interface}.disable_ipv6=0")
        for container, interface, address in (
            (client_name, "eth0", f"{client_ip}/64"),
            (server_name, "eth0", f"{peer_ip}/64"),
            (server_name, "lo", f"{endpoint}/128"),
            (server_name, "lo", f"{payload_ip}/128"),
        ):
            docker_exec(container, "ip", "-6", "addr", "add", address, "dev", interface, "nodad")
            added.append((container, interface, address))
        docker_exec(client_name, "ip", "-6", "route", "replace", "default", "via", peer_ip, "dev", "eth0")
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "::", "port": 11002, "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": vless_id}]},
                "streamSettings": {"network": "raw", "security": "none"},
            }],
            "outbounds": [{"protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": [payload_ip, "10.75.0.1"]}],
            }}],
        }
        proxy_fixture.write_container_json(server_name, "/tmp/netorch-xray-tun-ipv6.json", config)
        proxy_fixture.start_xray(server_name, "/tmp/netorch-xray-tun-ipv6.json", "tun-ipv6")
        proxy_fixture.run("docker", "exec", "-d", server_name, "python3", "-c", fixture)
        for _ in range(50):
            try:
                docker_exec(server_name, "cat", fixture_pid)
                docker_exec(
                    client_name, "python3", "-c",
                    "import socket,sys; socket.create_connection((sys.argv[1],11002),0.5).close()",
                    endpoint,
                )
                break
            except RuntimeError:
                time.sleep(0.1)
        else:
            raise RuntimeError("isolated IPv6 peer did not start")
        uri = f"vless://{vless_id}@[{endpoint}]:11002?type=raw&security=none"
        generated = proxy_fixture.generate_client(uri, directory, "ipv6").read_text()
        proxy_fixture.run("docker", "exec", "-d", client_name, "python3", "-c", observer)
        for _ in range(50):
            try:
                docker_exec(client_name, "cat", observer_pid)
                json.loads(docker_exec(client_name, "cat", observer_stats))
                break
            except RuntimeError:
                time.sleep(0.1)
        else:
            raise RuntimeError("isolated eth0 packet observer did not start")
        for dual, full in ((False, False), (True, False), (True, True)):
            active = f"xray-ipv6-{int(dual)}-{int(full)}"
            observed_before = json.loads(docker_exec(client_name, "cat", observer_stats))
            destinations = ["0.0.0.0/0", "::/0"] if full else (
                ["10.75.0.0/24", scope] if dual else [scope]
            )
            params = {
                "profileId": active, "config": generated,
                "routes": [{"destination": destination, "metric": 5} for destination in destinations],
                "dnsServers": [payload_ip],
                "dnsDomains": [] if full else ["xray-ipv6-e2e.test"],
                "role": "primary" if full or not dual else "secondary",
            }
            status = rpc("xray.connect", params)["status"]
            assert status["state"] == "running"
            assert status["ipv4Covered"] == full and status["ipv6Covered"] == full
            interface = status["interfaceName"]
            assigned = addresses(interface)
            assert sum(family == "inet6" and prefix == 128 for family, _, prefix in assigned) == 1
            assert sum(family == "inet" and prefix == 32 for family, _, prefix in assigned) == int(dual)
            assert len(assigned) == 1 + int(dual)
            if not full:
                installed = []
                for family in ("-4", "-6"):
                    routes = json.loads(docker_exec(
                        client_name, "ip", "-j", family, "route", "show", "table", "all", "proto", "79",
                    ))
                    installed.extend(route["dst"] for route in routes if route.get("dev") == interface)
                    assert "proto 79" not in docker_exec(client_name, "ip", family, "rule", "show")
                assert set(installed) == set(destinations), "scoped Xray widened its route capture"
            bypass = docker_exec(client_name, "ip", "-6", "route", "show", "proto", "79")
            assert endpoint in bypass and f"via {peer_ip}" in bypass and "dev eth0" in bypass
            if full:
                rules = docker_exec(client_name, "ip", "-6", "rule", "show")
                match = re.search(r"fwmark (0x[0-9a-f]+) lookup ([0-9]+) proto 79", rules)
                assert match
                marked = docker_exec(client_name, "ip", "-6", "route", "get", endpoint, "mark", match.group(1))
                assert f"via {peer_ip}" in marked and "dev eth0" in marked
            assert status["dnsApplied"]
            payload(interface, dual)
            dns(interface, full)
            reloaded = rpc("xray.reload", params)["status"]
            assert reloaded["state"] == "running" and addresses(interface) == assigned
            assert reloaded["dnsApplied"]
            payload(interface, dual)
            dns(interface, full)
            if dual:
                old_pid = docker_exec(client_name, "pgrep", "-x", "xray")
                docker_exec(client_name, "kill", "-KILL", old_pid)
                for _ in range(50):
                    time.sleep(0.2)
                    try:
                        new_pid = docker_exec(client_name, "pgrep", "-x", "xray")
                        if new_pid != old_pid and addresses(interface) == assigned:
                            payload(interface, dual)
                            dns(interface, full)
                            break
                    except RuntimeError:
                        continue
                else:
                    raise RuntimeError("dual-stack Xray did not restore IPv6 payload/DNS after child death")
            # This observes the selected TCP and UDP-DNS probes, not all
            # possible protocols: only VLESS's distinct endpoint may use eth0.
            observed = json.loads(docker_exec(client_name, "cat", observer_stats))
            assert observed["endpoint"] > observed_before["endpoint"], "packet observer missed Xray transport"
            assert observed["direct_payload"] == 0, "TCP/DNS payload leaked directly onto eth0"
            if not full:
                rpc("xray.disconnect", {"profileId": active})
            else:
                docker_exec(client_name, "systemctl", "kill", "-s", "KILL", "network-orchestrator.service")
                for _ in range(30):
                    time.sleep(0.5)
                    try:
                        owners = rpc("owned.list", None)["owners"]
                    except RuntimeError:
                        continue
                    if not any(owner["owner"] == f"xray:{active}" for owner in owners):
                        break
                else:
                    raise RuntimeError("daemon did not recover dual-stack Xray")
            cleaned(interface, assigned, full)
            print(f"ok   IPv6 payload/cleanup dual={dual} full={full}", flush=True)
            active = None
    finally:
        if active:
            try:
                rpc("xray.disconnect", {"profileId": active})
            except RuntimeError:
                pass
        proxy_fixture.stop_xray(server_name, "tun-ipv6")
        for container, pid_file in ((client_name, observer_pid), (server_name, fixture_pid)):
            docker_exec(
                container, "python3", "-c",
                "import os,signal,sys; from pathlib import Path; p=Path(sys.argv[1]); "
                "pid=int(p.read_text()) if p.exists() else None; "
                "os.kill(pid,signal.SIGTERM) if pid else None",
                pid_file,
            )
        docker_exec(client_name, "ip", "-6", "route", "del", "default", "via", peer_ip, "dev", "eth0")
        for route in previous_defaults.splitlines():
            docker_exec(client_name, "ip", "-6", "route", "replace", *route.split())
        for container, interface, address in reversed(added):
            docker_exec(container, "ip", "-6", "addr", "del", address, "dev", interface)


print("\n=== Xray TUN split tunnel across two containers", flush=True)
proxy_fixture.run("cargo", "build", "-q", "-p", "net-manager-core", "--example", "xray_e2e_config")
docker_exec(client_name, "install", "-d", "-m", "0755", XRAY_DIR)
for source, name, mode in (
    (proxy_fixture.XRAY, "xray", "0755"),
    (GEO_DIR / "geoip.dat", "geoip.dat", "0644"),
    (GEO_DIR / "geosite.dat", "geosite.dat", "0644"),
):
    proxy_fixture.run("docker", "cp", str(source), f"{client_name}:{XRAY_DIR}/{name}")
    docker_exec(client_name, "chown", "0:0", f"{XRAY_DIR}/{name}")
    docker_exec(client_name, "chmod", mode, f"{XRAY_DIR}/{name}")
assert docker_exec(client_name, f"{XRAY_DIR}/xray", "version").startswith("Xray 26.10.31 ")
assert docker_exec(client_name, "stat", "-c", "%u:%g", f"{XRAY_DIR}/xray") == "0:0"
print("ok   daemon binary is root-owned and pinned", flush=True)

docker_exec(server_name, "mkdir", "-p", "/opt/netorch/bin")
proxy_fixture.run(
    "docker", "cp", str(proxy_fixture.XRAY), f"{server_name}:{proxy_fixture.CLIENT_XRAY}"
)
server_ip = docker_exec(
    client_name,
    "python3",
    "-c",
    'import socket; print(socket.gethostbyname("wg-server"))',
)
if "10.75.0.1" not in docker_exec(server_name, "ip", "-4", "addr", "show", "lo"):
    docker_exec(server_name, "ip", "addr", "add", "10.75.0.1/32", "dev", "lo")
vless_id = str(uuid.uuid4())
server_config = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "0.0.0.0",
        "port": 11001,
        "protocol": "vless",
        "settings": {"decryption": "none", "clients": [{"id": vless_id}]},
        "streamSettings": {"network": "raw", "security": "none"},
    }],
    "outbounds": [{"protocol": "freedom", "settings": {
        "finalRules": [{"action": "allow", "ip": [server_ip, "10.75.0.1"]}],
    }}],
}
proxy_fixture.write_container_json(server_name, "/tmp/netorch-xray-tun-server.json", server_config)
proxy_fixture.start_xray(server_name, "/tmp/netorch-xray-tun-server.json", "tun-server")
try:
    proxy_fixture.wait_tcp(server_name, 11001)
    with tempfile.TemporaryDirectory(prefix="netorch-xray-tun-e2e-") as directory:
        uri = f"vless://{vless_id}@{server_ip}:11001?type=raw&security=none"
        config_path = proxy_fixture.generate_client(uri, Path(directory), "tun")
        config = config_path.read_text()
        bad_config = json.dumps({"log": {"access": "/tmp/unsafe.log"}, "inbounds": [], "outbounds": []})
        try:
            rpc("xray.connect", {
                "profileId": "xray-unsafe",
                "config": bad_config,
                "routes": [],
                "dnsServers": [],
                "dnsDomains": [],
            })
        except RuntimeError as error:
            assert "invalidParams" in str(error), "unsafe Xray config had wrong error"
        else:
            raise RuntimeError("daemon accepted an arbitrary Xray config")
        print("ok   arbitrary Xray JSON rejected before ownership", flush=True)

        params = {
            "profileId": "xray-tun-e2e",
            "config": config,
            "routes": [{"destination": "10.75.0.0/24", "metric": 5}],
            "dnsServers": [],
            "dnsDomains": [],
        }
        status = rpc("xray.connect", params)["status"]
        assert status["state"] == "running", "Xray TUN did not reach running"
        interface = status["interfaceName"]
        assert interface and interface.startswith("xray-"), "unexpected Xray TUN name"
        print("ok   daemon created a managed Xray TUN", flush=True)

        alice_status = json.loads(
            docker_exec(
                client_name,
                "runuser",
                "-u",
                "alice",
                "--",
                "python3",
                "/opt/netorch/e2e/client.py",
                "xray.status",
                '{"profileId":"xray-tun-e2e"}',
            )
        )
        assert alice_status["state"] == "stopped", "another uid saw the Xray tunnel"
        print("ok   another uid cannot see the Xray TUN", flush=True)

        route = docker_exec(client_name, "ip", "-4", "route", "get", "10.75.0.1")
        assert f"dev {interface}" in route, "test traffic bypasses Xray TUN"
        probe = (
            'from urllib.request import urlopen; '
            'print(urlopen("http://10.75.0.1:8765/server-health.txt", timeout=5).read().decode().strip())'
        )
        assert docker_exec(client_name, "python3", "-c", probe) == "netorch-e2e-server"
        print("ok   HTTP reached peer through Xray TUN", flush=True)

        pid_before = docker_exec(client_name, "pgrep", "-x", "xray")
        reload_config = json.loads(config)
        reload_config["routing"]["rules"].append(
            {"type": "field", "domain": ["reload-sentinel.test"], "outboundTag": "direct"}
        )
        reloaded = rpc("xray.reload", {**params, "config": json.dumps(reload_config)})["status"]
        assert reloaded["state"] == "running", "xray.reload dropped the tunnel"
        assert reloaded["interfaceName"] == interface, "xray.reload renamed the TUN"
        pid_after = docker_exec(client_name, "pgrep", "-x", "xray")
        assert pid_after != pid_before, "xray.reload did not restart the child"
        assert docker_exec(client_name, "python3", "-c", probe) == "netorch-e2e-server"
        print("ok   xray.reload swapped config and kept the tunnel", flush=True)

        try:
            rpc(
                "xray.reload",
                {
                    **params,
                    "routes": [
                        {"destination": "10.75.0.0/24", "metric": 5},
                        {"destination": "192.168.88.0/24", "metric": 5},
                    ],
                },
            )
        except RuntimeError as error:
            assert "invalidParams" in str(error), "route-changing reload had wrong error"
        else:
            raise RuntimeError("daemon accepted a network-changing Xray reload")
        assert rpc("xray.status", {"profileId": "xray-tun-e2e"})["state"] == "running"
        print("ok   xray.reload rejected network changes and kept running", flush=True)

        try:
            rpc("xray.reload", {**params, "profileId": "xray-absent"})
        except RuntimeError as error:
            assert "notFound" in str(error), "reload of a missing profile had wrong error"
        else:
            raise RuntimeError("daemon reloaded a profile that is not connected")
        print("ok   xray.reload is scoped to the live tunnel", flush=True)

        assert rpc("xray.disconnect", {"profileId": "xray-tun-e2e"}) == {"stopped": True}
        assert rpc("xray.status", {"profileId": "xray-tun-e2e"})["state"] == "stopped"
        try:
            docker_exec(client_name, "ip", "link", "show", interface)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Xray TUN link survived disconnect")
        print("ok   disconnect removed Xray process, TUN and route", flush=True)

        restarted = rpc("xray.connect", params)["status"]
        assert restarted["state"] == "running"
        docker_exec(
            client_name,
            "systemctl",
            "kill",
            "-s",
            "KILL",
            "network-orchestrator.service",
        )
        for _ in range(30):
            time.sleep(0.5)
            try:
                owners = rpc("owned.list", None)["owners"]
            except RuntimeError:
                continue
            if not any(entry["owner"] == "xray:xray-tun-e2e" for entry in owners):
                break
        else:
            raise RuntimeError("daemon did not recover crashed Xray owner")
        print("ok   daemon restarted and removed crashed Xray owner", flush=True)

        try:
            docker_exec(client_name, "ip", "link", "show", restarted["interfaceName"])
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Xray TUN link survived daemon crash")
        routes = docker_exec(client_name, "ip", "-4", "route", "show", "proto", "79")
        assert "10.75.0.0/24" not in routes, "Xray route survived daemon crash"
        try:
            docker_exec(client_name, "pgrep", "-x", "xray")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Xray child survived daemon crash")
        print("ok   crash recovery removed Xray process, TUN and route", flush=True)

        print("ALL 7 XRAY TUN SPLIT CHECKS PASSED", flush=True)
        print("\n=== Xray TUN full tunnel keeps endpoint on underlay", flush=True)
        if "10.79.0.3" not in docker_exec(server_name, "ip", "-4", "addr", "show", "lo"):
            docker_exec(server_name, "ip", "addr", "add", "10.79.0.3/32", "dev", "lo")
        original_default = docker_exec(
            client_name, "ip", "-4", "route", "show", "default"
        ).splitlines()[0].split()
        docker_exec(
            client_name,
            "ip",
            "-4",
            "route",
            "replace",
            "default",
            "via",
            server_ip,
            "dev",
            "eth0",
        )
        underlay_probe = (
            'from urllib.request import urlopen; '
            'print(urlopen("http://10.79.0.3:8765/server-health.txt", timeout=3).read().decode().strip())'
        )
        assert docker_exec(client_name, "python3", "-c", underlay_probe) == "netorch-e2e-server"
        print("ok   Xray endpoint reachable through underlay default", flush=True)

        full_uri = f"vless://{vless_id}@10.79.0.3:11001?type=raw&security=none"
        full_config = proxy_fixture.generate_client(full_uri, Path(directory), "full").read_text()
        full_params = {
            "profileId": "xray-full",
            "config": full_config,
            "routes": [{"destination": "0.0.0.0/0", "metric": 5}],
            "dnsServers": [],
            "dnsDomains": [],
        }
        full = rpc("xray.connect", full_params)["status"]
        assert full["state"] == "running"
        full_interface = full["interfaceName"]
        rules = docker_exec(client_name, "ip", "-4", "rule", "show")
        match = re.search(r"fwmark (0x[0-9a-f]+) lookup ([0-9]+) proto 79", rules)
        assert match, "Xray full tunnel has no fwmark rule"
        mark, table = match.groups()
        print("ok   daemon created Xray full TUN and fwmark rule", flush=True)

        marked = docker_exec(
            client_name, "ip", "-4", "route", "get", "10.79.0.3", "mark", mark
        )
        plain = docker_exec(client_name, "ip", "-4", "route", "get", "10.79.0.3")
        payload = docker_exec(client_name, "ip", "-4", "route", "get", "10.75.0.1")
        assert f"via {server_ip}" in marked and "dev eth0" in marked
        assert f"via {server_ip}" in plain and "dev eth0" in plain
        assert f"dev {full_interface}" in payload
        print("ok   marked Xray transport uses underlay, payload uses TUN", flush=True)

        assert docker_exec(client_name, "python3", "-c", probe) == "netorch-e2e-server"
        print("ok   HTTP crossed Xray full tunnel", flush=True)

        assert rpc("xray.disconnect", {"profileId": "xray-full"}) == {"stopped": True}
        docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)
        rules = docker_exec(client_name, "ip", "-4", "rule", "show")
        assert f"lookup {table}" not in rules
        table_routes = docker_exec(client_name, "ip", "-4", "route", "show", "table", table)
        assert not table_routes.strip(), "Xray full table survived disconnect"
        print("ok   full disconnect removed Xray TUN, rules and routes", flush=True)

        print("\n=== Xray TUN full tunnel applies DNS and survives daemon crash", flush=True)
        proxy_fixture.run(
            "docker",
            "exec",
            "-d",
            server_name,
            "python3",
            "/opt/netorch/e2e/dns_peer.py",
            "10.75.0.1",
            "10.75.0.1",
            "/run/xray-e2e-dns-count",
            "/run/xray-e2e-dns-ready",
        )
        for _ in range(20):
            try:
                docker_exec(server_name, "cat", "/run/xray-e2e-dns-ready")
                break
            except RuntimeError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Xray test DNS peer did not start")
        docker_exec(
            client_name,
            "ip",
            "-4",
            "route",
            "replace",
            "default",
            "via",
            server_ip,
            "dev",
            "eth0",
        )
        dns_params = {
            **full_params,
            "profileId": "xray-dns",
            "dnsServers": ["10.75.0.1"],
        }
        dns_status = rpc("xray.connect", dns_params)["status"]
        assert dns_status["state"] == "running" and dns_status["dnsApplied"]
        dns_interface = dns_status["interfaceName"]
        resolved = docker_exec(client_name, "resolvectl", "status", dns_interface)
        assert "10.75.0.1" in resolved and "~." in resolved
        print("ok   daemon applied Xray per-link DNS", flush=True)

        answer = docker_exec(client_name, "resolvectl", "query", "xray-e2e.test")
        assert "10.75.0.1" in answer
        assert int(docker_exec(server_name, "cat", "/run/xray-e2e-dns-count")) > 0
        print("ok   DNS query reached peer through Xray TUN", flush=True)

        dns_rules = docker_exec(client_name, "ip", "-4", "rule", "show")
        dns_match = re.search(r"fwmark (0x[0-9a-f]+) lookup ([0-9]+) proto 79", dns_rules)
        assert dns_match
        dns_table = dns_match.group(2)
        docker_exec(
            client_name,
            "systemctl",
            "kill",
            "-s",
            "KILL",
            "network-orchestrator.service",
        )
        for _ in range(30):
            time.sleep(0.5)
            try:
                owners = rpc("owned.list", None)["owners"]
            except RuntimeError:
                continue
            if not any(entry["owner"] == "xray:xray-dns" for entry in owners):
                break
        else:
            raise RuntimeError("daemon did not recover crashed Xray DNS owner")
        print("ok   daemon restarted and removed crashed Xray DNS owner", flush=True)

        try:
            docker_exec(client_name, "ip", "link", "show", dns_interface)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Xray DNS TUN survived daemon crash")
        rules = docker_exec(client_name, "ip", "-4", "rule", "show")
        assert f"lookup {dns_table}" not in rules
        table_routes = docker_exec(client_name, "ip", "-4", "route", "show", "table", dns_table)
        assert not table_routes.strip()
        docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)
        print("ok   crash recovery removed Xray process, TUN, rules and DNS link", flush=True)

        print("\n=== Xray TUN isolated IPv6 payload, DNS and dual-stack recovery", flush=True)
        ipv6_scenarios(Path(directory), vless_id)
finally:
    proxy_fixture.stop_xray(server_name, "tun-server")

print("ALL XRAY TUN IPv4/IPv6 CHECKS PASSED", flush=True)
