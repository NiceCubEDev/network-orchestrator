#!/usr/bin/env python3
"""Exercise daemon-owned WireGuard against a peer in another container.

Called by run.sh after the S1 scenarios. Keys exist only in process memory and
the disposable containers; no private key or config is printed or passed in
an argv entry.
"""

import json
import subprocess
import sys
import time


client_name, server_name = sys.argv[1:3]


def run(*args, input_text=None):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"E2E command failed: {args[0]} {args[1]}")
    return result.stdout.strip()


def docker_exec(container, *args, input_text=None):
    return run("docker", "exec", "-i", container, *args, input_text=input_text)


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
        raise RuntimeError(f"{method} failed: {response.get('error', {}).get('code')}")
    return response["result"]


print("\n=== WireGuard split tunnel across two containers", flush=True)
client_private = docker_exec(client_name, "wg", "genkey")
client_public = docker_exec(client_name, "wg", "pubkey", input_text=client_private + "\n")
server_private = docker_exec(server_name, "wg", "genkey")
server_public = docker_exec(server_name, "wg", "pubkey", input_text=server_private + "\n")
server_ip = docker_exec(
    client_name,
    "python3",
    "-c",
    'import socket; print(socket.gethostbyname("wg-server"))',
)

docker_exec(
    server_name,
    "sh",
    "-c",
    "umask 077; cat >/run/wg-e2e.key",
    input_text=server_private + "\n",
)
docker_exec(server_name, "ip", "link", "add", "wg-e2e", "type", "wireguard")
docker_exec(server_name, "ip", "addr", "add", "10.77.0.1/24", "dev", "wg-e2e")
docker_exec(
    server_name,
    "wg",
    "set",
    "wg-e2e",
    "private-key",
    "/run/wg-e2e.key",
    "listen-port",
    "51820",
    "peer",
    client_public,
    "allowed-ips",
    "10.77.0.2/32",
)
docker_exec(server_name, "ip", "link", "set", "wg-e2e", "up")

config = (
    "[Interface]\n"
    f"PrivateKey = {client_private}\n"
    "Address = 10.77.0.2/32\n"
    "[Peer]\n"
    f"PublicKey = {server_public}\n"
    f"Endpoint = {server_ip}:51820\n"
    "AllowedIPs = 10.77.0.0/24\n"
    "PersistentKeepalive = 5\n"
)
connected = rpc(
    "wireguard.connect", {"profileId": "wg-e2e", "config": config, "routes": []}
)["status"]
assert connected["state"] == "running", "WireGuard did not reach running"
interface = connected["interfaceName"]
assert interface and interface.startswith("wg-"), "unexpected WireGuard interface"
print("ok   daemon created a WireGuard link", flush=True)

alice_status = json.loads(
    docker_exec(
        client_name,
        "runuser",
        "-u",
        "alice",
        "--",
        "python3",
        "/opt/netorch/e2e/client.py",
        "wireguard.status",
        '{"profileId":"wg-e2e"}',
    )
)
assert alice_status["state"] == "stopped", "another uid saw the tunnel"
print("ok   another uid cannot see the tunnel", flush=True)

route = docker_exec(client_name, "ip", "-4", "route", "get", "10.77.0.1")
assert f"dev {interface}" in route, "peer traffic bypasses WireGuard"
print("ok   peer traffic selects WireGuard", flush=True)

probe = (
    'from urllib.request import urlopen; '
    'print(urlopen("http://10.77.0.1:8765/server-health.txt", timeout=2).read().decode().strip())'
)
for attempt in range(20):
    try:
        body = docker_exec(client_name, "python3", "-c", probe)
        if body == "netorch-e2e-server":
            break
    except RuntimeError:
        pass
    time.sleep(1)
else:
    raise RuntimeError("HTTP did not pass through WireGuard")
print("ok   HTTP reached peer over WireGuard", flush=True)

status = rpc("wireguard.status", {"profileId": "wg-e2e"})
assert status["state"] == "running", "status lost running state"
assert status["latestHandshake"] and status["rxBytes"] > 0 and status["txBytes"] > 0
print("ok   handshake and byte counters visible", flush=True)

assert rpc("wireguard.disconnect", {"profileId": "wg-e2e"}) == {"stopped": True}
assert rpc("wireguard.status", {"profileId": "wg-e2e"})["state"] == "stopped"
assert not any(
    entry["owner"] == "wg:wg-e2e" for entry in rpc("owned.list", None)["owners"]
)
route = docker_exec(client_name, "ip", "-4", "route", "show", "proto", "79")
assert "10.77.0.0/24" not in route, "WireGuard route left behind"
print("ok   disconnect removed link, route, and ownership", flush=True)

reconnected = rpc(
    "wireguard.connect", {"profileId": "wg-e2e", "config": config, "routes": []}
)["status"]
assert reconnected["state"] == "running"
docker_exec(
    client_name,
    "systemctl",
    "kill",
    "-s",
    "KILL",
    "network-orchestrator.service",
)
for _ in range(20):
    time.sleep(0.5)
    try:
        owners = rpc("owned.list", None)["owners"]
    except RuntimeError:
        continue
    if not any(entry["owner"] == "wg:wg-e2e" for entry in owners):
        break
else:
    raise RuntimeError("daemon did not recover WireGuard ownership")
print("ok   daemon restarted and removed crashed owner", flush=True)

try:
    docker_exec(client_name, "ip", "link", "show", reconnected["interfaceName"])
except RuntimeError:
    pass
else:
    raise RuntimeError("WireGuard link survived daemon recovery")
route = docker_exec(client_name, "ip", "-4", "route", "show", "proto", "79")
assert "10.77.0.0/24" not in route, "WireGuard route survived daemon recovery"
print("ok   crash recovery removed WireGuard link and route", flush=True)

print("ALL 8 WIREGUARD SPLIT CHECKS PASSED", flush=True)

print("\n=== WireGuard full tunnel keeps its endpoint on underlay", flush=True)
docker_exec(server_name, "ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
docker_exec(server_name, "ip", "addr", "add", "10.76.0.1/32", "dev", "lo")
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
    'print(urlopen("http://198.18.0.1:8765/server-health.txt", timeout=3).read().decode().strip())'
)
assert docker_exec(client_name, "python3", "-c", underlay_probe) == "netorch-e2e-server"
print("ok   endpoint is reachable through underlay default", flush=True)

full_config = config.replace(
    f"Endpoint = {server_ip}:51820", "Endpoint = 198.18.0.1:51820"
).replace("AllowedIPs = 10.77.0.0/24", "AllowedIPs = 0.0.0.0/0")
full = rpc(
    "wireguard.connect", {"profileId": "wg-full", "config": full_config, "routes": []}
)["status"]
assert full["state"] == "running"
full_interface = full["interfaceName"]
mark = docker_exec(client_name, "wg", "show", full_interface, "fwmark")
assert mark != "off", "WireGuard transport is unmarked"
print("ok   full tunnel assigns a transport fwmark", flush=True)

try:
    rpc(
        "wireguard.connect",
        {"profileId": "wg-full-other", "config": full_config, "routes": []},
    )
except RuntimeError as error:
    assert "conflict" in str(error), "second full tunnel had the wrong error"
else:
    raise RuntimeError("daemon accepted a second full tunnel")
assert not any(
    entry["owner"] == "wg:wg-full-other"
    for entry in rpc("owned.list", None)["owners"]
)
print("ok   second full tunnel is rejected before ownership", flush=True)

marked_endpoint = docker_exec(
    client_name, "ip", "-4", "route", "get", "198.18.0.1", "mark", mark
)
plain_endpoint = docker_exec(client_name, "ip", "-4", "route", "get", "198.18.0.1")
payload_route = docker_exec(client_name, "ip", "-4", "route", "get", "10.76.0.1")
assert "dev eth0" in marked_endpoint and f"via {server_ip}" in marked_endpoint
assert f"dev {full_interface}" in plain_endpoint
assert f"dev {full_interface}" in payload_route
print("ok   marked endpoint uses underlay while unmarked traffic uses WG", flush=True)

payload_probe = (
    'from urllib.request import urlopen; '
    'print(urlopen("http://10.76.0.1:8765/server-health.txt", timeout=3).read().decode().strip())'
)
assert docker_exec(client_name, "python3", "-c", payload_probe) == "netorch-e2e-server"
full_status = rpc("wireguard.status", {"profileId": "wg-full"})
assert full_status["latestHandshake"] and full_status["rxBytes"] > 0
print("ok   full tunnel payload and handshake survive the route switch", flush=True)


def wait_for(predicate, message, attempts=40):
    for _ in range(attempts):
        try:
            if predicate():
                return
        except RuntimeError:
            pass
        time.sleep(0.5)
    raise RuntimeError(message)


def full_state_present():
    rules = docker_exec(client_name, "ip", "-4", "rule", "show")
    table = docker_exec(client_name, "ip", "-4", "route", "show", "table", "51820")
    return "10000:" in rules and "10001:" in rules and "default" in table


# Uplink flap: the kernel drops the eth0 default; a network manager re-adds
# it and, like networkd with ManageForeignRoutingPolicyRules, flushes rules
# and routes it does not know. The daemon must restore only its own state.
docker_exec(client_name, "ip", "link", "set", "eth0", "down")
time.sleep(1)
docker_exec(client_name, "ip", "link", "set", "eth0", "up")
docker_exec(client_name, "ip", "-4", "rule", "del", "priority", "10001")
docker_exec(client_name, "ip", "-4", "route", "flush", "table", "51820")
docker_exec(
    client_name, "ip", "-4", "route", "replace", "default", "via", server_ip, "dev", "eth0"
)
wait_for(full_state_present, "daemon did not restore full-tunnel rules and route")
wait_for(
    lambda: docker_exec(client_name, "python3", "-c", payload_probe) == "netorch-e2e-server",
    "full tunnel payload did not recover after uplink flap",
)
assert rpc("wireguard.status", {"profileId": "wg-full"})["state"] == "running"
print("ok   uplink flap restores owned rules, route and payload", flush=True)

assert rpc("wireguard.disconnect", {"profileId": "wg-full"}) == {"stopped": True}
rules_after_disconnect = docker_exec(client_name, "ip", "-4", "rule", "show")
assert "10000:" not in rules_after_disconnect and "10001:" not in rules_after_disconnect
table_after_disconnect = docker_exec(
    client_name, "ip", "-4", "route", "show", "table", "51820"
)
assert "default" not in table_after_disconnect
assert rpc("wireguard.status", {"profileId": "wg-full"})["state"] == "stopped"
print("ok   full tunnel disconnect restores daemon-owned network state", flush=True)

vanish = rpc(
    "wireguard.connect", {"profileId": "wg-full-vanish", "config": full_config, "routes": []}
)["status"]
assert vanish["state"] == "running" and full_state_present()
docker_exec(client_name, "ip", "link", "del", vanish["interfaceName"])
# `wg show` fails at once, so status turns failed before the debounced
# reconcile; wait for the owner itself to be torn down.
wait_for(
    lambda: not any(
        entry["owner"] == "wg:wg-full-vanish" for entry in rpc("owned.list", None)["owners"]
    ),
    "daemon did not tear down a vanished WireGuard owner",
)
assert rpc("wireguard.status", {"profileId": "wg-full-vanish"})["state"] == "failed"
rules = docker_exec(client_name, "ip", "-4", "rule", "show")
assert "10000:" not in rules and "10001:" not in rules, "dead tunnel kept policy rules"
assert rpc("wireguard.disconnect", {"profileId": "wg-full-vanish"}) == {"stopped": True}
assert rpc("wireguard.status", {"profileId": "wg-full-vanish"})["state"] == "stopped"
docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)
print("ok   vanished transport is failed without leftover policy routing", flush=True)

print("\n=== WireGuard full tunnel applies per-link DNS", flush=True)
run(
    "docker",
    "exec",
    "-d",
    server_name,
    "python3",
    "/opt/netorch/e2e/dns_peer.py",
)
for _ in range(20):
    try:
        docker_exec(server_name, "cat", "/run/wg-e2e-dns-ready")
        break
    except RuntimeError:
        time.sleep(0.1)
else:
    raise RuntimeError("test DNS peer did not start")
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
dns_config = full_config.replace(
    "Address = 10.77.0.2/32\n", "Address = 10.77.0.2/32\nDNS = 10.77.0.1\n"
)
dns_status = rpc(
    "wireguard.connect", {"profileId": "wg-dns", "config": dns_config, "routes": []}
)["status"]
assert dns_status["state"] == "running" and dns_status["dnsApplied"]
print("ok   daemon reports per-link DNS applied", flush=True)

dns_interface = dns_status["interfaceName"]
resolved = docker_exec(client_name, "resolvectl", "status", dns_interface)
assert "10.77.0.1" in resolved and "~." in resolved
print("ok   resolved routes all DNS to the WG link", flush=True)

answer = docker_exec(client_name, "resolvectl", "query", "wg-e2e.test")
assert "10.76.0.1" in answer, "resolved did not return the tunnel DNS answer"
query_count = int(docker_exec(server_name, "cat", "/run/wg-e2e-dns-count"))
assert query_count > 0, "test DNS peer did not receive a query"
print("ok   DNS query reached the peer through WG", flush=True)

docker_exec(client_name, "systemctl", "restart", "systemd-resolved.service")
for _ in range(30):
    time.sleep(0.5)
    try:
        restored = docker_exec(client_name, "resolvectl", "status", dns_interface)
    except RuntimeError:
        continue
    if "10.77.0.1" in restored and "~." in restored:
        break
else:
    raise RuntimeError("daemon did not restore per-link DNS after resolved restart")
answer = docker_exec(client_name, "resolvectl", "query", "wg-e2e.test")
assert "10.76.0.1" in answer
restored_count = int(docker_exec(server_name, "cat", "/run/wg-e2e-dns-count"))
assert restored_count > query_count, "restored DNS did not reach the WG peer"
print("ok   per-link DNS recovered after resolved restart", flush=True)

assert rpc("wireguard.disconnect", {"profileId": "wg-dns"}) == {"stopped": True}
docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)
assert rpc("wireguard.status", {"profileId": "wg-dns"})["state"] == "stopped"
print("ok   DNS tunnel disconnect removed ownership", flush=True)

print("\n=== WireGuard secondary role: listed networks and split DNS only", flush=True)
secondary_params = {
    "profileId": "wg-secondary",
    # The original Docker default is restored: the synthetic 198.18.0.1
    # endpoint was reachable only through the temporary server default.
    "config": dns_config.replace(
        "Endpoint = 198.18.0.1:51820", f"Endpoint = {server_ip}:51820"
    ),
    "routes": [{"destination": "10.77.0.0/24", "metric": 5}],
    "role": "secondary",
    "dnsDomains": ["test"],
}
try:
    rpc("wireguard.connect", {**secondary_params, "routes": []})
except RuntimeError:
    print("ok   secondary without networks is refused", flush=True)
else:
    raise RuntimeError("daemon accepted a secondary tunnel with no networks")
try:
    rpc(
        "wireguard.connect",
        {**secondary_params, "routes": [{"destination": "0.0.0.0/0", "metric": 5}]},
    )
except RuntimeError:
    print("ok   secondary cannot take the default route", flush=True)
else:
    raise RuntimeError("daemon accepted a secondary tunnel with a default route")

secondary = rpc("wireguard.connect", secondary_params)["status"]
assert secondary["state"] == "running", "secondary WireGuard did not reach running"
secondary_interface = secondary["interfaceName"]
route = docker_exec(client_name, "ip", "-4", "route", "get", "10.77.0.1")
assert f"dev {secondary_interface}" in route, "listed network bypasses the secondary tunnel"
default = docker_exec(client_name, "ip", "-4", "route", "get", "198.51.100.7")
assert secondary_interface not in default, "secondary tunnel captured unrelated traffic"
print("ok   only the listed network uses the secondary tunnel", flush=True)

resolved = docker_exec(client_name, "resolvectl", "status", secondary_interface)
assert "10.77.0.1" in resolved and "~test" in resolved, resolved
assert "~." not in resolved, "secondary tunnel became the default DNS route"
before = int(docker_exec(server_name, "cat", "/run/wg-e2e-dns-count"))
answer = docker_exec(client_name, "resolvectl", "query", "wg-e2e.test")
assert "10.76.0.1" in answer, "split DNS did not answer through the tunnel"
after = int(docker_exec(server_name, "cat", "/run/wg-e2e-dns-count"))
assert after > before, "split DNS query did not reach the secondary peer"
print("ok   split DNS scoped to the listed domain", flush=True)

assert rpc("wireguard.disconnect", {"profileId": "wg-secondary"}) == {"stopped": True}
assert rpc("wireguard.status", {"profileId": "wg-secondary"})["state"] == "stopped"
assert not any(
    entry["owner"] == "wg:wg-secondary" for entry in rpc("owned.list", None)["owners"]
)
print("ok   secondary disconnect removed ownership", flush=True)

docker_exec(
    client_name,
    "systemctl",
    "mask",
    "--runtime",
    "--now",
    "systemd-resolved.service",
)
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
unavailable = rpc(
    "wireguard.connect", {"profileId": "wg-dns-recover", "config": dns_config, "routes": []}
)["status"]
if unavailable["state"] != "running" or unavailable["dnsApplied"]:
    try:
        resolved_state = docker_exec(
            client_name, "systemctl", "is-active", "systemd-resolved.service"
        )
    except RuntimeError:
        resolved_state = "inactive"
    raise RuntimeError(
        "unexpected DNS state after resolved mask: "
        f"tunnel={unavailable['state']}, dnsApplied={unavailable['dnsApplied']}, "
        f"resolved={resolved_state}"
    )
assert "dnsNotApplied" in unavailable["warnings"]
print("ok   absent resolved is reported without dropping WG", flush=True)

docker_exec(
    client_name, "systemctl", "unmask", "--runtime", "systemd-resolved.service"
)
docker_exec(client_name, "systemctl", "start", "systemd-resolved.service")
for _ in range(30):
    time.sleep(0.5)
    status = rpc("wireguard.status", {"profileId": "wg-dns-recover"})
    if status["dnsApplied"]:
        break
else:
    raise RuntimeError("daemon did not apply DNS after resolved became available")
restored = docker_exec(client_name, "resolvectl", "status", unavailable["interfaceName"])
assert "10.77.0.1" in restored and "~." in restored
print("ok   daemon applied pending DNS when resolved returned", flush=True)
assert rpc("wireguard.disconnect", {"profileId": "wg-dns-recover"}) == {"stopped": True}

crash_status = rpc(
    "wireguard.connect", {"profileId": "wg-dns-crash", "config": dns_config, "routes": []}
)["status"]
crash_interface = crash_status["interfaceName"]
docker_exec(
    client_name,
    "systemctl",
    "kill",
    "-s",
    "KILL",
    "network-orchestrator.service",
)
for _ in range(20):
    time.sleep(0.5)
    try:
        owners = rpc("owned.list", None)["owners"]
    except RuntimeError:
        continue
    if not any(entry["owner"] == "wg:wg-dns-crash" for entry in owners):
        break
else:
    raise RuntimeError("daemon did not recover full/DNS ownership")
print("ok   daemon restarted and removed crashed full owner", flush=True)

try:
    docker_exec(client_name, "ip", "link", "show", crash_interface)
except RuntimeError:
    pass
else:
    raise RuntimeError("full WireGuard link survived daemon recovery")
rules = docker_exec(client_name, "ip", "-4", "rule", "show")
assert "10000:" not in rules and "10001:" not in rules
table = docker_exec(client_name, "ip", "-4", "route", "show", "table", "51820")
assert "default" not in table, "full tunnel table survived recovery"
print("ok   crash recovery removed full link, rules, route, and DNS link", flush=True)

docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)

print("\n=== WireGuard always-on replays before UI login", flush=True)
result = rpc(
    "alwaysOn.set",
    {"definition": {"kind": "wireGuard", "profile": {
        "profileId": "wg-always", "config": config, "routes": []
    }}},
)
assert result["stored"] and result["active"], "WireGuard always-on did not activate"
stored = rpc("alwaysOn.list", {})
assert any(item["profileId"] == "wg-always" for item in stored["profiles"])
assert client_private not in json.dumps(stored), "always-on list leaked WireGuard key"
mode = docker_exec(client_name, "stat", "-c", "%a", "/var/lib/network-orchestrator/profiles/0/definitions.json")
assert mode == "600", "always-on config is not private"
print("ok   typed definition stored privately without leaking in list", flush=True)

docker_exec(client_name, "systemctl", "kill", "-s", "KILL", "network-orchestrator.service")
for _ in range(50):
    try:
        status = rpc("wireguard.status", {"profileId": "wg-always"})
        if status["state"] == "running":
            break
    except RuntimeError:
        pass
    time.sleep(0.2)
else:
    raise RuntimeError("WireGuard always-on did not replay after daemon SIGKILL")
route = docker_exec(client_name, "ip", "-4", "route", "show", "10.77.0.0/24")
assert f"dev {status['interfaceName']}" in route, "replayed WireGuard route is missing"
print("ok   crash recovery re-created WireGuard link and route", flush=True)

result = rpc("alwaysOn.remove", {"kind": "wireGuard", "profileId": "wg-always"})
assert result["removed"] and result["disconnected"]
route = docker_exec(client_name, "ip", "-4", "route", "show", "10.77.0.0/24")
assert "wg-" not in route, "WireGuard always-on route survived disable"
print("ok   disable removed definition, link and route", flush=True)
print("ALL 32 WIREGUARD CHECKS PASSED", flush=True)
