#!/usr/bin/env python3
"""Exercise real daemon failover in a disposable Docker network namespace.

Run from the repository root after building the daemon. No host route, DNS,
service or app-data mutation occurs. Uses the existing netorch-e2e-client image
and the pinned Xray already staged by the package build.
"""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.client import HTTPResponse
from struct import pack, unpack
from urllib.parse import quote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def driver(service_checks_only=False, named_proxies=False):
    root = Path(__file__).resolve().parents[2]
    binary = root / "target/debug/network-orchestrator-daemon"
    cli = root / "target/debug/netorch"
    xray = root / "target/release/xray-package/v26.10.31"
    if not binary.is_file() or not cli.is_file() or not (xray / "xray").is_file():
        raise SystemExit("Build daemon and CLI and stage pinned Linux Xray before this scenario")
    name = "netorch-multinode-" + uuid.uuid4().hex[:12]
    run("docker", "run", "--detach", "--name", name, "--network", "none",
        "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--security-opt", "label=disable",
        "--ulimit", "nofile=16384:16384",
        "--entrypoint", "sleep", "netorch-e2e-client", "infinity")
    try:
        run("docker", "exec", name, "mkdir", "-p", "/usr/lib/network-orchestrator/xray/v26.10.31")
        run("docker", "cp", str(xray) + "/.", name + ":/usr/lib/network-orchestrator/xray/v26.10.31/")
        run("docker", "exec", name, "chown", "-R", "0:0", "/usr/lib/network-orchestrator/xray")
        # Packaged files are public read/execute, unlike the private staging
        # directory produced by a per-user managed installer.
        run("docker", "exec", name, "chmod", "-R", "a+rX", "/usr/lib/network-orchestrator/xray")
        run("docker", "cp", str(binary), name + ":/tmp/network-orchestrator-daemon")
        run("docker", "cp", str(cli), name + ":/tmp/netorch")
        run("docker", "cp", str(Path(__file__).resolve()), name + ":/tmp/multinode_scenarios.py")
        run("docker", "cp", str(root / "packaging/linux/com.netmanager.app.policy"),
            name + ":/usr/share/polkit-1/actions/com.netmanager.app.policy")
        result = subprocess.run(["docker", "exec", "--env", "NETORCH_MULTINODE_E2E=1",
            "--env", f"NETORCH_SERVICE_CHECKS_E2E={int(service_checks_only)}",
            "--env", f"NETORCH_NAMED_PROXIES_E2E={int(named_proxies)}", name,
            "python3", "-u", "/tmp/multinode_scenarios.py", "--inside"], text=True, timeout=600)
        if result.returncode:
            raise SystemExit(result.returncode)
    finally:
        run("docker", "rm", "--force", name)


def inside():
    if not Path("/.dockerenv").exists() or os.environ.get("NETORCH_MULTINODE_E2E") != "1":
        raise SystemExit("This scenario may only run inside its disposable Docker container")
    Path("/run/network-orchestrator").mkdir(mode=0o755, exist_ok=True)
    xray = "/usr/lib/network-orchestrator/xray/v26.10.31/xray"
    children = []
    servers = []
    keys = {"primary": "1" * 16, "backup": "2" * 16, "reserve": "4" * 16, "pinned": "3" * 16}
    with tempfile.TemporaryDirectory(prefix="netorch-multinode-") as tmp:
        directory = Path(tmp)
        directory.chmod(0o755)
        cert, key = directory / "cert.pem", directory / "key.pem"
        ca, ca_key, csr = directory / "ca.pem", directory / "ca-key.pem", directory / "request.pem"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Netorch Disposable Test CA", "-keyout", str(ca_key), "-out", str(ca),
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
            "-keyout", str(key), "-out", str(csr))
        extension = directory / "extensions"
        extension.write_text(chr(10).join([
            "subjectAltName=DNS:localhost,DNS:default.test,DNS:pinned.test,DNS:direct.test,DNS:blocked.test,DNS:api.country.is,DNS:ipinfo.io,IP:198.51.100.50",
            "basicConstraints=CA:FALSE", "extendedKeyUsage=serverAuth",
            "keyUsage=digitalSignature,keyEncipherment", "",
        ]))
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
            "-CAcreateserial", "-days", "1", "-extfile", str(extension), "-out", str(cert))
        Path("/usr/local/share/ca-certificates/netorch-test.crt").write_bytes(ca.read_bytes())
        run("update-ca-certificates")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        records = {}
        records["serviceRequests"] = []
        records["proxyRequests"] = []
        socket_path = "/run/network-orchestrator/daemon.sock"
        managed_logs = []
        log_capture_stop = threading.Event()
        def capture_managed_logs():
            seen = set()
            while not log_capture_stop.wait(.005):
                for path in Path("/run/network-orchestrator/0").glob("xray-*/xray.log"):
                    try:
                        inode = path.stat().st_ino
                        if inode not in seen and len(seen) < 16:
                            managed_logs.append(path.open())
                            seen.add(inode)
                    except FileNotFoundError:
                        pass
        log_capture = threading.Thread(target=capture_managed_logs, daemon=True)
        log_capture.start()

        def port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        def start(name, args, env=None):
            with open(directory / (name + ".log"), "ab") as log:
                child = subprocess.Popen(args, env=env, stdout=log, stderr=log)
            children.append(child)
            return child

        def start_node(name):
            path = directory / (name + ".json")
            records[name]["process"] = start(name, [xray, "run", "-config", str(path)])

        def stop_node(name):
            child = records[name]["process"]
            child.terminate()
            child.wait(timeout=5)

        def rpc(method, params):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(8)
                sock.connect(socket_path)
                stream = sock.makefile("rwb")
                for number, command, body in [(1, "hello", {"protocol": 1, "client": "multinode-e2e"}),
                        (2, method, params)]:
                    stream.write(json.dumps({"id": number, "method": command, "params": body}).encode() + b"\n")
                    stream.flush()
                    reply = json.loads(stream.readline())
                    if not reply.get("ok"):
                        raise AssertionError((command, reply.get("error")))
                return reply["result"]

        def until(predicate, description, timeout=35):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    if predicate():
                        print("PASS", description, flush=True)
                        return
                except (OSError, subprocess.SubprocessError, KeyError, AssertionError):
                    pass
                time.sleep(.25)
            if Path(socket_path).exists():
                print("Last synthetic tunnel status:", rpc("xray.status", {"profileId": "multinode-e2e"}), file=sys.stderr)
            print("Last synthetic HTTP response:", records.get("lastRequest"), file=sys.stderr)
            raise AssertionError(description)

        def request(host):
            result = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "3", "--noproxy", "*",
                "--cacert", str(ca), "--resolve", f"{host}:9443:198.51.100.10", f"https://{host}:9443/"],
                capture_output=True, text=True)
            records["lastRequest"] = {"host": host, "code": result.returncode,
                "body": result.stdout, "error": result.stderr}
            return result.stdout if result.returncode == 0 else None

        def active():
            return rpc("xray.status", {"profileId": "multinode-e2e"})["failover"]["activeKey"]

        try:
            # Synthetic underlay: all routes, peers and packet filters stay
            # inside this disposable namespace.
            run("ip", "link", "add", "e2e-uplink", "type", "dummy")
            run("ip", "address", "add", "10.7.0.1/24", "dev", "e2e-uplink")
            run("ip", "link", "set", "e2e-uplink", "up")
            run("ip", "route", "add", "default", "via", "10.7.0.254", "dev", "e2e-uplink", "metric", "10")
            run("nft", "add", "table", "ip", "e2e_peers")
            run("nft", "add", "chain", "ip", "e2e_peers", "output",
                "{ type nat hook output priority -100; policy accept; }")
            run("nft", "add", "rule", "ip", "e2e_peers", "output",
                "ip", "daddr", "10.8.0.20", "dnat", "to", "127.0.0.1")
            with open("/etc/hosts", "a") as hosts:
                hosts.write("\n198.51.100.10 default.test pinned.test\n")
                hosts.write("198.51.100.50 direct.test blocked.test\n")

            def managed_pid():
                managed = [path.parent for path in Path("/proc").glob("[0-9]*/cmdline")
                    if b"/run/network-orchestrator/0/" in path.read_bytes()]
                assert len(managed) == 1, "expected exactly one daemon-owned Xray"
                return int(managed[0].name)

            def watchdog():
                return rpc("xray.status", {"profileId": "multinode-e2e"})["watchdog"]
            outbounds = []
            subscription_links = []
            countries = {"primary": "NL", "backup": "CA", "reserve": "RU", "pinned": "JP"}
            for name in keys:
                class Handler(BaseHTTPRequestHandler):
                    marker = name
                    protocol_version = "HTTP/1.1"
                    def do_HEAD(self):
                        records["serviceRequests"].append({
                            "node": self.marker, "path": self.path,
                            "authorization": self.headers.get("Authorization"),
                            "cookie": self.headers.get("Cookie"),
                        })
                        if self.path.startswith("/blocked-service") and records.get("serviceFailure"):
                            time.sleep(6)
                            self.close_connection = True
                            return
                        status = 403 if self.path.startswith("/denied-service") else (
                            302 if self.path.startswith("/redirect-service") else 200)
                        self.send_response(status)
                        if status == 302:
                            self.send_header("Location", "/unexpected-redirect-follow")
                        self.send_header("Set-Cookie", "fixture=must-not-be-reused")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    def do_GET(self):
                        records["proxyRequests"].append((self.marker, self.path))
                        host = self.headers.get("Host", "").split(":")[0]
                        if self.path == "/subscription":
                            body = records["subscriptionBody"].encode()
                        elif host in ("api.country.is", "ipinfo.io"):
                            body = json.dumps({"country": countries[self.marker],
                                "ip": "203.0.113.20"}).encode()
                        else:
                            body = self.marker.encode()
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    def log_message(self, *_):
                        pass
                http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                http.socket = context.wrap_socket(http.socket, server_side=True)
                servers.append(http)
                threading.Thread(target=http.serve_forever, daemon=True).start()
                listen, ident = port(), str(uuid.uuid4())
                records[name] = {"port": listen}
                subscription_links.append(
                    f"vless://{ident}@10.8.0.20:{listen}?security=none&type=tcp#"
                    + quote("🇨🇦 Canada " + name))
                config = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": listen,
                    "protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": ident}]}}],
                    # Xray 26.10 blocks private destinations on server-side
                    # VLESS by default; only our disposable HTTPS peer is allowed.
                    "outbounds": [{"protocol": "freedom", "settings": {
                        "redirect": f"127.0.0.1:{http.server_port}",
                        "finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}],
                    }}]}
                (directory / (name + ".json")).write_text(json.dumps(config))
                start_node(name)
                tag = ("pin-" if name == "pinned" else "node-") + keys[name]
                outbounds.append({"tag": tag, "protocol": "vless", "settings": {"vnext": [{"address": "10.8.0.20",
                    "port": listen, "users": [{"id": ident, "encryption": "none"}]}]},
                    "streamSettings": {"network": "tcp", "security": "none"}})
            # Preserve the daemon's generated-config invariant: direct is second.
            records["subscriptionBody"] = "\n".join(subscription_links)
            outbounds.insert(1, {"tag": "direct", "protocol": "freedom"})
            outbounds.append({"tag": "blocked", "protocol": "blackhole"})
            outbounds.append({"tag": "dns", "protocol": "dns", "settings": {"rules": [
                {"action": "return", "qType": "65,28", "rCode": 5},
                {"action": "hijack", "qType": "1", "domain": ["full:default.test"]},
                {"action": "direct"},
            ]}})
            config = {"log": {"loglevel": "warning"}, "inbounds": [
                {"tag": "socks-in", "listen": "127.0.0.1", "port": 19080, "protocol": "socks", "settings": {"udp": True}},
                {"tag": "http-in", "listen": "127.0.0.1", "port": 19081, "protocol": "http"}],
                "dns": {"servers": ["1.1.1.1"], "hosts": {"default.test": "198.51.100.10"}},
                "outbounds": outbounds, "routing": {"domainStrategy": "AsIs", "rules": [
                    {"type": "field", "network": "tcp,udp", "port": 53, "outboundTag": "dns"},
                    {"type": "field", "network": "udp", "port": 443, "outboundTag": "blocked"},
                    {"type": "field", "domain": ["full:pinned.test"], "outboundTag": "pin-" + keys["pinned"]},
                    {"type": "field", "network": "tcp,udp", "balancerTag": "failover"}],
                    "balancers": [{"tag": "failover", "selector": ["unavailable"]}]}}
            Path("/run/dbus").mkdir(exist_ok=True)
            run("dbus-daemon", "--system", "--fork")
            polkit = next(path for path in ("/usr/lib/polkit-1/polkitd", "/usr/libexec/polkitd")
                if Path(path).exists())
            if os.environ.get("NETORCH_SERVICE_CHECKS_E2E") in ("1", "2") or os.environ.get("NETORCH_NAMED_PROXIES_E2E") == "1":
                rules = Path("/etc/polkit-1/rules.d")
                rules.mkdir(parents=True, exist_ok=True)
                (rules / "99-netorch-e2e.rules").write_text(
                    'polkit.addRule(function(action, subject) {'
                    ' if (subject.user === "nobody" && action.id.indexOf("com.netmanager.app.") === 0)'
                    ' return polkit.Result.YES; });')
            start("polkit", [polkit, "--no-debug"])
            until(lambda: subprocess.run(["pkcheck", "--action-id", "com.netmanager.app.connect-profile",
                "--process", str(os.getpid())], capture_output=True).returncode == 0, "isolated polkit authorizes root")
            env = dict(os.environ, SSL_CERT_FILE=str(ca))
            daemon = start("daemon", ["/tmp/network-orchestrator-daemon", "--socket", socket_path,
                "--state-dir", str(directory / "state")], env)
            until(lambda: Path(socket_path).exists(), "isolated daemon starts")
            Path(socket_path).chmod(0o666)
            cli_data = directory / "cli-data"
            cli_data.mkdir(mode=0o700)
            os.chown(cli_data, 65534, 65534)
            runtime_dir = directory / "user-runtime"
            runtime_dir.mkdir(mode=0o700)
            os.chown(runtime_dir, 65534, 65534)
            cli_env = dict(env, XDG_RUNTIME_DIR=str(runtime_dir))
            def cli_raw(*args):
                return subprocess.run(["/tmp/netorch", "--data-dir", str(cli_data), "--json", *args],
                    check=False, text=True, capture_output=True, env=cli_env, user=65534, group=65534,
                    timeout=90)
            def cli(*args):
                result = cli_raw(*args)
                if result.returncode:
                    raise AssertionError("synthetic CLI failed: " + result.stderr)
                return json.loads(result.stdout)
            cli("add", f"https://localhost:{servers[0].server_port}/subscription", "--name", "country-proof")
            if os.environ.get("NETORCH_NAMED_PROXIES_E2E") == "1":
                # All setup and mutations below remain in this disposable
                # namespace and the UID-65534 temporary data directory.
                document_path = cli_data / "profiles.json"
                document = json.loads(document_path.read_text())
                profile = document["profiles"][0]
                profile["xrayMode"] = "tun"
                profile["routes"] = []
                profile["privateLanDirect"] = False
                profile["xrayTunDnsServers"] = []
                profile["domainPolicies"] = [
                    {"target": "block", "domains": ["full:blocked.test"]},
                    {"target": "direct", "domains": ["full:direct.test"]},
                ]
                profile["xrayDns"] = {"hosts": {
                    "direct.test": ["198.51.100.50"], "blocked.test": ["198.51.100.50"]}}
                profile["subscription"]["probeUrl"] = "https://198.51.100.50:9443/"
                document_path.write_text(json.dumps(document))
                profile_id = profile["id"]
                cli("use", "country-proof", "1")
                cli("backup", "set", "country-proof", "reserve")
                endpoints = cli("endpoints", "country-proof")
                # Resolve real stable keys, never the root RPC fixture's
                # unrelated synthetic 1111/2222/... identifiers.
                endpoint_rows = endpoints if isinstance(endpoints, list) else endpoints["endpoints"]
                real_keys = {name: next(row["key"] for row in endpoint_rows
                    if name in row["name"]) for name in keys}
                before_configuration = len(records["proxyRequests"])
                cli_env["NETWORK_ORCHESTRATOR_SOCKET"] = str(directory / "absent.sock")
                try:
                    for name, target in [
                        ("default", ["--rules"]),
                        ("nl", ["--via", real_keys["backup"]]),
                        ("ru", ["--pool", real_keys["backup"], real_keys["pinned"]]),
                        ("direct", ["--direct"]),
                        ("gone", ["--via", "ffffffffffffffff"]),
                        ("bypass", ["--via", real_keys["reserve"], "--no-proxy", "198.51.100.50"]),
                    ]:
                        cli("proxy", "set", name, "--profile", "country-proof", *target)
                    assert {row["name"] for row in cli("proxy", "list")} == {
                        "default", "nl", "ru", "direct", "gone", "bypass"}
                    unchanged = document_path.read_bytes()
                    duplicate_profile = cli_raw("proxy", "--profile", "country-proof", "set",
                        "nl", "--profile", "country-proof", "--direct")
                    assert duplicate_profile.returncode != 0
                    assert document_path.read_bytes() == unchanged
                finally:
                    cli_env.pop("NETWORK_ORCHESTRATOR_SOCKET")
                assert len(records["proxyRequests"]) == before_configuration
                print("PASS named proxy configuration and listing are offline and send no probes", flush=True)

                class UnderlayHandler(Handler):
                    marker = "underlay"
                physical = ThreadingHTTPServer(("127.0.0.1", 0), UnderlayHandler)
                physical.socket = context.wrap_socket(physical.socket, server_side=True)
                servers.append(physical)
                threading.Thread(target=physical.serve_forever, daemon=True).start()
                # The marker requires the physical output interface before
                # DNAT, not merely a nonzero mark. Captured TUN traffic cannot
                # reach it by being redirected back to loopback.
                run("nft", "add", "rule", "ip", "e2e_peers", "output",
                    "oifname", "e2e-uplink", "meta", "mark", "!=", "0",
                    "ip", "daddr", "198.51.100.50",
                    "tcp", "dport", "9443", "dnat", "to", f"127.0.0.1:{physical.server_port}")
                cli("up", "country-proof")
                assert (runtime_dir / "netorch" / f"{profile_id}.pid").is_file()

                def user_rpc(method, params):
                    script = (
                        "import json,socket,sys\n"
                        "with socket.socket(socket.AF_UNIX) as s:\n"
                        " s.settimeout(8);s.connect(sys.argv[1]);f=s.makefile('rwb')\n"
                        " for i,m,p in [(1,'hello',{'protocol':1,'client':'proxy-e2e'}),"
                        "(2,sys.argv[2],json.loads(sys.argv[3]))]:\n"
                        "  f.write(json.dumps({'id':i,'method':m,'params':p}).encode()+b'\\n');f.flush()\n"
                        "  r=json.loads(f.readline());assert r.get('ok'),r\n"
                        " print(json.dumps(r['result']))\n")
                    result = subprocess.run(["python3", "-c", script, socket_path, method, json.dumps(params)],
                        check=True, text=True, capture_output=True, env=cli_env, user=65534, group=65534, timeout=15)
                    return json.loads(result.stdout)

                def named_status(name):
                    return next(row for row in user_rpc("xray.proxyExits", {"profileId": profile_id})
                        if row["name"] == name)

                def user_pid():
                    matches = [path.parent for path in Path("/proc").glob("[0-9]*/cmdline")
                        if b"/run/network-orchestrator/65534/" in path.read_bytes()]
                    assert len(matches) == 1, "expected exactly one user-owned managed Xray"
                    return int(matches[0].name)

                poisoned_env = dict(cli_env, HTTP_PROXY="http://127.0.0.1:9", http_proxy="http://127.0.0.1:9",
                    HTTPS_PROXY="http://127.0.0.1:9", https_proxy="http://127.0.0.1:9",
                    ALL_PROXY="socks5h://127.0.0.1:9", all_proxy="socks5h://127.0.0.1:9",
                    NO_PROXY="*", no_proxy="*")

                def proxy_run(name, *command):
                    return subprocess.run(["/tmp/netorch", "--data-dir", str(cli_data),
                        "proxy", name, "--", *command], text=True, capture_output=True,
                        env=poisoned_env, user=65534, group=65534, timeout=20)

                def via(name, host="198.51.100.50"):
                    return proxy_run(name, "curl", "-sS", "--max-time", "5", "--cacert", str(ca),
                        f"https://{host}:9443/")

                until(lambda: named_status("ru").get("pool", {}).get("activeKey") == real_keys["backup"],
                    "independent named pool probes and selects its own first member", timeout=70)
                initial_pid = user_pid()
                initial_rules = run("ip", "-j", "rule", "show")
                initial_routes = run("ip", "-j", "route", "show", "table", "all")
                normal = subprocess.run(["curl", "-sS", "--max-time", "5", "--noproxy", "*",
                    "--cacert", str(ca), "https://198.51.100.50:9443/"], text=True,
                    capture_output=True, env=cli_env, user=65534, group=65534, timeout=10)
                assert normal.returncode == 0 and normal.stdout == "primary", normal
                for name, expected in [("default", "primary"), ("nl", "backup"), ("ru", "backup"),
                        ("direct", "underlay"), ("bypass", "primary")]:
                    result = via(name)
                    assert result.returncode == 0 and result.stdout == expected, (name, result)
                blocked = via("default", "blocked.test")
                assert blocked.returncode != 0, "normal-rules exit ignored the block"
                fixed = via("nl", "blocked.test")
                assert fixed.returncode == 0 and fixed.stdout == "backup", fixed
                direct_rule = via("default", "direct.test")
                assert direct_rule.returncode == 0 and direct_rule.stdout == "underlay", direct_rule
                missing = via("gone")
                assert missing.returncode != 0, "missing fixed node fell back"
                print("PASS real curl follows rules, fixed node and pool; marked direct bypasses full TUN; ambient proxy/NO_PROXY cannot bypass the exit", flush=True)

                result = proxy_run("default", "python3", "-c",
                    "import json,sys;print(json.dumps(sys.argv[1:]))", "two words", ";$not-a-shell")
                assert result.returncode == 0 and json.loads(result.stdout) == ["two words", ";$not-a-shell"]
                assert proxy_run("default", "/bin/sh", "-c", "exit 37").returncode == 37
                sleeper = subprocess.Popen(["/tmp/netorch", "--data-dir", str(cli_data),
                    "proxy", "default", "--", "/bin/sleep", "60"], env=poisoned_env,
                    user=65534, group=65534, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(sleeper)
                until(lambda: Path(f"/proc/{sleeper.pid}/comm").read_text().strip() == "sleep",
                    "proxy exec preserves the process PID")
                sleeper.send_signal(signal.SIGTERM)
                assert sleeper.wait(timeout=5) == -signal.SIGTERM
                assert user_pid() == initial_pid
                assert run("ip", "-j", "rule", "show") == initial_rules
                assert run("ip", "-j", "route", "show", "table", "all") == initial_routes
                print("PASS argv, exit status and signals survive exec without tunnel restart or routing changes", flush=True)

                stop_node("backup")
                until(lambda: named_status("ru").get("pool", {}).get("activeKey") == real_keys["pinned"],
                    "named pool fails over only to its own next member", timeout=70)
                assert via("ru").stdout == "pinned"
                assert via("nl").returncode != 0, "dead fixed node used the pool or default"
                stop_node("pinned")
                until(lambda: named_status("ru").get("pool", {}).get("activeKey") == "unavailable",
                    "all-down named pool blocks despite healthy default and reserve", timeout=70)
                marker = cli_data / "unexpected-command"
                rejected = proxy_run("ru", "/usr/bin/touch", str(marker))
                assert rejected.returncode != 0 and not marker.exists()
                assert via("default").stdout == "primary" and via("direct").stdout == "underlay"
                assert user_rpc("xray.status", {"profileId": profile_id})["failover"]["activeKey"] == real_keys["primary"]
                print("PASS unavailable fixed exits and pools never leak to default/direct or alter the default node", flush=True)

                cli("proxy", "set", "nl", "--profile", "country-proof", "--direct")
                rejected = proxy_run("nl", "/usr/bin/touch", str(marker))
                assert rejected.returncode != 0 and not marker.exists()
                cli("proxy", "remove", "direct", "--profile", "country-proof")
                rejected = proxy_run("direct", "/usr/bin/touch", str(marker))
                assert rejected.returncode != 0 and not marker.exists()
                assert user_pid() == initial_pid
                old_ports = [(row["socksPort"], row["httpPort"]) for row in user_rpc(
                    "xray.proxyExits", {"profileId": profile_id})]
                cli("down", "country-proof")
                for pair in old_ports:
                    for listener in pair:
                        with socket.socket() as sock:
                            sock.settimeout(.25)
                            assert sock.connect_ex(("127.0.0.1", listener)) != 0, "owned proxy listener leaked"
                assert records["primary"]["process"].poll() is None
                assert records["reserve"]["process"].poll() is None
                print("PASS stale/removed aliases refuse before exec; disconnect removes listeners and preserves peers", flush=True)
                return
            cli("backup", "pool", "set", "country-proof", "Canada", "--no-verify")
            Path(xray).rename(xray + ".disabled")
            try:
                unverified = cli("backup", "pool", "rebuild", "country-proof")
                assert len(unverified["members"]) == 3
                assert all(entry["exitCountry"] is None for entry in unverified["entries"])
                print("PASS name-only pool rebuild needs neither an installed backend nor a country request", flush=True)
            finally:
                Path(xray + ".disabled").rename(xray)
            cli("backup", "pool", "set", "country-proof", "CA:Canada")
            rebuilt = cli("backup", "pool", "rebuild", "country-proof")
            assert len(rebuilt["members"]) == 1, "pool accepted a false advertised country"
            assert any(entry["verdict"] == "wrongCountry" for entry in rebuilt["entries"])
            checks = cli("backup", "verify", "country-proof")
            assert any(check["exitCountry"] == "NL" and check["mismatch"] for check in checks["checks"])
            assert any(check["exitCountry"] == "CA" and not check["mismatch"] for check in checks["checks"])
            print("PASS real unprivileged CLI rebuild and verification use each candidate's HTTPS exit", flush=True)
            source_policy = json.loads(json.dumps(config))
            source_policy["routing"]["balancers"][0]["selector"] = ["node-"]
            source_policy["inbounds"].append({"protocol": "tun",
                "settings": {"mtu": 8500, "dns": ["1.1.1.1"]}})
            source_policy["policy"] = {"levels": {"0": {"connIdle": 120}}}
            for outbound in source_policy["outbounds"]:
                if outbound["protocol"] == "vless":
                    outbound["streamSettings"]["sockopt"] = {
                        "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 10,
                        "tcpUserTimeout": 20000, "tcpNoDelay": True}
            policy_path = directory / "import-policy.json"
            source_bytes = json.dumps(source_policy).encode()
            policy_path.write_bytes(source_bytes)
            preview = cli("migrate", "preview", "country-proof", "--from", str(policy_path))
            assert preview["refused"] == [] and preview["tunMtu"] == 8500
            cli("migrate", "apply", "country-proof", "--from", str(policy_path))
            saved = json.loads((cli_data / "profiles.json").read_text())["profiles"][0]
            assert saved["xrayTunMtu"] == 8500 and saved["xrayConnectionIdleSecs"] == 120
            assert saved["xraySockopts"]["tcpUserTimeout"] == 20000
            assert len(saved["pinnedPolicies"]) == 1 and len(saved["subscription"]["backupKeys"]) == 2
            assert policy_path.read_bytes() == source_bytes, "migration changed its source"
            print("PASS actual CLI preview/apply preserves mapped policy and leaves its source unchanged", flush=True)
            connect_params = {"profileId": "multinode-e2e", "config": json.dumps(config),
                "routes": [{"destination": "198.51.100.10/32", "metric": 5},
                    {"destination": "1.1.1.1/32", "metric": 5}],
                "dnsServers": [], "dnsDomains": [], "rejectQuic": True,
                "probeUrl": "https://default.test:9443",
                "failover": {"nodes": [{"key": keys[name]} for name in ("primary", "backup", "reserve")],
                    "primaryKey": keys["primary"], "autoReturnPrimary": True,
                    "probeUrl": "https://localhost:9443", "intervalSecs": 2}}
            rpc("xray.connect", connect_params)
            until(lambda: active() == keys["primary"] and request("default.test") == "primary", "HTTPS probes select primary")
            until(lambda: request("pinned.test") == "pinned", "pinned route uses independent node")
            until(lambda: watchdog()["uplink"] is True and watchdog()["httpsLatencyMs"] is not None,
                "watchdog verifies HTTPS through the owned TUN")
            if os.environ.get("NETORCH_SERVICE_CHECKS_E2E") in ("1", "2"):
                assert records["serviceRequests"] == [], "unsolicited inferred service probe"
                assert cli("checks", "list", "country-proof") == []
                Path(xray).rename(xray + ".disabled")
                try:
                    assert cli("checks", "run", "country-proof") == []
                finally:
                    Path(xray + ".disabled").rename(xray)
                assert records["serviceRequests"] == [], "empty checks caused network traffic"
                cli("checks", "add", "country-proof", "--via", saved["pinnedPolicies"][0]["endpointKey"],
                    "--name", "Service denial", "--url", "https://localhost:9443/denied-service?fixture=private")
                listed = cli("checks", "list", "country-proof")
                assert len(listed) == 1 and listed[0]["background"] is False
                assert "url" not in listed[0] and "private" not in json.dumps(listed)
                assert records["serviceRequests"] == [], "saving a check caused remote traffic"
                denial = cli("checks", "run", "country-proof")
                assert len(denial) == 1 and denial[0]["outcome"] == "http"
                assert denial[0]["httpStatus"] == 403 and denial[0]["consecutiveFailures"] == 0
                assert "private" not in json.dumps(denial) and "url" not in denial[0]
                assert records["serviceRequests"][-1]["node"] == "pinned"
                assert records["serviceRequests"][-1]["authorization"] is None
                assert records["serviceRequests"][-1]["cookie"] is None
                cli("checks", "add", "country-proof", "--via", saved["pinnedPolicies"][0]["endpointKey"],
                    "--name", "Service redirect", "--url", "https://localhost:9443/redirect-service")
                redirected = cli("checks", "run", "country-proof")
                assert {row["httpStatus"] for row in redirected} == {302, 403}
                assert all(row["cookie"] is None for row in records["serviceRequests"])
                assert not any(row["path"] == "/unexpected-redirect-follow" for row in records["serviceRequests"])
                print("PASS real CLI checks are explicit HEAD requests on the pin, without credentials, cookie reuse or redirects", flush=True)
                cli("checks", "add", "country-proof", "--via", saved["pinnedPolicies"][0]["endpointKey"],
                    "--name", "Service TLS rejection", "--url", "https://127.0.0.1:9443/tls-service")
                classified = cli("checks", "run", "country-proof")
                tls = next(row for row in classified if row["name"] == "Service TLS rejection")
                assert tls["outcome"] == "tlsError" and tls["httpStatus"] is None
                assert not any(b"stdin:" in path.read_bytes() and b"xray" in path.read_bytes()
                    for path in Path("/proc").glob("[0-9]*/cmdline")), "manual probe child was not reaped"
                before_refresh = json.loads((cli_data / "profiles.json").read_text())["profiles"][0]["xrayServiceChecks"]
                cli("refresh", "country-proof")
                after_refresh = json.loads((cli_data / "profiles.json").read_text())["profiles"][0]["xrayServiceChecks"]
                assert after_refresh == before_refresh, "subscription refresh lost service check configuration"
                print("PASS real TLS failures are classified without URL leakage, temporary children exit and refresh preserves checks", flush=True)
                # A real unprivileged CLI owns a separate narrow TUN, so these
                # assertions exercise cancellation rather than a mock RPC echo.
                document_path = cli_data / "profiles.json"
                document = json.loads(document_path.read_text())
                user_profile = document["profiles"][0]
                user_profile["xrayMode"] = "tun"
                user_profile["routes"] = [{"destination": "198.51.100.50/32", "metric": 5}]
                user_profile["xrayTunDnsServers"] = []
                user_profile["xrayQuicReject"] = False
                user_profile["subscription"]["probeUrl"] = "https://198.51.100.50:9443/"
                document_path.write_text(json.dumps(document))
                cli("up", "country-proof")
                first_id = user_profile["xrayServiceChecks"][0]["id"]
                pin_key = user_profile["pinnedPolicies"][0]["endpointKey"]
                heads_before = len(records["serviceRequests"])
                cli("checks", "background", "country-proof", first_id, "on")
                until(lambda: len(records["serviceRequests"]) > heads_before,
                    "unprivileged CLI enables an actual live diagnostic worker", timeout=70)
                cli("route", "unpin", "country-proof", "--via", pin_key)
                stopped_count = len(records["serviceRequests"])
                time.sleep(62)
                assert len(records["serviceRequests"]) == stopped_count, "unpin left an old SOCKS probe active"
                assert all(row["outcome"] == "unavailable" for row in cli("checks", "run", "country-proof"))
                cli("route", "pin", "country-proof", "--via", pin_key, "--selector", "full:pinned.test")
                unchanged_document = document_path.read_bytes()
                fault = cli_data / "profiles.json.tmp"
                fault.mkdir()
                try:
                    failed = cli_raw("checks", "add", "country-proof", "--via", pin_key,
                        "--name", "Unsaved background check", "--url",
                        "https://localhost:9443/denied-service?fixture=unsaved-private", "--background")
                    assert failed.returncode != 0, "write fault did not reject the configuration save"
                    assert "unsaved-private" not in failed.stdout + failed.stderr
                    assert document_path.read_bytes() == unchanged_document
                finally:
                    fault.rmdir()
                cancelled_count = len(records["serviceRequests"])
                time.sleep(62)
                assert len(records["serviceRequests"]) == cancelled_count, "failed save left a diagnostic worker running"
                cli("down", "country-proof")
                print("PASS live unpin and failed persistence cancel diagnostic workers without losing canonical settings", flush=True)
                if os.environ.get("NETORCH_SERVICE_CHECKS_E2E") == "2":
                    rpc("xray.disconnect", {"profileId": "multinode-e2e"})
                    return
                stable_pid = managed_pid()
                check = {"id": "service-failure", "name": "Service-specific failure",
                    "url": "https://localhost:9443/blocked-service?fixture=private",
                    "endpointKey": keys["pinned"], "background": True}
                records["serviceFailure"] = True
                before = len(records["serviceRequests"])
                rpc("xray.serviceChecks", {"profileId": "multinode-e2e", "checks": [check]})
                time.sleep(1)
                assert len(records["serviceRequests"]) == before, "saving background checks probed immediately"
                until(lambda: any(row.get("degraded") and row["consecutiveFailures"] >= 3
                    and row["outcome"] == "timeout" for row in watchdog().get("serviceChecks", [])),
                    "three target-specific timeouts produce diagnostic degradation", timeout=205)
                assert request("default.test") == "primary" and request("pinned.test") == "pinned"
                assert managed_pid() == stable_pid, "service failure restarted the tunnel"
                assert active() == keys["primary"], "service failure selected another node"
                assert "private" not in json.dumps(rpc("owned.list", {}))
                assert "private" not in json.dumps(watchdog())
                records["serviceFailure"] = False
                until(lambda: any(row["outcome"] == "http" and row["consecutiveFailures"] == 0
                    and not row["degraded"] for row in watchdog().get("serviceChecks", [])),
                    "fresh HTTP response clears service failure streak", timeout=70)
                assert managed_pid() == stable_pid
                rpc("xray.serviceChecks", {"profileId": "multinode-e2e", "checks": []})
                stopped_count = len(records["serviceRequests"])
                time.sleep(62)
                assert len(records["serviceRequests"]) == stopped_count, "opt-out left background traffic running"
                assert not watchdog().get("serviceChecks")
                assert managed_pid() == stable_pid
                print("PASS service diagnostics never recover/restart/change pins and opt-out stops requests immediately", flush=True)
                rpc("xray.disconnect", {"profileId": "multinode-e2e"})
                return
            def dns_query(qtype):
                name = b"".join(bytes([len(label)]) + label.encode() for label in "default.test".split(".")) + b"\0"
                query = pack("!6H", 1234, 0x100, 1, 0, 0, 0) + name + pack("!2H", qtype, 1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(3)
                    sock.sendto(query, ("1.1.1.1", 53))
                    answer = sock.recv(4096)
                header = unpack("!6H", answer[:12])
                assert header[0] == 1234
                return header, answer
            header, answer = dns_query(1)
            assert header[1] & 15 == 0 and header[3] > 0 and socket.inet_aton("198.51.100.10") in answer
            for qtype in (28, 65):
                header, _ = dns_query(qtype)
                assert header[1] & 15 == 5 and header[3] == 0, "DNS rewrite did not return REFUSED"
            print("PASS pinned Xray answers intercepted A and refuses AAAA/HTTPS according to imported rewrite policy", flush=True)
            dns_pid = managed_pid()
            run("nft", "add", "table", "inet", "e2e_dns_fault")
            run("nft", "add", "chain", "inet", "e2e_dns_fault", "output",
                "{ type filter hook output priority -10; policy accept; }")
            run("nft", "add", "rule", "inet", "e2e_dns_fault", "output",
                "ip", "daddr", "1.1.1.1", "udp", "dport", "53", "drop")
            until(lambda: watchdog()["dnsStallStreak"] >= 3, "watchdog detects bounded DNS failures", timeout=50)
            assert managed_pid() == dns_pid, "DNS-only failure reset a healthy HTTPS path"
            run("nft", "delete", "table", "inet", "e2e_dns_fault")
            until(lambda: watchdog()["dnsStallStreak"] == 0, "DNS recovery clears its diagnostic without restarting HTTPS")
            foreign_udp, storm = [], []
            storm_pid = managed_pid()
            try:
                for _ in range(2005):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(("127.0.0.1", 0))
                    foreign_udp.append(sock)
                for _ in range(31):
                    sock = ssl.create_default_context(cafile=str(ca)).wrap_socket(
                        socket.create_connection(("198.51.100.10", 9443), timeout=3),
                        server_hostname="default.test")
                    storm.append(sock)
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: default.test\r\nConnection: keep-alive\r\n\r\n")
                    response = HTTPResponse(sock)
                    response.begin()
                    assert response.read() == b"primary"
                until(lambda: (watchdog().get("connStorm") or {}).get("count", 0) >= 31,
                    "watchdog reports inner application connection storm")
                assert watchdog()["xrayUdpSockets"] < 2000, "foreign UDP sockets were attributed to Xray"
                assert managed_pid() == storm_pid, "diagnostic-only connection storm caused a reset"
                print("PASS foreign UDP sockets do not trigger owned-child leak recovery", flush=True)
            finally:
                for sock in storm + foreign_udp:
                    sock.close()
            original = managed_pid()
            tls = ssl.create_default_context(cafile=str(ca)).wrap_socket(
                socket.create_connection(("198.51.100.10", 9443), timeout=3),
                server_hostname="default.test")
            def persistent_request():
                tls.sendall(b"GET / HTTP/1.1\r\nHost: default.test\r\nConnection: keep-alive\r\n\r\n")
                response = HTTPResponse(tls)
                response.begin()
                return response.read().decode()
            assert persistent_request() == "primary"
            run("ip", "address", "change", "10.7.0.1/24", "dev", "e2e-uplink",
                "valid_lft", "forever", "preferred_lft", "forever")
            run("ip", "route", "replace", "default", "via", "10.7.0.254", "dev", "e2e-uplink", "metric", "10")
            time.sleep(3)
            assert managed_pid() == original and persistent_request() == "primary", "DHCP renewal reset a live stream"
            tls.close()
            print("PASS unchanged DHCP identity preserves an existing TLS connection", flush=True)
            run("ip", "link", "add", "e2e-uplink-next", "type", "dummy")
            run("ip", "address", "add", "10.9.0.1/24", "dev", "e2e-uplink-next")
            run("ip", "link", "set", "e2e-uplink-next", "up")
            run("ip", "route", "replace", "default", "via", "10.9.0.254", "dev", "e2e-uplink-next", "metric", "10")
            until(lambda: managed_pid() != original and request("default.test") == "primary",
                "source, gateway and interface change respawns only the owned child")
            assert watchdog()["lastRecoveryUnix"] is not None
            bypass = json.loads(run("ip", "-json", "route", "show", "10.8.0.20/32"))
            assert len(bypass) == 1 and bypass[0]["gateway"] == "10.9.0.254" and bypass[0]["dev"] == "e2e-uplink-next"
            print("PASS existing owned endpoint bypass migrates off the old gateway and interface", flush=True)
            run("ip", "route", "del", "default", "via", "10.9.0.254", "dev", "e2e-uplink-next", "metric", "10")
            until(lambda: watchdog()["uplink"] is False, "watchdog observes uplink loss")
            offline_pid = managed_pid()
            os.kill(offline_pid, 9)
            time.sleep(12)
            assert not Path(f"/proc/{offline_pid}").exists(), "offline child did not exit"
            assert not any(b"/run/network-orchestrator/0/" in path.read_bytes()
                for path in Path("/proc").glob("[0-9]*/cmdline")), "daemon restarted a child while offline"
            run("ip", "route", "add", "default", "via", "10.9.0.254", "dev", "e2e-uplink-next", "metric", "10")
            until(lambda: request("default.test") == "primary", "uplink return heals the deferred child crash")
            frozen = managed_pid()
            os.kill(frozen, 19)
            until(lambda: managed_pid() != frozen and request("default.test") == "primary",
                "stalled owned child is replaced when the upstream TCP path is healthy", timeout=100)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(1)
                udp.connect(("198.51.100.10", 443))
                started = time.monotonic()
                try:
                    udp.send(b"synthetic-quic-probe")
                    udp.recv(1)
                except (ConnectionRefusedError, PermissionError):
                    assert time.monotonic() - started < 1, "QUIC rejection was not immediate"
                except TimeoutError as error:
                    raise AssertionError("QUIC silently dropped instead of kernel REJECT") from error
                else:
                    raise AssertionError("QUIC was not rejected")
            print("PASS owned QUIC rejection returns immediate kernel error", flush=True)
            stop_node("primary")
            until(lambda: active() == keys["backup"] and request("default.test") == "backup", "primary failure selects backup")
            assert request("pinned.test") == "pinned", "backup changed pinned route"
            stop_node("backup")
            until(lambda: active() == keys["reserve"] and request("default.test") == "reserve", "backup failure selects next ordered reserve")
            start_node("primary")
            until(lambda: active() == keys["primary"] and request("default.test") == "primary", "primary recovery automatically returns")
            managed = [path.parent for path in Path("/proc").glob("[0-9]*/cmdline")
                if b"/run/network-orchestrator/0/" in path.read_bytes()]
            assert len(managed) == 1, "expected exactly one daemon-owned Xray"
            os.kill(int(managed[0].name), 9)
            until(lambda: request("default.test") == "primary", "child respawn reinstalls failover selection")
            stop_node("pinned")
            until(lambda: request("pinned.test") is None, "dead pinned node does not use primary")
            assert request("default.test") == "primary", "pinned failure changed default route"
            stop_node("primary")
            stop_node("reserve")
            until(lambda: active() == "unavailable", "all-down status has no active node")
            assert request("default.test") is None, "all-down leaked to direct"
            print("PASS all-down blocks traffic instead of using direct", flush=True)
            rpc("xray.disconnect", {"profileId": "multinode-e2e"})
            assert "netorch_quic_" not in run("nft", "list", "tables"), "owned QUIC firewall table leaked"
            print("PASS disconnect removes the owned QUIC firewall table", flush=True)
            # A new connection has its own recovery budget. Create actual
            # child-owned UDP transports, not sockets in another process.
            start_node("primary")
            config["routing"]["rules"].insert(2, {"type": "field", "network": "udp",
                "port": 8443, "ip": ["198.51.100.11"], "outboundTag": "direct"})
            connect_params["config"] = json.dumps(config)
            connect_params["routes"].append({"destination": "198.51.100.11/32", "metric": 5})
            rpc("xray.connect", connect_params)
            until(lambda: request("default.test") == "primary", "fresh connection starts for owned UDP recovery")
            leaked_pid = managed_pid()
            staged_path = Path(f"/proc/{leaked_pid}/cmdline").read_bytes().split(b"\0")[3].decode()
            staged = json.loads(Path(staged_path).read_text())
            mark = next(outbound["streamSettings"]["sockopt"]["mark"]
                for outbound in staged["outbounds"] if outbound["tag"] == "direct")
            run("nft", "add", "rule", "ip", "e2e_peers", "output",
                "meta", "mark", str(mark), "ip", "daddr", "198.51.100.11",
                "udp", "dport", "8443", "dnat", "to", "127.0.0.1:8443")
            clients = []
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
                    sink.bind(("127.0.0.1", 8443))
                    for _ in range(2005):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        clients.append(sock)
                        sock.connect(("198.51.100.11", 8443))
                        sock.send(b"owned-udp-lifetime")
                        # Do not overflow the TUN receive queue before Xray
                        # has created the corresponding owned transport.
                        if len(clients) % 16 == 0:
                            time.sleep(.01)
                    until(lambda: managed_pid() != leaked_pid and request("default.test") == "primary",
                        "owned UDP socket leak replaces only the managed child", timeout=70)
                    until(lambda: watchdog()["xrayUdpSockets"] < 2000,
                        "replacement child clears the owned UDP socket accumulation")
            finally:
                for sock in clients:
                    sock.close()

            # A daemon crash followed by an upgrade can leave a child mapped
            # from a removed old package. Cleanup must use protected ownership,
            # never the current pin path or a process-name-wide kill.
            import shutil
            orphan = managed_pid()
            retired = Path(xray).parent.parent / "v26.3.27"
            retired.mkdir(mode=0o755)
            old_binary = retired / "xray"
            Path(xray).rename(old_binary)
            shutil.copy2(old_binary, xray)
            old_binary.unlink()
            assert str(retired) in os.readlink(f"/proc/{orphan}/exe")
            assert os.readlink(f"/proc/{orphan}/exe").endswith(" (deleted)")
            daemon.kill()
            daemon.wait(timeout=5)
            start("daemon-restarted", ["/tmp/network-orchestrator-daemon", "--socket", socket_path,
                "--state-dir", str(directory / "state")], env)
            until(lambda: rpc("xray.status", {"profileId": "multinode-e2e"})["state"] == "stopped",
                "restarted daemon cleans the deleted old-version owned child", timeout=30)
            assert not Path(f"/proc/{orphan}/exe").exists(), "old owned child survived upgrade cleanup"
            assert records["primary"]["process"].poll() is None, "cleanup killed an unrelated Xray peer"
            assert not Path(staged_path).exists(), "old staging survived successful cleanup"
            assert "netorch_quic_" not in run("nft", "list", "tables")
            print("PASS upgrade cleanup preserves unrelated same-binary processes and removes owned state", flush=True)
        finally:
            log_capture_stop.set()
            log_capture.join(timeout=2)
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
            for child in children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for server in servers:
                server.shutdown()
            # Synthetic logs contain no real credentials; print only on failure.
            if sys.exc_info()[0] is not None:
                for path in directory.glob("*.log"):
                    print(path.name, path.read_text(errors="replace")[-4000:], file=sys.stderr)
                for log in managed_logs:
                    print("managed synthetic Xray:", log.read()[-4000:], file=sys.stderr)
            for log in managed_logs:
                log.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        inside()
    elif not sys.argv[1:]:
        driver()
    elif sys.argv[1:] == ["--service-checks"]:
        driver(service_checks_only=True)
    elif sys.argv[1:] == ["--service-checks-client"]:
        driver(service_checks_only=2)
    elif sys.argv[1:] == ["--named-proxies"]:
        driver(named_proxies=True)
    else:
        raise SystemExit("usage: python3 e2e/linux/multinode_scenarios.py [--service-checks|--service-checks-client|--named-proxies]")
