#!/usr/bin/env python3
"""Exercise generated Xray proxy configs in disposable Docker containers.

Usage: xray_scenarios.py CLIENT SERVER
The two containers must share a private Docker network. SERVER serves
/opt/netorch/e2e/server-health.txt on port 8765. No host network is changed.
"""

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
XRAY = Path(os.environ.get("XRAY_E2E_BINARY", str(ROOT / "target/release/xray-package/v26.10.31/xray")))
GENERATOR = ROOT / "target/debug/examples/xray_e2e_config"
CLIENT_XRAY = "/opt/netorch/bin/xray-e2e"


def run(*args, input_text=None):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"E2E command failed: {args[0]} {args[1]}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def docker_exec(container, *args, input_text=None):
    return run("docker", "exec", "-i", container, *args, input_text=input_text)


def write_container_json(container, path, value):
    code = (
        "import json,os,sys; "
        "p=sys.argv[1]; "
        "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); "
        "f=os.fdopen(fd,'w'); json.dump(json.load(sys.stdin),f); f.close()"
    )
    docker_exec(container, "python3", "-c", code, path, input_text=json.dumps(value))


def start_xray(container, config, label):
    docker_exec(container, CLIENT_XRAY, "run", "-test", "-c", config)
    launch = (
        f"{CLIENT_XRAY} run -c {config} > /dev/null 2>&1 "
        f"& echo $! > /tmp/netorch-xray-{label}.pid"
    )
    docker_exec(container, "sh", "-c", launch)


def stop_xray(container, label):
    code = (
        "import os,signal,sys; "
        "p='/tmp/netorch-xray-'+sys.argv[1]+'.pid'; "
        "os.kill(int(open(p).read()),signal.SIGTERM) if os.path.exists(p) else None"
    )
    try:
        docker_exec(container, "python3", "-c", code, label)
    except RuntimeError:
        pass


def wait_tcp(container, port):
    probe = (
        "import socket,sys; "
        "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),0.5); s.close()"
    )
    for _ in range(50):
        try:
            docker_exec(container, "python3", "-c", probe, str(port))
            return
        except RuntimeError:
            time.sleep(0.1)
    raise RuntimeError("Xray proxy did not open its local port")


def generate_client(uri, local_dir, name):
    destination = local_dir / f"{name}.json"
    payload = {"uri": uri, "socksPort": 10808, "httpPort": 10809}
    run(str(GENERATOR), str(destination), input_text=json.dumps(payload))
    return destination


def assert_proxies(client, server_ip):
    url = f"http://{server_ip}:8765/server-health.txt"
    common = ("curl", "--silent", "--show-error", "--fail", "--max-time", "8", "--noproxy", "")
    socks = docker_exec(client, *common, "--socks5-hostname", "127.0.0.1:10808", url)
    assert socks == "netorch-e2e-server", "SOCKS5 proxy returned unexpected content"
    print("ok   SOCKS5 reached the peer HTTP server", flush=True)
    http = docker_exec(
        client, *common, "--proxytunnel", "--proxy", "http://127.0.0.1:10809", url
    )
    assert http == "netorch-e2e-server", "HTTP CONNECT returned unexpected content"
    print("ok   HTTP CONNECT reached the peer HTTP server", flush=True)


def run_client(client, server_ip, uri, local_dir, label):
    config = generate_client(uri, local_dir, label)
    config_path = f"/opt/netorch/bin/xray-{label}.json"
    run("docker", "cp", str(config), f"{client}:{config_path}")
    docker_exec(client, "chmod", "0600", config_path)
    try:
        start_xray(client, config_path, "client")
        wait_tcp(client, 10808)
        wait_tcp(client, 10809)
        assert_proxies(client, server_ip)
    finally:
        stop_xray(client, "client")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: xray_scenarios.py CLIENT SERVER")
    client, server = sys.argv[1:]
    print("\n=== Xray userspace proxy across two containers", flush=True)
    version = run(str(XRAY), "version")
    assert version.startswith("Xray 26.10.31 "), "unexpected Xray version"
    run("cargo", "build", "-q", "-p", "net-manager-core", "--example", "xray_e2e_config")
    for container in (client, server):
        docker_exec(container, "mkdir", "-p", "/opt/netorch/bin")
        run("docker", "cp", str(XRAY), f"{container}:{CLIENT_XRAY}")
        assert docker_exec(container, CLIENT_XRAY, "version").startswith("Xray 26.10.31 ")
    docker_exec(client, "which", "curl")
    server_ip = docker_exec(
        client,
        "python3",
        "-c",
        "import socket,sys; print(socket.gethostbyname(sys.argv[1]))",
        server,
    )
    socket.inet_aton(server_ip)

    with tempfile.TemporaryDirectory(prefix="netorch-xray-e2e-") as directory:
        local_dir = Path(directory)
        vless_id = str(uuid.uuid4())
        vless_server = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "0.0.0.0", "port": 11001, "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": vless_id}]},
                "streamSettings": {"network": "raw", "security": "none"},
            }],
            "outbounds": [{"protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": [server_ip]}],
            }}],
        }
        write_container_json(server, "/tmp/netorch-xray-vless.json", vless_server)
        start_xray(server, "/tmp/netorch-xray-vless.json", "server")
        try:
            uri = f"vless://{vless_id}@{server_ip}:11001?type=raw&security=none"
            run_client(client, server_ip, uri, local_dir, "vless")
        finally:
            stop_xray(server, "server")
        print("ok   generated VLESS raw config passed interop", flush=True)

        docker_exec(
            server,
            "openssl",
            "req",
            "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=xray-e2e.test", "-addext", "subjectAltName=DNS:xray-e2e.test",
            "-keyout", "/tmp/netorch-xray-key.pem", "-out", "/tmp/netorch-xray-cert.pem",
        )
        cert_der = subprocess.run(
            ("docker", "exec", server, "openssl", "x509", "-in", "/tmp/netorch-xray-cert.pem", "-outform", "DER"),
            capture_output=True,
            check=True,
        ).stdout
        cert_pin = hashlib.sha256(cert_der).hexdigest()
        password = secrets.token_hex(16)
        hysteria_server = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "0.0.0.0", "port": 11002, "protocol": "hysteria",
                "settings": {"version": 2, "clients": [{"auth": password}]},
                "streamSettings": {
                    "network": "hysteria", "security": "tls",
                    "hysteriaSettings": {"version": 2},
                    "tlsSettings": {"alpn": ["h3"], "certificates": [{
                        "certificateFile": "/tmp/netorch-xray-cert.pem",
                        "keyFile": "/tmp/netorch-xray-key.pem",
                    }]},
                },
            }],
            "outbounds": [{"protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": [server_ip]}],
            }}],
        }
        write_container_json(server, "/tmp/netorch-xray-hysteria.json", hysteria_server)
        start_xray(server, "/tmp/netorch-xray-hysteria.json", "server")
        try:
            uri = (
                f"hysteria2://{password}@{server_ip}:11002"
                f"?sni=xray-e2e.test&pinSHA256={cert_pin}"
            )
            run_client(client, server_ip, uri, local_dir, "hysteria")
        finally:
            stop_xray(server, "server")
        print("ok   generated Hysteria2 pinned TLS config passed interop", flush=True)
    print("ALL 4 XRAY PROXY CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
