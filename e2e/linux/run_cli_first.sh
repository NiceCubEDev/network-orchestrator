#!/bin/sh
# All network mutations run inside this disposable container, never on the host.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
NAME="netorch-cli-first-$$"
OUT="$ROOT/target/e2e-cli-first"
mkdir -p "$OUT"
for file in target/debug/netorch target/debug/network-orchestrator-daemon target/debug/net-manager-app target/release/xray-package/v26.10.31/xray; do
    test -f "$ROOT/$file" || { echo "missing prerequisite: $ROOT/$file" >&2; exit 1; }
done
cleanup() {
    docker logs "$NAME" >"$OUT/container.log" 2>&1 || true
    docker exec "$NAME" journalctl --no-pager >"$OUT/journal.log" 2>&1 || true
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
if ! docker image inspect netorch-e2e-client >/dev/null 2>&1; then
    docker build -q -t netorch-e2e-client "$ROOT/e2e/linux" >/dev/null
fi
docker build -q -t netorch-cli-first-e2e -f "$ROOT/e2e/linux/Dockerfile.cli-first" "$ROOT/e2e/linux" >"$OUT/install.log"
docker run -d --name "$NAME" --network none -e container=docker \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW \
    --security-opt apparmor=unconfined --device /dev/net/tun \
    --tmpfs /run --tmpfs /run/lock --cgroupns=private \
    -v "$ROOT:/src:ro" -v "$OUT:/artifacts" netorch-cli-first-e2e >/dev/null
for _ in $(seq 60); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 1
done
case "$state" in running|degraded) ;; *) echo "systemd failed: $state" >&2; exit 1 ;; esac
docker exec "$NAME" bash -euc '
 install -m 0755 /src/target/debug/network-orchestrator-daemon /usr/bin/network-orchestrator-daemon
 install -m 0644 /src/packaging/linux/network-orchestrator.service /usr/lib/systemd/system/
 install -m 0644 /src/packaging/linux/com.netmanager.app.policy /usr/share/polkit-1/actions/
 install -m 0644 /src/packaging/linux/tmpfiles.conf /usr/lib/tmpfiles.d/network-orchestrator.conf
 install -m 0644 /src/e2e/linux/app_gui_polkit.rules /etc/polkit-1/rules.d/49-netorch-e2e.rules
 systemd-tmpfiles --create network-orchestrator.conf
 cp -a /src/target/release/xray-package/v26.10.31 /opt/netorch-xray-fixture
 chmod 0755 /opt/netorch-xray-fixture
 systemctl daemon-reload
 systemctl restart polkit.service
 systemctl start network-orchestrator.service
 ip link add ne2e0 type dummy
 ip link set ne2e0 up
'
docker exec "$NAME" python3 /src/e2e/linux/cli_first_scenarios.py >"$OUT/scenarios.log" 2>&1 || {
    cat "$OUT/scenarios.log"
    exit 1
}
cat "$OUT/scenarios.log"
