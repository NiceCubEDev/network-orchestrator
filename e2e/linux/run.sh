#!/bin/sh
# Linux E2E harness (S2). Builds the daemon, boots disposable Ubuntu 26.04
# client/server containers on a private Docker network, installs the daemon
# as a package would and runs scenarios.sh in the client. Network mutations
# happen only in the containers' own namespaces.
#
# Requirements: docker or podman (CONTAINER_ENGINE). Needs CAP_SYS_ADMIN +
# apparmor=unconfined for systemd (cgroup remount) — dev machine / CI only.
# `label=disable` keeps bind-mounted sources readable on SELinux hosts
# without relabeling the repo; it is a no-op where SELinux is absent.
#
# Usage: e2e/linux/run.sh [--keep]   (--keep leaves the container running)
#        E2E_DISTRO=fedora e2e/linux/run.sh   (Fedora 44 client, Ubuntu peer)
#        CONTAINER_ENGINE=podman e2e/linux/run.sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE=${CONTAINER_ENGINE:-docker}
# The Python scenario drivers shell out to `docker`; when another engine is
# selected, the shim in e2e/linux/bin forwards those calls to it. With real
# docker the shim stays off PATH.
SYSTEMD_FLAG=""
CGROUP_NS="--cgroupns=private"
if [ "$ENGINE" != docker ]; then
    export PATH="$REPO_ROOT/e2e/linux/bin:$PATH"
    # Rootless podman mounts the container cgroup read-only unless it runs in
    # systemd mode, which also owns cgroup delegation — docker gets neither.
    SYSTEMD_FLAG="--systemd=always"
    CGROUP_NS=""
fi
SERVER_IMAGE=netorch-e2e-client
case "${E2E_DISTRO:-ubuntu}" in
    ubuntu) IMAGE=$SERVER_IMAGE; DOCKERFILE=Dockerfile ;;
    fedora) IMAGE=netorch-e2e-client-fedora; DOCKERFILE=Dockerfile.fedora ;;
    *) echo "unknown E2E_DISTRO: $E2E_DISTRO" >&2; exit 2 ;;
esac
NAME=netorch-e2e-$$
SERVER=netorch-e2e-server-$$
NETWORK=netorch-e2e-net-$$
KEEP=${1:-}

echo "==> Building daemon (release)"
(cd "$REPO_ROOT" && cargo build --release -p network-orchestrator-daemon)

echo "==> Building images $SERVER_IMAGE, $IMAGE"
"$ENGINE" build -q -t "$SERVER_IMAGE" "$REPO_ROOT/e2e/linux" >/dev/null
"$ENGINE" build -q -t "$IMAGE" -f "$REPO_ROOT/e2e/linux/$DOCKERFILE" "$REPO_ROOT/e2e/linux" >/dev/null

cleanup() {
    if [ "$KEEP" = "--keep" ]; then
        echo "containers kept: $ENGINE exec -it $NAME bash"
        echo "remove with: $ENGINE rm -f $NAME $SERVER; $ENGINE network rm $NETWORK"
    else
        "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
        "$ENGINE" rm -f "$SERVER" >/dev/null 2>&1 || true
        "$ENGINE" network rm "$NETWORK" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Starting isolated peer on $NETWORK"
IPV6_SUBNET=$(printf 'fd6e:6574:%x:%x::/64' "$(( $$ / 65536 ))" "$(( $$ % 65536 ))")
"$ENGINE" network create --ipv6 --subnet "$IPV6_SUBNET" "$NETWORK" >/dev/null

"$ENGINE" run -d --name "$SERVER" --network "$NETWORK" --network-alias wg-server \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --security-opt label=disable \
    -v "$REPO_ROOT/e2e/linux:/opt/netorch/e2e:ro" \
    --entrypoint python3 "$SERVER_IMAGE" \
    -m http.server 8765 --bind 0.0.0.0 --directory /opt/netorch/e2e >/dev/null

echo "==> Starting $NAME"
"$ENGINE" run -d --name "$NAME" --network "$NETWORK" -e container=docker \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW --security-opt apparmor=unconfined \
    --security-opt label=disable $SYSTEMD_FLAG \
    --device /dev/net/tun --tmpfs /run --tmpfs /run/lock $CGROUP_NS \
    -v "$REPO_ROOT/target/release/network-orchestrator-daemon:/opt/netorch/bin/network-orchestrator-daemon:ro" \
    -v "$REPO_ROOT/packaging/linux:/opt/netorch/packaging:ro" \
    -v "$REPO_ROOT/e2e/linux:/opt/netorch/e2e:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 60); do
    state=$("$ENGINE" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 0.5
done
echo "    systemd: $state"

echo "==> Installing daemon as a package would"
"$ENGINE" exec "$NAME" sh -eu -c '
    install -D -m 0755 /opt/netorch/bin/network-orchestrator-daemon \
        /usr/bin/network-orchestrator-daemon
    install -m 0644 /opt/netorch/packaging/network-orchestrator.service /usr/lib/systemd/system/
    install -m 0644 /opt/netorch/packaging/com.netmanager.app.policy /usr/share/polkit-1/actions/
    install -m 0644 /opt/netorch/packaging/tmpfiles.conf /usr/lib/tmpfiles.d/network-orchestrator.conf
    # The managed package root must exist before the service starts:
    # ReadWritePaths is ignored for paths that do not exist yet.
    systemd-tmpfiles --create network-orchestrator.conf
    systemctl daemon-reload
    systemctl enable --now network-orchestrator.service
'

echo "==> Running scenarios"
"$ENGINE" exec "$NAME" bash /opt/netorch/e2e/scenarios.sh

echo "==> Running WireGuard split scenarios"
python3 "$REPO_ROOT/e2e/linux/wg_scenarios.py" "$NAME" "$SERVER"

echo "==> Running OpenVPN split scenarios"
python3 "$REPO_ROOT/e2e/linux/ovpn_scenarios.py" "$NAME" "$SERVER"

echo "==> Running OpenVPN management auth scenarios"
python3 "$REPO_ROOT/e2e/linux/ovpn_auth_scenarios.py" "$NAME" "$SERVER"

echo "==> Running Xray proxy scenarios"
python3 "$REPO_ROOT/e2e/linux/xray_scenarios.py" "$NAME" "$SERVER"

echo "==> Running Xray TUN scenarios"
python3 "$REPO_ROOT/e2e/linux/xray_tun_scenarios.py" "$NAME" "$SERVER"

echo "==> Running always-on lifecycle scenarios"
"$ENGINE" exec "$NAME" bash /opt/netorch/e2e/always_on_scenarios.sh
