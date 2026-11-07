#!/bin/sh
# Packaged Tauri WebView -> daemon -> kernel route in one disposable Ubuntu container.
# Never run the Python scenario directly on the host: it mutates container routes.
# Usage: run_app_gui.sh [--blank-config] [path/to/package.deb|package.rpm]
# A .rpm runs in the Fedora 44 client image, a .deb in the Ubuntu one.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(python3 "$REPO_ROOT/scripts/versions.py" get linux)"
PKG="$REPO_ROOT/target/release/bundle/deb/Network Orchestrator_${VERSION}_amd64.deb"
BLANK_CONFIG=0
for arg in "$@"; do
    case "$arg" in
        --blank-config) BLANK_CONFIG=1 ;;
        *.deb|*.rpm) PKG="$arg" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done
NAME="netorch-app-gui-$$"
set --
case "$PKG" in
    *.rpm)
        IMAGE=netorch-e2e-client-fedora DOCKERFILE=Dockerfile.fedora PKG_EXT=rpm
        INSTALL='dnf -y -q --setopt=install_weak_deps=False --disablerepo=fedora-cisco-openh264 install xorg-x11-server-Xvfb xdotool scrot openbox dbus-x11 python3-websockets /opt/netorch/network-orchestrator.rpm'
        ;;
    *)
        IMAGE=netorch-e2e-client DOCKERFILE=Dockerfile PKG_EXT=deb
        DEB_VERSION="$(python3 -c 'import sys; print(sys.argv[1].replace("-", "~", 1))' "$VERSION")"
        DAEMON_PKG="$REPO_ROOT/target/release/packages/network-orchestrator-daemon_${DEB_VERSION}_amd64.deb"
        CLI_PKG="$REPO_ROOT/target/release/packages/netorch_${DEB_VERSION}_amd64.deb"
        for dependency in "$DAEMON_PKG" "$CLI_PKG"; do
            [ -f "$dependency" ] || { echo "missing package: $dependency" >&2; exit 1; }
        done
        set -- -v "$DAEMON_PKG:/opt/netorch/daemon.deb:ro" \
            -v "$CLI_PKG:/opt/netorch/netorch.deb:ro"
        INSTALL='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends xvfb xdotool scrot openbox dbus-x11 python3-websockets /opt/netorch/daemon.deb /opt/netorch/netorch.deb /opt/netorch/network-orchestrator.deb'
        ;;
esac

if [ ! -f "$PKG" ]; then
    echo "missing package: $PKG" >&2
    exit 1
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -q -t "$IMAGE" -f "$REPO_ROOT/e2e/linux/$DOCKERFILE" "$REPO_ROOT/e2e/linux" >/dev/null
fi

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$NAME" -e container=docker \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    --device /dev/net/tun --tmpfs /run --tmpfs /run/lock --cgroupns=private \
    -v "$PKG:/opt/netorch/network-orchestrator.$PKG_EXT:ro" \
    -v "$REPO_ROOT/e2e/linux:/opt/netorch/e2e:ro" \
    "$@" \
    "$IMAGE" >/dev/null

for _ in $(seq 60); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 0.5
done
case "$state" in running|degraded) ;; *) echo "container systemd failed: $state" >&2; exit 1 ;; esac

docker exec "$NAME" bash -euc "$INSTALL >/tmp/netorch-install.log"
docker exec "$NAME" bash -euc '
    systemctl is-active --quiet network-orchestrator.service
    install -m 0644 /opt/netorch/e2e/app_gui_polkit.rules \
        /etc/polkit-1/rules.d/49-netorch-e2e.rules
    systemctl restart polkit.service
    ip link add ne2e0 type dummy
    ip link set ne2e0 up
    systemctl start user@1001.service
    test -S /run/user/1001/bus
'

docker exec -d "$NAME" Xvfb :99 -screen 0 1280x800x24 -nolisten tcp
for _ in $(seq 30); do
    if docker exec "$NAME" test -S /tmp/.X11-unix/X99; then break; fi
    sleep 0.2
done
docker exec "$NAME" test -S /tmp/.X11-unix/X99

# The inspector and WebKit sandbox overrides exist only inside this container.
docker exec -d --user alice -e DISPLAY=:99 -e XDG_RUNTIME_DIR=/run/user/1001 \
    -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus \
    -e XDG_SESSION_TYPE=x11 -e GDK_BACKEND=x11 \
    -e WEBKIT_DISABLE_DMABUF_RENDERER=1 \
    -e WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 \
    -e WEBKIT_INSPECTOR_HTTP_SERVER=127.0.0.1:9222 \
    "$NAME" bash -c \
    'openbox & exec /usr/bin/net-manager-app >/tmp/netorch-app.log 2>&1'

ready=0
for _ in $(seq 60); do
    if docker exec "$NAME" sh -c \
        'curl -fsS http://127.0.0.1:9222/ 2>/dev/null | grep -q "Network Orchestrator"'; then
        ready=1
        break
    fi
    sleep 0.5
done
if [ "$ready" -ne 1 ]; then
    echo "packaged WebKit inspector did not start" >&2
    exit 1
fi

if [ "$BLANK_CONFIG" -eq 1 ]; then
    docker exec "$NAME" python3 /opt/netorch/e2e/app_gui_inspector.py --blank-config
else
    docker exec "$NAME" python3 /opt/netorch/e2e/app_gui_inspector.py
fi
