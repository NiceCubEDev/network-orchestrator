#!/bin/sh
# Builds the two .deb packages that do not come from Tauri, from binaries that
# are already built:
#
#   network-orchestrator-daemon  the daemon, its systemd unit, the polkit policy
#                                and the pinned Xray
#   netorch                      the command line client; depends on the daemon
#
# The app (network-orchestrator) is built by Tauri and depends on the daemon
# too; see scripts/build-linux-deb.sh. All three carry the Linux line's version
# (versions.toml) and depend on the daemon of the same major.minor or newer, so
# installing any one of them keeps a suitable daemon and installs or upgrades
# an unsuitable one when the package manager can get it.
#
# Environment (defaults in brackets):
#   DAEMON_BIN [target/release/network-orchestrator-daemon]
#   CLI_BIN    [target/release/netorch]
#   XRAY_DIR   [target/release/xray-package/v26.10.31]
#   OUT_DIR    [target/release/packages]
#   INSTALLER_OUT_DIR [target/release/installers]
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
umask 022

DAEMON_BIN="${DAEMON_BIN:-target/release/network-orchestrator-daemon}"
CLI_BIN="${CLI_BIN:-target/release/netorch}"
XRAY_DIR="${XRAY_DIR:-target/release/xray-package/v26.10.31}"
OUT_DIR="${OUT_DIR:-target/release/packages}"
XRAY_VERSION=v26.10.31

SEMVER="$(python3 scripts/versions.py get linux)"
# 0.10.0-beta.1 sorts before 0.10.0 in SemVer; Debian spells that with a tilde.
DEB_VERSION="$(printf '%s' "$SEMVER" | sed 's/-/~/')"
LINE="$(printf '%s' "$SEMVER" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')"
ARCH="$(dpkg --print-architecture)"
MAINTAINER="Network Orchestrator <noreply@users.noreply.github.com>"

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

control() { # name, depends, recommends, extra-lines, description
    root="$WORK/$1"
    size="$(du -sk "$root" | cut -f1)"
    mkdir -p "$root/DEBIAN"
    {
        printf 'Package: %s\n' "$1"
        printf 'Version: %s\n' "$DEB_VERSION"
        printf 'Architecture: %s\n' "$ARCH"
        printf 'Maintainer: %s\n' "$MAINTAINER"
        printf 'Installed-Size: %s\n' "$size"
        printf 'Section: net\nPriority: optional\n'
        printf 'Depends: %s\n' "$2"
        [ -z "$3" ] || printf 'Recommends: %s\n' "$3"
        [ -z "$4" ] || printf '%s\n' "$4"
        printf 'Description: %s\n' "$5"
    } >"$root/DEBIAN/control"
    (cd "$root" && find . -path ./DEBIAN -prune -o -type f -print | sed 's|^\./||' |
        sort | xargs md5sum >DEBIAN/md5sums)
}

# ---- daemon ---------------------------------------------------------------
D="$WORK/network-orchestrator-daemon"
install -Dm0755 "$DAEMON_BIN" "$D/usr/bin/network-orchestrator-daemon"
install -Dm0644 packaging/linux/network-orchestrator.service \
    "$D/usr/lib/systemd/system/network-orchestrator.service"
install -Dm0644 packaging/linux/tmpfiles.conf \
    "$D/usr/lib/tmpfiles.d/network-orchestrator.conf"
install -Dm0644 packaging/linux/com.netmanager.app.policy \
    "$D/usr/share/polkit-1/actions/com.netmanager.app.policy"
install -Dm0755 "$XRAY_DIR/xray" "$D/usr/lib/network-orchestrator/xray/$XRAY_VERSION/xray"
for name in geoip.dat geosite.dat; do
    install -Dm0644 "$XRAY_DIR/$name" "$D/usr/lib/network-orchestrator/xray/$XRAY_VERSION/$name"
done
install -Dm0644 "$XRAY_DIR/LICENSE" "$D/usr/share/doc/network-orchestrator-daemon/xray/LICENSE"
install -Dm0644 "$XRAY_DIR/README.md" "$D/usr/share/doc/network-orchestrator-daemon/xray/README.md"
install -Dm0644 packaging/linux/xray-NOTICES \
    "$D/usr/share/doc/network-orchestrator-daemon/xray/NOTICES"
install -Dm0644 LICENSE "$D/usr/share/doc/network-orchestrator-daemon/copyright"
control network-orchestrator-daemon "systemd, polkitd, iproute2, nftables" \
    "systemd-resolved, wireguard-tools, openvpn" \
    "Replaces: network-orchestrator (<< 0.10.1)
Breaks: network-orchestrator (<< 0.10.1)" \
    "Network Orchestrator privileged network daemon
 Applies routes, interfaces, DNS and VPN tunnels on behalf of the Network
 Orchestrator app and the netorch command line client, after polkit
 authorization. Ships the pinned Xray the daemon runs."
install -m0755 packaging/linux/postinst "$D/DEBIAN/postinst"
install -m0755 packaging/linux/prerm "$D/DEBIAN/prerm"
install -m0755 packaging/linux/postrm "$D/DEBIAN/postrm"
dpkg-deb --root-owner-group --build "$D" \
    "$OUT_DIR/network-orchestrator-daemon_${DEB_VERSION}_${ARCH}.deb" >/dev/null

# ---- netorch --------------------------------------------------------------
C="$WORK/netorch"
install -Dm0755 "$CLI_BIN" "$C/usr/bin/netorch"
mkdir -p "$C/usr/share/bash-completion/completions" "$C/usr/share/zsh/vendor-completions" \
    "$C/usr/share/fish/vendor_completions.d"
"$CLI_BIN" completions bash >"$C/usr/share/bash-completion/completions/netorch"
"$CLI_BIN" completions zsh >"$C/usr/share/zsh/vendor-completions/_netorch"
"$CLI_BIN" completions fish >"$C/usr/share/fish/vendor_completions.d/netorch.fish"
chmod 0644 "$C"/usr/share/*/completions/netorch "$C/usr/share/zsh/vendor-completions/_netorch" \
    "$C/usr/share/fish/vendor_completions.d/netorch.fish" 2>/dev/null || true
install -Dm0644 LICENSE "$C/usr/share/doc/netorch/copyright"
control netorch "network-orchestrator-daemon (>= ${LINE}.0), libdbus-1-3" "" \
    "Breaks: network-orchestrator (<< ${LINE}.0)" \
    "Network Orchestrator command line client
 Connects the VPN profiles of Network Orchestrator (WireGuard, OpenVPN and
 Xray) from a terminal or a script, without the graphical app. It talks to the
 network daemon, which is installed as a dependency."
dpkg-deb --root-owner-group --build "$C" "$OUT_DIR/netorch_${DEB_VERSION}_${ARCH}.deb" >/dev/null

python3 scripts/package-linux-installers.py \
    --daemon "$OUT_DIR/network-orchestrator-daemon_${DEB_VERSION}_${ARCH}.deb" \
    --cli "$OUT_DIR/netorch_${DEB_VERSION}_${ARCH}.deb" \
    --output-dir "${INSTALLER_OUT_DIR:-target/release/installers}"

ls -l "$OUT_DIR"/*.deb
