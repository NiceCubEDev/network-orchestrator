#!/usr/bin/env bash
# Build a local Arch package from the current source tree in a disposable container.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-}" in
    '') VERIFY_ONLY=0 ;;
    --verifysource) VERIFY_ONLY=1 ;;
    *) printf 'usage: %s [--verifysource]\n' "$0" >&2; exit 2 ;;
esac
PKGNAME=network-orchestrator
PKGVER="$(python3 "$REPO_ROOT/scripts/versions.py" get linux)"
PKGREL="$(python3 -c 'import pathlib,re,sys; print(re.search(r"(?m)^pkgrel=(\d+)$", pathlib.Path(sys.argv[1]).read_text()).group(1))' "$REPO_ROOT/packaging/arch/PKGBUILD")"
BUILD_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$BUILD_ROOT"' EXIT
mkdir -p "$BUILD_ROOT/build/$PKGNAME-$PKGVER" "$REPO_ROOT/target/arch"

tar -C "$REPO_ROOT" -cf - \
    Cargo.toml Cargo.lock LICENSE package.json package-lock.json index.html \
    tsconfig.json tsconfig.node.json vite.config.ts crates src src-tauri public packaging/linux \
    packaging/arch/xray-NOTICES \
    | tar -C "$BUILD_ROOT/build/$PKGNAME-$PKGVER" -xf -
tar -C "$BUILD_ROOT/build" -czf "$BUILD_ROOT/build/$PKGNAME-$PKGVER.tar.gz" \
    "$PKGNAME-$PKGVER"
cp "$REPO_ROOT/packaging/arch/PKGBUILD" \
    "$REPO_ROOT/packaging/arch/$PKGNAME.install" "$BUILD_ROOT/build/"

SOURCE_SHA256="$(sha256sum "$BUILD_ROOT/build/$PKGNAME-$PKGVER.tar.gz" | cut -d ' ' -f 1)"
python3 - "$BUILD_ROOT/build/PKGBUILD" "$PKGVER" "$SOURCE_SHA256" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text, count = re.subn(r'(?m)^pkgver=.*$', f'pkgver={sys.argv[2]}', text, count=1)
if count != 1 or text.count("sha256sums=('SKIP'") != 1:
    raise SystemExit('unexpected PKGBUILD template')
text = text.replace("sha256sums=('SKIP'", f"sha256sums=('{sys.argv[3]}'")
path.write_text(text)
PY

docker run --rm \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -e VERIFY_ONLY="$VERIFY_ONLY" \
    -v "$BUILD_ROOT/build:/build" -v "$REPO_ROOT/target/arch:/out" \
    -w /build archlinux:latest bash -euc '
        if [ "$VERIFY_ONLY" = 0 ]; then
            pacman -Syu --noconfirm --needed base-devel rust nodejs npm pkgconf openssl \
                libappindicator-gtk3 librsvg xdotool webkit2gtk-4.1 polkit iproute2
        fi
        groupadd -g "$HOST_GID" pkgbuild
        useradd -m -u "$HOST_UID" -g "$HOST_GID" pkgbuild
        su -s /bin/bash pkgbuild -c "cd /build && makepkg --verifysource"
        if [ "$VERIFY_ONLY" = 0 ]; then
            su -s /bin/bash pkgbuild -c "cd /build && PKGDEST=/out makepkg --force"
        fi
    '

if [ "$VERIFY_ONLY" = 0 ]; then
    python3 - "$REPO_ROOT/crates/core/src/managed_xray.rs" \
        "$REPO_ROOT/target/arch/$PKGNAME-$PKGVER-$PKGREL-x86_64.pkg.tar.zst" <<'PY'
import hashlib
import pathlib
import re
import subprocess
import sys

source = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r'pub const LINUX_REQUIRED_SHA256:.*?= \[(.*?)\];', source, re.S)
if not match:
    raise SystemExit('missing Linux Xray file hashes in core')
expected = dict(re.findall(r'\(\s*"([^"]+)",\s*"([0-9a-f]{64})",\s*\)', match.group(1)))
if set(expected) != {'xray', 'geoip.dat', 'geosite.dat'}:
    raise SystemExit('unexpected Linux Xray hash list in core')
for name, pinned_hash in expected.items():
    path = f'usr/lib/network-orchestrator/xray/v26.10.31/{name}'
    data = subprocess.check_output(['tar', '-I', 'zstd', '-xOf', sys.argv[2], path])
    if hashlib.sha256(data).hexdigest() != pinned_hash:
        raise SystemExit(f'package Xray file hash mismatch: {name}')
    print(f'verified package Xray hash: {name}')
PY
fi
