#!/bin/bash
# Native macOS client developer loop. Keeps builds incremental and disk usage
# bounded; see macos/README.md.
#
#   macos-dev.sh build          fast dev bundle (release-fast bridge, Swift debug)
#   macos-dev.sh run [--real]   build, then run in the foreground with logs on the
#                               terminal; isolated QA data unless --real
#   macos-dev.sh test           bridge + core Rust tests, then Swift tests
#   macos-dev.sh preview [dir] render every screen offscreen (en/ru, light/dark)
#                               with synthetic data; default target/macos/preview
#   macos-dev.sh check          fmt + clippy for the crates the native client uses
#   macos-dev.sh du             show what occupies target/
#   macos-dev.sh clean [--all]  drop incremental caches and stale outputs;
#                               --all also removes every build output (cargo clean)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_BIN="$REPO_ROOT/target/macos/Network Orchestrator.app/Contents/MacOS/NetworkOrchestrator"
QA_DATA="$REPO_ROOT/target/macos-qa-data"
CRATES=(-p net-manager-core -p net-manager-engine -p net-manager-macos-bridge -p net-manager-cli)
cd "$REPO_ROOT"

case "${1:-}" in
build)
    bash scripts/build-macos-native.sh --dev
    ;;
run)
    bash scripts/build-macos-native.sh --dev >/dev/null
    pkill -x NetworkOrchestrator 2>/dev/null || true
    if [[ "${2:-}" == --real ]]; then
        exec "$APP_BIN"
    fi
    mkdir -p "$QA_DATA"
    NETORCH_MACOS_DATA_DIR="$QA_DATA" exec "$APP_BIN"
    ;;
test)
    cargo test "${CRATES[@]}"
    bash scripts/stage-macos-bridge.sh release-fast
    swift test --package-path macos --scratch-path target/macos-swift
    ;;
preview)
    OUT="${2:-$REPO_ROOT/target/macos/preview}"
    rm -rf "$OUT"
    bash scripts/stage-macos-bridge.sh release-fast
    NETORCH_DESIGN_PREVIEWS="$OUT" swift test --package-path macos \
        --scratch-path target/macos-swift --filter renderBothThemesAndAllPages
    echo "$OUT"
    ;;
check)
    cargo fmt --all -- --check
    cargo clippy "${CRATES[@]}" --all-targets -- -D warnings
    python3 scripts/generate-ui-theme.py --check
    python3 scripts/generate-localizations.py --check
    ;;
du)
    du -sh target 2>/dev/null || true
    du -sh target/* 2>/dev/null | sort -h
    ;;
clean)
    rm -rf target/debug/incremental target/release-fast/incremental \
        target/qa-linux target/x86_64-unknown-linux-gnu macos/.build
    # Cargo keeps every superseded artifact; this drops stale test binaries.
    find target/debug/deps -type f -mtime +7 -delete 2>/dev/null || true
    if [[ "${2:-}" == --all ]]; then
        cargo clean
        rm -rf target/macos-swift
    fi
    du -sh target 2>/dev/null || true
    ;;
*)
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
