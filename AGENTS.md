# AGENTS

Guidance for agents/contributors working in this repository.

## Layout

- `crates/core` — pure Rust library: models, static analysis, profile diagnostics checks, config vault,
  DPAPI, policy routes, tunnel manager, route plan, connect plan (conflict
  checks, route/interface derivation), system proxy, explorer,
  backend executable settings, managed Xray verification. Also hosts the
  opt-in `windows_e2e` integration tests (see Safety rules).
- `crates/daemon` — Linux privileged system service: Unix socket protocol,
  polkit authorization, netlink mutations, ownership journal and recovery.
  Hard-learned netlink quirks live in `MEMORY.md`.
- `crates/engine` — typed connection engine (`Engine`): connect/disconnect/
  status/system proxy/Xray install and the requests to the privileged helper.
  macOS (aarch64) `Engine` is shared by the bridge and the `netorch` CLI
  (`docs/plans/2026-10-15-19-netorch-cli.md`). On Linux, `linux` holds pure
  daemon request builders and `linux_engine::LinuxEngine` serves both CLI and GUI.
  `linux_session` hosts their unprivileged `netorch serve` runtime: local Xray
  children and detached daemon client lifetime. No UI, no FFI.
- `crates/cli` — the `netorch` command line tool. macOS: clap commands over
  `crates/engine` and the bridge's profile/import/routing services; ships in
  the app bundle next to the helper. Linux (`src/linux/`): a client of the
  network daemon built on `LinuxEngine` and the import/subscription code of
  `crates/core`, no GUI needed. `serve` is started on demand as one systemd user
  unit per data directory/daemon socket; no per-profile keepers. The user runtime
  must stay unprivileged; routes/interfaces/DNS remain system-daemon-only.
- `crates/macos-bridge` — unprivileged JSON C ABI staticlib the Swift client
  links; every macOS core operation goes through it. A thin JSON wrapper over
  `crates/engine` for runtime operations.
- `crates/macos-helper` — privileged launchd helper daemon for root macOS
  network mutations; design in
  `docs/plans/2026-09-30-14-macos-privileged-helper.md`.
- `macos/` — native SwiftUI/AppKit client for macOS 27 (no WebView); Swift
  tests in `macos/Tests/NativeTests`, capabilities and test isolation in
  `macos/README.md`. Links the bridge from `target/macos-bridge`, which
  `scripts/stage-macos-bridge.sh <profile>` fills.
- `src-tauri` — Tauri 2 shell for Windows/Linux: commands in
  `src-tauri/src/commands/`, `state.rs` (AppState + runtime mutex),
  `lifecycle.rs` (shutdown cleanup), `test_support.rs` fixtures.
- `src` — React/TypeScript frontend (Tauri client + browser sandbox);
  `src/types.ts` mirrors the Rust models (camelCase).
- `tests/` — frontend Node unit tests (`npm run test`).
- `e2e/linux` — disposable Docker test harness for the Linux daemon.
- `packaging/` — deb/rpm/Arch package scripts used by the build scripts.
- `docs/plans` — per-stage implementation plans; `docs/testing.md` — browser
  sandbox, Linux Docker and Windows VM E2E contracts;
  `docs/platform-matrix.md` — per-OS feature matrix (keep in sync with
  `PlatformCapabilities` in `src-tauri/src/commands/system.rs`).

## Setup

```bash
npm install
cargo fetch
rustup component add clippy rustfmt
```

Windows + MSVC + WebView2 are required for Windows tunnel functionality.
On Linux, the daemon requires systemd and polkit for network mutations;
WireGuard also needs `wireguard-tools`, OpenVPN needs `openvpn`, and DNS needs
`systemd-resolved`.
The native macOS client requires macOS 27, Xcode 27 and Python 3; the build
script aborts without SDK 27.

## Quality gate (run before reporting done)

```bash
python3 scripts/versions.py check
python3 -m unittest scripts/test_versions.py
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build
```

On Linux, append `--exclude net-manager-macos-bridge --exclude
network-orchestrator-macos-helper` to the workspace check/clippy/test commands:
those crates use native macOS APIs and must be checked on macOS instead.

CI (`.github/workflows/ci.yml`) is manual-only (`workflow_dispatch`) and
mirrors this gate on Windows.

## Commands

- `cargo test -p net-manager-core <filter>` / `-p net-manager-app <filter>` —
  focused Rust tests; `swift test --package-path macos --scratch-path
  target/macos-swift --filter <name>` — focused Swift tests.
- `cargo run -p net-manager-cli -- <args>` — the `netorch` CLI against the
  default data dir; add `NETORCH_MACOS_DATA_DIR=<dir>` for an isolated one.
- `npm run test` — frontend Node unit tests (format, i18n, sandbox,
  subscriptions, intent doctor).
- `npm run dev:sandbox` — browser-only frontend on :1422 with an in-memory
  synthetic backend (no VPN, no native calls); contract in `docs/testing.md`.
- **Production binary:** never install a `cargo build --release` artifact as
  the prod app. Without the `tauri/custom-protocol` feature the release binary
  compiles with `cfg(dev)` and loads `devUrl` (`http://127.0.0.1:1420`) — the
  window then shows "Could not connect to 127.0.0.1". Build via
  `npm run tauri build` / `scripts/build-linux-deb.sh` (the CLI injects the
  feature), or pass `--features tauri/custom-protocol` to cargo explicitly.
- `scripts/macos-dev.sh build|run|test|preview|check|du|clean` — native
  macOS loop: `release-fast` bridge (no LTO, incremental) + Swift debug,
  isolated QA data for `run` (`NETORCH_MACOS_DATA_DIR`), offscreen renders
  for `preview`; `check` covers only core + macos-bridge, not the workspace.
  `npm run build:macos` builds the distributable release bundle (LTO +
  Swift release, ad-hoc signed).
- `npm run dev:app` — Linux dev run against the dev daemon
  (`network-orchestrator-dev.service`, socket `/run/network-orchestrator-dev/`,
  data dir `~/.local/share/com.netmanager.app.dev/`, "(Dev)" window title);
  `npm run tauri dev` keeps the production identity; on Windows,
  `npm run tauri build -- --bundles nsis` builds unsigned NSIS under
  `target/release/bundle/nsis/`; on Linux use `scripts/build-linux-deb.sh`
  (`.deb`), `scripts/build-linux-deb.sh rpm` (Fedora `.rpm`) or
  `scripts/build-linux-arch.sh`.
- `npm audit --audit-level=high` — dependency audit.
- `e2e/linux/run.sh` (`E2E_DISTRO=fedora` for a Fedora 44 client) — Linux
  daemon/tunnel E2E in disposable Docker containers;
  requires Docker, `/dev/net/tun`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and
  unconfined AppArmor for containerized systemd.

## Safety rules

- **Never** run `cargo test -- --ignored` or
  `cargo test --test windows_e2e -- --ignored` outside a disposable Windows
  VM — those tests mutate real routes/interfaces and spawn real VPN
  processes. They require the env contract in `docs/testing.md`.
- No VPN/UAC/registry/network mutations in ordinary tests — use fake
  adapters, temp dirs, and in-memory fixtures.
- Run Linux netlink/systemd E2E only inside the disposable `e2e/linux`
  container. Never run its scenario script directly on the host.
- Never log or return config contents, VLESS URIs, private keys, UUIDs, or
  passwords; use existing redaction helpers and keep paths out of errors
  where they may contain user secrets.
- Managed configs must be written only through `ConfigVault` (ACL +
  revisioning); generated Xray plaintext must go through
  `store_generated_xray` (DPAPI on Windows).
- Managed backend downloads must stay fixed-version, hash-pinned, bounded,
  allowlisted, and atomic; tests use synthetic archives and never hit the
  network or install into real app data.
- `netorch` (`crates/cli`) is an unprivileged client of the helper like the
  app. Its `sudo netorch up` mode runs the helper's own executors in-process
  (same rules: Xray only as the console user, the pinned OpenVPN, no script
  hooks) and refuses when the helper is running; as root it must never write
  into the user's data directory (root-owned files would lock the app out),
  execute a binary from a user-writable directory, or run local Xray.
  Loopback Xray runs only in a foreground `netorch up` holding the data
  directory's `.instance.lock`, which the app takes too.
- `crates/macos-bridge` stays unprivileged: never add `daemon_protocol`
  methods or network mutations to it. macOS mutations go through a launchd
  helper speaking `daemon_protocol` over a Unix socket
  (`docs/plans/2026-09-30-14-macos-privileged-helper.md`). The only
  exceptions are user-level: the managed Xray child listening on loopback and
  the per-user system proxy via `networksetup` (snapshot + rollback through
  `SystemProxyManager`), and an explicit user toggle of another app's VPN
  service via `scutil --nc start|stop <UUID>`, and driving the user's own
  NetBird daemon through its CLI (`netbird status|up|down`, no keys on the
  command line). Routes, interfaces and DNS stay helper-only. The helper itself launches Xray TUN only as the console
  user (groups, gid and uid dropped irreversibly before exec), only from the
  user's hash-verified managed install, and never as root; tests use fake
  platforms/runners and must not create a utun or touch routes or DNS. The
  helper runs OpenVPN as root only from the pinned, self-contained copy of the
  bundled binary (SHA-256 compiled into the helper, no script hooks, config
  through `sanitize_openvpn_config`), and runs WireGuard in-process; tests use
  fake platforms and a fake management server, never a real tunnel.
- Do not commit unless explicitly asked; do not push to `main`/`master`.

## Conventions

- Rust: serde `camelCase` models in `crates/core/src/models.rs`; errors as
  `io::Result` in core, `Result<_, String>` in commands; TDD — tests first,
  report RED/GREEN.
- Frontend: components subscribe to `route-changed` window events for
  refresh; types stay in `src/types.ts`.
- i18n: both clients share `locales/*.json` — canonical keys are English
  source text used as the key (`tr("Connecting {name}")` in TSX,
  `L10n.text("Add a connection")` in Swift); `t("dotted.key")` is the legacy
  compat path still used across the web UI. Never delete an English-text key
  that only appears in Swift sources; add new messages to `en.json` first.
- Versions are per release line (`core`, `macos`, `linux`, `windows`), not one
  for the app: `versions.toml` is the only source of truth, and
  `python3 scripts/versions.py set <line> X.Y.Z` / `sync` write it into the
  crates and `src-tauri/tauri.<linux|windows>.conf.json`. Never edit a crate or
  Tauri version by hand; `crates/cli` and `src-tauri` say `0.0.0` and take the
  version of the target OS from `versions.toml` at build time
  (`NETORCH_VERSION`).
- Versioning, commit messages and releases follow `docs/versioning.md`
  (SemVer per line, Conventional Commits in English, `changelog/<line>.md`;
  `CHANGELOG.md` is the history up to 0.10.0); read it before committing or
  bumping a version. Every commit needs a `type(scope):`
  prefix, one type per commit (never mix `feat` and `fix`), breaking changes
  carry `!` or a `BREAKING CHANGE:` footer. Bump a line's version in a separate
  `chore(release): <line> X.Y.Z` commit after each group of changes.
- Store files are versioned documents written atomically (temp + rename)
  and ACL-protected via `config_security::protect_path`.

## Design system

- All colors come from the OKLCH design tokens in `design/tokens.json`
  (neutral surfaces, indigo accent, `--up/--down/--warn/--info` semantics,
  `--cat-*` categorical scale, dark + light themes). Edit `tokens.json` and
  run `python3 scripts/generate-ui-theme.py` — do not edit the generated
  outputs (`src/theme.generated.css`, `src/palette.ts`,
  `macos/Sources/NetworkOrchestrator/Theme.generated.swift`). No hardcoded
  hex/`rgba()` colors in CSS or TSX — JS-rendered visuals import from
  `src/palette.ts`.
- User-facing copy lives in `locales/*.json`; run `npm run i18n:generate`
  (or `python3 scripts/generate-localizations.py`) instead of editing
  `src/i18n/catalog.generated.ts` or the macOS `Localizations.json`.
- Editing `src/icons.tsx` (24×24 stroke-based) changes the hash that
  `generate-ui-theme.py --check` validates against the checked-in native PDF
  icons; regenerate with `python3 scripts/generate-native-icons.py`
  (needs ReportLab) or the build fails. No Unicode glyphs as UI icons; `…`
  is allowed only in placeholders/loading labels.
- One primary CTA per screen: `btn-primary`. Default `<button>` is the
  secondary style; `btn-danger`, `btn-ghost`, `btn-sm`, `btn-with-icon` are
  the other sanctioned variants.
- Right-align numeric table cells with `.num`; use `formatBytes`/`formatRate`
  from `src/format.ts` and `<RateText>` for rx/tx readouts.
- Transient feedback uses `useToast()` (`ToastProvider` wraps the app in
  `src/App.tsx`); persistent banners keep `.runtime-notice`/`.save-notice`.
