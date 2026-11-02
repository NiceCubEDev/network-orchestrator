# Network Orchestrator

A desktop app for WireGuard, OpenVPN, Xray/VLESS, policy routes, and
network exploration. Windows and Linux use Tauri 2; macOS 27 has a native
SwiftUI/AppKit client linked directly to the Rust core, without a WebView.
The macOS client supports managed configuration imports, profile editing,
static analysis, interface inventory and routing-table inspection. macOS VPN
activation and network mutations require a separate provider implementation
and are disabled in this first native stage. Tunnel management works on Windows.
On Linux, the
privileged daemon, WireGuard and OpenVPN split/full tunnels with per-link DNS,
Xray VLESS/Hysteria2 SOCKS5/HTTP proxy and Xray TUN have passed container E2E
on Ubuntu 26.04 and Fedora 44 clients. Packages: `.deb` (Ubuntu/Debian),
`.rpm` (Fedora) and an Arch `PKGBUILD`. Desktop acceptance on a real install
is still pending.

## Development status

The project is in pre-release stabilization. MVP-0–4 functionality is implemented. Linux container E2E and package install/remove smoke testing have passed; disposable-VM desktop acceptance and code signing remain open.

Local development and release builds are supported and do not require CI/CD. GitHub Actions workflows exist in the repository, but CI/CD is intentionally deferred as a release gate until the application is stable.

The repository, Tauri package, window and app UI use **Network Orchestrator**.

## Quick Start

### macOS 27 native client

Requires macOS 27, Xcode 27 (including Command Line Tools), Rust and Python 3.
On Apple Silicon:

```bash
npm run build:macos
open "target/macos/Network Orchestrator.app"
```

The script builds a release `.app` with a local ad-hoc signature and a minimum
OS version of 27.0. App version comes from the root Cargo workspace. Developer
ID signing and notarization for distribution remain separate release steps.
No Node runtime, React or WebKit is included in the native app. npm only invokes
the build script; `bash scripts/build-macos-native.sh` works without npm.

Native data lives under `~/Library/Application Support/com.netmanager.app.macos`.
The native client currently uses a separate store from Tauri. See
[`macos/README.md`](macos/README.md) for supported functions and test isolation.

### Windows / Linux Tauri client

```bash
npm install
npm run tauri dev
```

On Windows, WireGuard (`wireguard.exe`) and OpenVPN (`openvpn.exe`) must be
installed separately or selected as existing executables; Xray may likewise be
selected, or explicitly installed as a verified app-managed version from the
Backend prerequisites section. On Linux, WireGuard and OpenVPN require the
daemon plus `wireguard-tools` or `openvpn`; per-link DNS needs
`systemd-resolved`.
No backend is silently downloaded or updated; the Profiles tab shows which
backends were found.

### Linux Xray subscriptions: backups and pinned nodes

One Xray TUN can use a primary subscription server, an ordered chain of
backups, and independent nodes for domain rules. In Profiles, use the
endpoint-row controls to add/reorder backups and the **Pinned to a node**
section to assign domain selectors. These settings are shared with `netorch`:

```bash
netorch endpoints work
netorch backup set work "Germany" "Finland"
netorch backup show work
netorch route pin work --via "Netherlands" --selector domain:example.com
netorch route show work
netorch up work
netorch status work
```

Servers may be selected by number, name, or a unique name fragment.
`backup add|rm|clear` edits the chain; `route unpin` removes a pin.
Settings saved while connected take effect on reconnect.

The daemon probes each candidate through that node using HTTPS
(`https://connectivitycheck.gstatic.com/generate_204` by default).
It prefers the primary, tries backups in their saved order, and automatically
returns when the primary recovers. `backup auto work off` keeps a healthy
backup instead. Probes contact an external service and reveal the node's
exit IP to it. Two consecutive failed/successful observations change a known
node's health; checks are bounded but switching is not instantaneous.
Existing connections may break when an exit changes.

Pinned traffic never falls back to another node or direct. A missing pinned
server stays configured and blocks its selectors; missing backup servers
are retained but skipped. If all default-path candidates fail, that traffic
is blocked; explicit direct rules still remain direct. This is not an
OS-level kill switch when the whole tunnel is stopped.

#### Filtered backup pools and exit-country checks

Pools are opt-in and come after explicit backups in the eight-node default
chain. Primary, manual backups, domain pins and the fixed DNS node are never
automatically recruited into a pool.

```bash
netorch backup pool set work 'CA:Canada|Канада' 'FI:'
netorch backup pool rebuild work
netorch backup pool show work
netorch backup verify work
netorch backup pool clear work
```

`CC:words` matches any supplied name term and requires the measured country;
`CC:` accepts any name with that measured exit country. A flag or country in a
server name is only a hint, not verification. Name-only selection is explicit:
`netorch backup pool set work --no-verify 'Canada|Канада'`.
It does not require Xray or make country requests.

Verified rebuilds and `backup verify` run temporary unprivileged loopback Xray
processes and contact `api.country.is` / `ipinfo.io` through each candidate.
Those services see its exit IP; no host routes are changed. Rebuilds bound
candidate count, concurrency, response size and duration. Enabled pools also
rebuild after subscription refresh. An outage retains eligible previous
members, but a positively wrong country or a newly explicit choice removes a
member. Clearing the pool leaves manual backups and pins unchanged.

#### Importing an existing Xray policy

```bash
netorch migrate preview work --from "$HOME/vpn/config.json"
netorch migrate apply work --from "$HOME/vpn/config.json"
netorch route quic work on
```

The app exposes the same operations under **Backup pool** and **Import local
Xray policy**. Disconnect before applying. Import reads the source without
changing it; previews show counts, supported settings and refusal categories,
not configuration contents or credentials.

The importer maps nodes against the subscription and preserves the selected
primary. It transfers representable domain/IP rules, fixed domain and DNS
egress, DNS rewriting/scheduling, IP/port guards, interface-bound policies,
connection idle and socket settings, TUN MTU/DNS and custom geodata URLs.
A source default balancer becomes an ordered explicit backup chain rather than
least-ping load balancing. Existing pins are retained; conflicting pins and
unrepresentable conditions block the entire apply. Dedicated
`proxy-ru` / `proxy-nl` / `direct` wrapper listeners are not imported.

Linux's pinned Xray is **26.10.31**, including DNS rewrite support. Its bundled
GeoIP Lite / GeoSite Standard data differs from older full country databases;
custom imported geodata URLs remain explicit overrides.
Use TLS or Reality for public VLESS endpoints; unencrypted VLESS test peers
must use private addresses with this backend.

#### Recovery and QUIC

The daemon observes the physical gateway, device and selected source. An
unchanged DHCP renewal does not reset established connections; a real underlay
change rebinds owned endpoint bypasses and restarts only its managed child.
Offline recovery waits for the uplink. Bounded HTTPS/DNS probes, fixed-pin
health, owned-child UDP socket counts and inner application connection storms
are visible in the profile and CLI status. DNS-only failures and connection
storms are diagnostic, not reasons to reset a healthy HTTPS path.

`route quic … on` installs an owned, tunnel-scoped UDP/443 **REJECT** using
`nftables`, so clients can immediately fall back to TCP. `off` removes that rule;
it does not install a silent drop. Disconnect removes only the daemon's table.



## Features (MVP-0–4)

- **Network Explorer** — interface inventory (addresses, DNS, MTU, state),
  route table, Linux kernel route lookup that accounts for policy rules,
  and auto-refresh on OS route changes.
- **Profiles** — versioned profiles for WireGuard (`.conf`), OpenVPN
  (`.ovpn`), and Xray/VLESS (`vless://` import generates a managed config with
  a local SOCKS5 listener; existing Xray JSON can be imported as-is).
- **Managed config vault** — imported/generated configs live in
  `app_data/configs/<profile>/rev-N/` with explicit Windows DACLs
  (current user + SYSTEM + Administrators, protected). Generated Xray configs
  are additionally encrypted with DPAPI (`config.json.dpapi`) and decrypted
  only in memory.
- **Connect/disconnect** — WireGuard via `wireguard.exe /installtunnelservice`,
  OpenVPN and Xray as contained child processes under a Windows Job Object.
  Xray SOCKS ports are auto-allocated from 10808–10999 on conflict.
- **Policy routes** — per-profile CIDR routes applied transactionally through
  the Windows IP Helper API or Linux daemon, persisted for crash recovery and
  rolled back on failure.
  The profile form accepts bulk IPv4/IPv6 CIDR paste or text files and
  aggregates duplicate or adjacent networks before adding routes.
- **Route map** — predicted routes from static config analysis vs. the
  effective OS route table; missing/mismatched-interface/exact-competition
  diffs, prefix tree, LPM + metric winner resolution.
- **Diagnostics** — per-profile checks: configuration, backend executable,
  tunnel status, protocol health (WireGuard `wg.exe show` dump, OpenVPN log
  markers, Xray process state), redacted bounded log tails, endpoints and
  listeners.
- **Backend management** — persistent custom executable paths for
  WireGuard, OpenVPN, and Xray; explicit managed Xray v26.7.28
  install/remove from the Backend prerequisites section with progress and
  cancellation. The managed archive is pinned (SHA-256
  `c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1`, plus
  required-file hashes), installed under the app data directory, and
  integrity-checked before use; the fixed official release URL is shown in
  the install confirmation and there is no automatic update.
- **Recovery** — on startup the app detects leftover WireGuard services,
  owned routes, and stale system-proxy ownership, and offers explicit
  cleanup. Graceful close restores proxy settings and removes owned routes
  before stopping tunnels.
- **Optional system proxy** — Xray profiles with a configured local SOCKS5
  port can set the Windows
  per-user proxy (`socks=127.0.0.1:<port>`) with a bypass list; previous
  settings are snapshotted, verified, and restored on disconnect/shutdown.
- **Elevation** — interface changes, WireGuard/OpenVPN, and policy routes
  require administrator; the app can restart itself elevated. The system
  proxy uses HKCU and needs no elevation.

## Documentation

- `docs/security.md` — threat model, vault ACL/DPAPI, redaction, trust.
- `docs/recovery.md` — crash recovery, Job Object, ownership model.
- `docs/testing.md` — Linux container and opt-in Windows VM E2E instructions.
- `docs/versioning.md` — SemVer, commit message and release rules.
- `CHANGELOG.md` — changes by version.
- `docs/plans/` — stage-by-stage implementation plans.
- `AGENTS.md` — contributor/agent commands and safety rules.

### Linux development

On Ubuntu or Fedora, install the daemon and its polkit policy before testing
route or interface changes:

```bash
scripts/install-linux-daemon-dev.sh
systemctl status network-orchestrator-dev.service
npm run dev:app
```

The script builds the daemon, installs it under `/usr/local/bin/`, and starts
the service. It requires `sudo`; `--uninstall` stops the service and removes
the development installation and its state. Route changes require polkit
authorization. The daemon's Unix socket is
`/run/network-orchestrator-dev/daemon.sock`; `npm run dev:app` points the dev
build at it through `NETWORK_ORCHESTRATOR_SOCKET` and a separate Tauri
identifier, so a packaged install is never touched.

The Linux E2E test runs in disposable Docker containers on a private network,
each with its own network namespace. The client is Ubuntu 26.04 by default or
Fedora 44 (firewalld and resolved enabled); the peer is Ubuntu:

```bash
e2e/linux/run.sh
E2E_DISTRO=fedora e2e/linux/run.sh
```

It needs Docker, `/dev/net/tun`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and an
unconfined AppArmor profile for systemd in the container. Do not run these
network scenarios on the host.

Build local Linux packages without installing them on the host:

```bash
scripts/build-linux-deb.sh
scripts/build-linux-deb.sh cli  # CLI installer only; no GUI/WebKit build
scripts/build-linux-deb.sh rpm
scripts/build-linux-arch.sh
```

For Debian/Ubuntu, distribute the single-file installers under
`target/release/installers/`: `netorch-<version>-amd64.run` for the CLI and
`network-orchestrator-<version>-amd64.run` for the GUI. Each contains its client
and the shared daemon; users do not download a daemon package separately.

```bash
sh ./netorch-0.10.1-amd64.run --check  # preview installed versions and planned actions
sudo sh ./netorch-0.10.1-amd64.run    # install CLI or update an older installation
# Later, add the GUI using the same daemon:
sudo sh ./network-orchestrator-0.10.1-amd64.run
```

Run the installer from a newer release to update. It compares installed Debian
package versions, skips equal versions, updates older packages and refuses client
downgrades. A newer daemon patch from the same release line is preserved; a daemon
from a newer release line requires a newer client installer. Updating the daemon
restarts its service and can interrupt connections. Adding another client with an
up-to-date daemon does not restart it. `--yes` accepts the APT plan without prompting.
The client and daemon are bundled; missing distribution dependencies may need
internet access and current APT indexes. No application repository is required.
When migrating from the former combined GUI package (0.10.0 or earlier), run the
new GUI installer first to transfer the daemon files, then add the CLI.

The CLI and daemon `.deb` files remain under `target/release/packages/`, the GUI
`.deb` and `.rpm` under `target/release/bundle/{deb,rpm}/`, and the Arch package
under `target/arch/`. RPM and Arch still use their existing packaging. The Arch
build uses a disposable Docker container.

## Development

### Prerequisites

- Windows 10/11, [Rust](https://rustup.rs/) (MSVC toolchain),
  [Node.js](https://nodejs.org/), Visual Studio C++ build tools, WebView2.
- Backend executables are needed only for the profiles you actually use.
  WireGuard (`wireguard.exe`/`wg.exe`) and OpenVPN (`openvpn.exe`) external
  packages remain required because their drivers/services are not managed by
  the app; an external Xray (`xray.exe`) install is optional because a
  verified managed install exists.

### Quality gates

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build
```

### Local Windows installer

No CI/CD service is required:

```bash
npm ci
npm run tauri build -- --bundles nsis
```

Produces an unsigned release-mode NSIS installer under `target/release/bundle/nsis/`.

## Limitations

- Linux WireGuard, OpenVPN, Xray SOCKS5/HTTP and Xray TUN pass container E2E.
  Desktop acceptance is pending (see
  `docs/plans/2026-09-22-02-ubuntu-completion-spec.md`). Linux system proxy is
  outside the plan.
- Pre-login always-on currently supports WireGuard and static routes. OpenVPN
  and Xray profiles can auto-connect when the user launches the app, but cannot
  be enrolled for pre-login daemon replay yet.
- No process-based routing, no VPN chaining, and no custom TUN. Generated Xray configurations expose a local SOCKS5 inbound; imported Xray JSON may define other inbounds.
- The release-candidate gate is incomplete: real-backend VM E2E, desktop tray
  interaction and a secret scan remain pending. Docker package smoke and daemon
  crash-recovery drills have passed.
- The destructive E2E harness runs only on a disposable Windows VM with
  explicit env acknowledgement (see `docs/testing.md`).
- Release artifacts are unsigned; expect SmartScreen warnings.

## License

[MIT](LICENSE)
