# Network Orchestrator

A CLI-first app for WireGuard, OpenVPN, Xray/VLESS, policy routes, and
network exploration. Windows and Linux use Tauri 2; macOS 27 has a native
SwiftUI/AppKit client linked directly to the Rust core, without a WebView.
On macOS, the GUI and `netorch` call the same typed Engine services and share
one unprivileged connection runtime per data directory. The separate privileged
helper owns tunnel, route, interface and DNS mutations; the bridge is only the
Swift client's JSON adapter.
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
OS version of 27.0. App version comes from the macOS line in `versions.toml`. Developer
ID signing and notarization for distribution remain separate release steps.
No Node runtime, React or WebKit is included in the native app. npm only invokes
the build script; `bash scripts/build-macos-native.sh` works without npm.

The native GUI and CLI share `~/Library/Application Support/com.netmanager.app.macos`.
`netorch up PROFILE` connects in the background; closing the GUI does not disconnect.
Use `netorch down PROFILE` to stop it or `netorch up PROFILE --foreground` for a
generation-scoped foreground connection. See [`macos/README.md`](macos/README.md)
for the command surface, credentials and test isolation.

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

#### Named per-command proxy exits (Linux)

Names are saved in the netorch profile, not executable hooks in an imported
Xray config. Choose ordinary profile rules, a fixed subscription node, an
independent ordered pool, or the daemon's marked direct outbound:

```bash
netorch proxy set default --profile work --rules
netorch proxy set nl --profile work --via "Netherlands"
netorch proxy set ru --profile work --pool "Moscow" "Saint Petersburg"
netorch proxy set direct --profile work --direct
netorch proxy list --profile work
netorch up work
netorch proxy nl -- curl https://example.com
netorch proxy ru -- curl https://example.com
netorch proxy direct -- curl https://example.com
netorch proxy --profile work default -- curl https://example.com
netorch proxy remove nl --profile work
```

Use your own endpoint names, numbers or stable keys. Exit names are arbitrary
lowercase ASCII letters/digits/`-`/`_`, 1–32 characters, starting with a letter
or digit; `list`, `set`, `remove` and `help` are reserved. A profile supports
16 exits and each pool 1–8 unique, ordered nodes. Duplicate names across
profiles require `--profile` before the exit name.

Configuration and listing work offline. Launch requires an already connected
Xray **TUN** profile and an updated Linux daemon supporting `xray.proxyExits`.
Adding/changing listeners requires an explicit disconnect/reconnect; launch
never starts, reloads or restarts the VPN. A stale or removed saved exit refuses
before running the command. Node/pool settings retain missing keys and block
instead of choosing an unconfigured endpoint. Pools probe their own members
with the profile's HTTPS probe target, prefer the first healthy member and
return to it after recovery; an all-down pool blocks, even if the main exit is
healthy. They do not change the default exit. Explicit named nodes are excluded
from automatic main-pool recruitment, but may still be selected as primary or
manual backups.

`--rules` retains profile routing, including blocks. Fixed node, pool and direct
exits override those routing rules, including blocks, for their own listeners.
`direct` uses marked daemon sockets to bypass this profile's TUN; it does not
merely clear proxy variables or promise to bypass another VPN/firewall.

Commands are executed as the invoking user with their original argument vector,
terminal, exit status and signals; no shell is inserted. Both case spellings of
`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` are replaced. HTTP(S) uses
the exit's loopback HTTP proxy; SOCKS uses `socks5h` for proxy-side name resolution.
The bypass list is empty by default, even when the parent has `NO_PROXY=*`.
To explicitly exempt destinations, save the exit with
`--no-proxy 'internal.example,10.0.0.0/8'`; changing only that list applies to the
next command without reconnecting. These exceptions use normal system routing,
which can still traverse the TUN.

This is **not process network isolation**: programs must honor proxy environment
variables, and arbitrary UDP is not covered. The loopback listeners are
unauthenticated and usable by other local processes while the profile is active.

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
`network-orchestrator-<version>-amd64.run` for the GUI. The CLI installer includes
the shared daemon; the GUI installer includes both `netorch` and that daemon.

```bash
sh ./netorch-0.15.0-amd64.run --check  # preview without installing
sudo sh ./netorch-0.15.0-amd64.run
# The GUI installer also installs/reuses netorch:
sudo sh ./network-orchestrator-0.15.0-amd64.run
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
Do not mix an older GUI release line with the new shared CLI runtime; use the
matching GUI installer to update both clients together.

The CLI and daemon `.deb` files remain under `target/release/packages/`, the GUI
`.deb` and `.rpm` under `target/release/bundle/{deb,rpm}/`, and the Arch package
under `target/arch/`. RPM and Arch contain GUI, CLI, daemon and the pinned Xray.
The Arch build uses a disposable Docker container; on Arch/CachyOS install the
resulting `target/arch/network-orchestrator-*.pkg.tar.zst` with `sudo pacman -U`.

### One Linux backend, two clients

`netorch` is the headless client; the GUI calls the same `LinuxEngine`, not a
second connection implementation or a CLI subprocess for each action.
Both use `${XDG_DATA_HOME:-$HOME/.local/share}/com.netmanager.app/` by default:
profiles, managed configs, subscriptions, executable settings and remembered
OpenVPN credentials are shared. `NETORCH_DATA_DIR` selects an absolute isolated
data directory for either client; CLI `--data-dir` overrides it. The development
GUI retains its separate `com.netmanager.app.dev` identity and daemon socket.
Profile writes use an OS file lock and atomic replacement; CLI changes refresh
the open GUI through its existing `route-changed` event.
Opening an existing GUI editor obtains the profile and an opaque edit revision
from one read. Saving uses an atomic revision comparison; a concurrent CLI edit
causes a reload conflict instead of silently overwriting the newer profile.

System connections (WireGuard, OpenVPN, Xray TUN and static-route profiles) are
owned by the privileged daemon until explicit disconnect or backend cleanup.
They require neither an open CLI/GUI nor a user service to keep them alive.
Either client can inspect/disconnect the same connection. Routes, interfaces
and DNS remain polkit-authorized operations of the system daemon.

One unprivileged `netorch serve` process per data directory/daemon socket owns
local Xray SOCKS/HTTP children and user proxy rollback. It starts on demand as
a transient systemd user unit; closing the GUI or invoking shell does not
disconnect it. Raw Xray JSON imports default to SOCKS mode.
For these local proxies, the user manager must be available
(`systemctl --user status`). Without one, run `netorch serve` in a separate
foreground session using the same data directory and daemon socket. User units
normally stop at logout; keeping them across logout requires an explicit
administrator-approved linger setting (`loginctl enable-linger "$USER"`).
Nothing enables linger automatically.
`netorch up --foreground` disconnects on interrupt, termination or terminal
hangup. Root connections require `--foreground` and never launch the user service.

The user service restarts on failure to restore saved proxy settings, not to
reconnect profiles. Its global proxy lock and ownership marker live in
`${XDG_STATE_HOME:-$HOME/.local/state}/netorch/`, independently of ephemeral
session sockets. A different data directory cannot take over an unrestored proxy.

Headless observation and explicit recovery:

```bash
netorch diagnose [PROFILE]
netorch --json watch [PROFILE]
netorch recover
netorch recover --cleanup
```

`diagnose` and `recover` without `--cleanup` are read-only reports. Diagnostics
exit successfully when the report is produced, even when its findings describe
failures. **`recover --cleanup` disconnects all current-user daemon and local
connections, restores the saved user proxy and pauses always-on definitions**;
it is not limited to stale owners and does not delete saved profiles.

JSON `watch` emits one snapshot per line, with `type`, `reason`, `daemon` and
`profiles` fields. Reasons are `initial`, `change`, `resync`, `disconnected` and
`reconnected`; profile states are `running`, `stopped`, `failed` or `unknown`.
Lost IPC never preserves a cached `running` state. Subscription events trigger
fresh snapshots; bounded polling also observes local children and profile edits.
The GUI uses the same event transport and refreshes after reconnect/event gaps.

CLI exit codes are 0 for success, 1 for operation failure and 2 for invalid usage.
With `--json`, errors on stderr use
`{"error":{"kind":"usage|operation","message":"..."}}`; watch stdout remains JSONL.

The cross-platform target and migration boundary are defined in
[`ARCHITECTURE_CONTRACT.md`](ARCHITECTURE_CONTRACT.md).

### Linux CLI-first operations

The GUI and CLI use the same profile, subscription, network, provider,
diagnostic, system and connection-set services. Existing short commands remain
available; `netorch --json` emits machine-readable results. Use
`netorch COMMAND --help` for arguments and protected input-file options.

| Area | Commands |
|---|---|
| Profile settings | `profile list/show/create/edit/delete/reorder/role/networks`, `profile save-link/save-wireguard/import-configs/import-link` |
| Subscriptions | `subscription import/refresh/interval/endpoints/test/switch`; existing `backup`, `route`, `checks`, `migrate` and `proxy` commands |
| Connection lifecycle | `up`, `down`, `status`, `reload`; `openvpn connect/plan/probe`, `openvpn credentials forget` |
| Network inventory and changes | `net interfaces/routes/tables/lookup/map/explain`, `net interface`, `net stop-external`, `net route/rule add/delete/list`, `net dns status/probe`, `net intent list/set/delete` |
| Routing input | `net import-cidrs/import-happ/test-route` |
| Other providers | `service nm list/set`, `service tailscale status/up/down`, `service netbird status/up/down` |
| Persistent policy | `always-on list/set/remove/resume`, `condition list/put/remove` |
| Observability and recovery | `diagnostics inspect/diagnose/exit-ip/proxies/stats`, `logs show/clear/daemon`, `recovery report/cleanup` |
| System settings | `system capabilities/daemon-status/elevated`, `system proxy status`, `system auth get/set`, `system autostart get/set`, `system auto-connect result/run` |
| Backend settings | `backend list`, `backend path set/reset`, `backend xray offer/install/cancel/remove` |
| Saved combinations | `sets list/get/put/delete/import/capture/apply/down` |

`profile edit PROFILE --file FILE` is a partial atomic update: omitted
subscription identities, pins, checks, proxy exits and other settings survive.
`subscription import` accepts separate private URL/HWID files and an optional
`--cache-file`; cached import/refresh does not contact the provider.
`checks set PROFILE --file FILE` replaces the complete service-check list.
Use private regular files owned by your user (`chmod 600`), or supported stdin
inputs, rather than putting subscription URLs, credentials or setup keys in argv.

Connection sets live in the protected shared `connection-sets.json`; Linux
migrates browser-owned sets only after persistence succeeds, without replacing
existing shared IDs. Missing members remain visible and block application.
Apply prepares starts and rollback requests before stopping existing connections;
unchanged members and always-on enrollment are preserved. OpenVPN prompts are
collected before teardown. Headless callers can use:

```bash
netorch sets apply work --credentials-file /private/openvpn-inputs.json
```

The private input maps profile IDs to
`{"credentials":{"authUserPass":{"username":"vpn-user","password":"<password>"}},"remember":false}`.
Credentials are not stored in a set; `remember: true` explicitly requests the
shared keyring policy. `sets down` needs no reconnect credentials and reports
partial teardown failures. App logs are shared, bounded and redacted before
persistence; clearing them in either frontend clears the same store.

Starting an idle runtime or listing profiles does not execute auto-connect.
`system auto-connect run` is explicit. Login autostart retains the existing
`Network Orchestrator.desktop` entry and starts the GUI; it does not silently
enable a second headless startup mode. Managed installation cancellation works
across frontends. Update both packages and restart an old user runtime before
using prepared local-Xray connections; incompatibility is rejected before a set
disconnects anything. Windows-only elevation relaunch and standard-config
discovery are not Linux CLI operations.

### Linux Xray IPv6

A primary managed TUN with no explicit routes captures IPv4 and IPv6. Split
default installs both halves of each family. Explicit routes and secondary
networks are not expanded. FakeDNS emits only pools fully captured by the
effective routes; incompatible explicit DNS-family choices fail rather than
being rewritten. Endpoint bypasses, underlay selection, reload, child recovery
and journal cleanup handle both address families.

IPv6 TUN requests require the daemon's `xray.tun.ipv6` capability. Update/restart
the system daemon when upgrading; unsupported requests fail before mutation.
IPv4-only requests and status/disconnect remain available with older daemons.
Capture is not proof that a remote provider offers IPv6 Internet egress.
See [`docs/testing.md`](docs/testing.md) for isolated packet evidence and limits.


## Development

### Prerequisites

- Windows 10/11, [Rust](https://rustup.rs/) (MSVC toolchain),
  [Node.js](https://nodejs.org/), Visual Studio C++ build tools, WebView2.
- Backend executables are needed only for the profiles you actually use.
  WireGuard (`wireguard.exe`/`wg.exe`) and OpenVPN (`openvpn.exe`) external
  packages remain required because their drivers/services are not managed by
  the app; an external Xray (`xray.exe`) install is optional because a
  verified managed install exists.

### Windows subscriptions and NetBird

Import a subscription through **Import → Subscription** to choose its servers
inside the app. If the provider requires an HWID, use **Generate automatically**
or enter the HWID already registered with that provider. A generated identifier
is stable for this Windows installation; it can count as an additional device
at the provider. Supported inputs are VLESS/Hysteria2 share-link subscriptions
and full Xray JSON subscriptions.

New Windows Xray imports use TUN mode; saved profiles retain their previous
mode. Install managed Xray from Settings before connecting. Its pinned package
includes Wintun. The app owns capture routes and rollback and selects a physical
uplink for Xray; NetBird keeps its own more-specific private routes and DNS.
Native simultaneous-traffic and crash-recovery acceptance is still pending.

Install and sign in to the official NetBird Windows service once, then use its
service row in Profiles for status/connect/disconnect. The app talks to the
installed daemon rather than importing NetBird keys. Generic detected adapters
are read-only on Windows; they are not VPN profile controls. Windows background
service/CLI parity remains outside this implementation.

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

```powershell
npm.cmd ci
pwsh -File scripts/build-windows.ps1
```

Requires PowerShell 7 and the normal Windows build prerequisites, including
`python3` on PATH. The script prints the unsigned NSIS installer path and keeps
build output outside the checkout. `TEMP` must be on the same drive as the project;
an existing external `CARGO_TARGET_DIR` is reused.

The destination PC only needs the installer, not Rust or Node. Setup downloads
WebView2 when it is missing. Install managed Xray from the app settings, install
and sign in to NetBird separately, and import the subscription on that PC.

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
