# E2E testing

## Linux CLI-first architecture acceptance

```bash
npm run build
cargo build -p net-manager-app -p network-orchestrator-daemon -p net-manager-cli --features tauri/custom-protocol
e2e/linux/run_cli_first.sh
e2e/linux/run.sh
```

Requires Docker, `/dev/net/tun`, the pinned Xray assets under
`target/release/xray-package/v26.10.31`, and containerized systemd permissions.
The CLI-first runner builds its disposable image from `Dockerfile.cli-first`;
its actual scenarios run with `--network none`. Never execute
`cli_first_scenarios.py` on the host. The GUI must embed the current frontend,
not load a development URL.

Verified on 2026-11-08 in disposable Ubuntu 26.04 containers:

- A real CLI-only static connection, with no user manager, invalid runtime
  directory and no sibling `netorch`, retained its kernel route and daemon owner
  for 36 seconds after CLI exit; a new CLI disconnected both.
- The native Tauri Profiles surface showed the CLI connection as running.
  Light/dark views at 1200px and the 960px minimum had no horizontal overflow;
  native screenshots were inspected. GUI exit preserved the connection, and GUI
  disconnect removed it. Foreground SIGHUP and SIGTERM removed resources explicitly.
- Real `watch` observed initial/change/disconnected/reconnected snapshots;
  `diagnose` produced a report. Daemon restart cleaned ordinary ownership
  without autoconnect. `recover` was read-only, while `recover --cleanup` removed
  current-user ownership and paused always-on.
- Real loopback VLESS traffic crossed both SOCKS and HTTP CONNECT as the user.
  CLI and GUI shared the runtime; traffic survived GUI exit. Killing Xray
  restored the complete real dconf proxy snapshot, and subsequent `down` cleared
  failed state. Killing the runtime triggered systemd restart and proxy recovery
  without either frontend.
- A stale GUI edit revision was rejected after a real CLI rename, preserving
  the newer stored profile.
- The existing backend suite passed real WireGuard and OpenVPN split/full
  traffic, per-link DNS, Xray TUN/proxy traffic, UID/polkit isolation, daemon
  crash recovery and always-on pause/replay scenarios.

Artifacts: `target/e2e-cli-first/scenarios.log`, `watch.jsonl`, native PNGs and
`journal.log`. They contain synthetic fixtures only. Missing subscription
capabilities, incompatible/malformed frames, stalled services, partial-frame
timeouts and closed stdout consumers are covered by real-CLI subprocess and
transport regressions, not an old native daemon installation.

For an externally built daemon, the backend suite accepts
`NETORCH_E2E_DAEMON=/absolute/path/to/binary`; it skips the default release build.
The CLI-first smoke uses debug binaries and is not a production package build.
The installer unit/container suites separately verify CLI-only installation and
shared-daemon upgrade/removal semantics.

Workspace fmt/check/strict Clippy/tests (excluding native macOS crates), version
checks/tests, `npm run build` and frontend tests passed. This verifies Linux, not
macOS/Windows integration or physical logout/reboot behavior.

## Linux multinode routing and recovery

```bash
cargo build -p network-orchestrator-daemon -p net-manager-cli
python3 e2e/linux/multinode_scenarios.py
```

Requires Docker, `/dev/net/tun`, the existing `netorch-e2e-client` image
(`docker build -t netorch-e2e-client e2e/linux`) and the pinned Xray package
staged under `target/release/xray-package/v26.10.31`.
The script creates and removes a disposable container with `--network none`;
route mutations never run on the host. It starts real local VLESS peers and
HTTPS marker servers with a temporary CA trusted only inside the container.
It verifies primary preference, ordered backups, automatic primary return,
independent pinned routing, fail-closed pins/all-down, owned QUIC rejection,
unchanged-DHCP stream preservation, gateway/source/interface migration,
offline crash deferral and recovery of a `SIGSTOP`-stalled child.
Real unprivileged CLI commands import a synthetic subscription, rebuild
verified/name-only pools, reject advertised-country mismatches and apply a
policy without changing its source. Local HTTPS country fixtures are reached
through each candidate; no real subscription or public connectivity service
is used.

DNS A/AAAA/HTTPS queries exercise the pinned backend's rewrite policy. An
injected DNS outage must clear without restarting a healthy HTTPS path.
Foreign UDP sockets must not count as the child's sockets, and an application
connection storm must remain diagnostic. The final scenarios create actual
owned UDP transports and simulate a daemon crash plus a deleted old package
executable, checking recovery/cleanup without killing unrelated Xray peers.
The container has an explicit file-descriptor limit for these resource tests.

## Linux named process proxy exits

```bash
cargo build -p network-orchestrator-daemon -p net-manager-cli
python3 e2e/linux/multinode_scenarios.py --named-proxies
```

Uses the same disposable image, pinned backend and temporary CA, with real
UID-65534 CLI commands and a full IPv4 TUN. Offline configuration/listing runs
with an unreachable daemon socket and must send no service request. Synthetic
HTTPS markers distinguish ordinary rules, fixed nodes, an independent ordered
pool and the physical path: unproxied traffic first proves the target is captured
by the TUN, while only a marked direct connection reaches the underlay marker.

The scenario checks block/direct rules, fixed-node override, missing-key
blackholes, ordered pool failover and all-down refusal despite a healthy main
node/reserve. It poisons inherited HTTP/SOCKS proxies and `NO_PROXY=*`, then
checks both the cleared default and an explicit bypass exception. It exercises
literal argv, exit status 37, same-PID `exec`, SIGTERM, unchanged tunnel PID and
kernel routes, stale/removed-alias refusal before command execution, listener
cleanup and preservation of unrelated peers. No real subscription or public
service is contacted.

## Linux pinned service availability

```bash
cargo build -p network-orchestrator-daemon -p net-manager-cli
python3 e2e/linux/multinode_scenarios.py --service-checks
# Shorter focused pass for CLI configuration, live unpin and failed persistence:
python3 e2e/linux/multinode_scenarios.py --service-checks-client
```

The same disposable Docker contract applies. Synthetic HTTPS services verify
HEAD-only requests, HTTP 403/302 transport responses without redirect following,
no cookie/auth reuse, typed TLS failures, child reaping and refresh preservation.
The service-only outage keeps ordinary tunnel traffic healthy: three timeouts
must degrade only that check, fresh HTTP must reset it, and PID/pins/default
selection must remain unchanged. Disabling the checks must stop subsequent
requests. Real unprivileged CLI operations also exercise live unpin cancellation
and a failed atomic configuration write; an unsaved worker must not keep probing.

### Configuration and interpretation

In a Linux Xray subscription profile, use **Service availability**, or:

```bash
netorch checks list PROFILE
netorch checks add PROFILE --via NODE --name 'API connectivity' --url 'https://service.example/health'
netorch checks run PROFILE --id CHECK_ID
netorch checks background PROFILE CHECK_ID on
netorch checks background PROFILE CHECK_ID off
netorch checks remove PROFILE CHECK_ID
```

Replace `PROFILE`, `NODE`, `CHECK_ID` and the example URL with your own choices.
`NODE` is a stable endpoint key, current subscription number or unambiguous name,
and must already be explicitly pinned by domain or fixed-DNS policy. Merely being
the primary, backup or a pool member does not qualify. Missing/unbound pins are
unavailable: no alternate node or direct connection is attempted.

The initial list is empty; background is off. Manual checks work while
disconnected and in SOCKS mode through a temporary unprivileged single-node
Xray. Background preferences run only during an active TUN connection, starting
60 seconds after enabling/connecting. Background changes require acknowledgment
from the daemon; a transient socket failure is not treated as proof of opt-out.
Ordinary profile editing and subscription refresh retain the settings.

Each HTTPS HEAD request has a five-second limit. There are at most 16 checks;
manual workers use up to four endpoints concurrently and serialize checks of
the same endpoint. No cookies, authentication headers, user headers, response
body reads or redirects are used. Do not supply passwords, query tokens, secret
URLs or side-effect/webhook endpoints. Queries are allowed, not secret storage.
Use non-secret names: they are diagnostic labels and may appear in logs.
URLs remain in protected profile configuration/editor data, not results,
transition logs or the ownership journal. CLI URLs can also enter shell history.

Every HTTP status, including 403, 405 and 5xx, proves only an HTTP transport
response; it does not prove API authorization or application correctness.
Timeout/TLS/transport failures increment the background streak and mark
degradation at three. HTTP or unavailable resets the streak. Remote SOCKS DNS
failures are reported as transport errors when they cannot be distinguished
reliably. Service results never request recovery, route changes, tunnel restart,
country/IP changes or direct fallback. Existing global tunnel and failover
health checks remain separate.



## Debian/Ubuntu installers and updates

```bash
python3 -m unittest scripts/test_linux_installers.py
e2e/linux/run_installers.sh
```

The unit tests generate synthetic Debian archives and execute both generated
`.run` installers with fake package and service commands. They cover fresh CLI
and GUI installs in both orders, updates, equal versions, newer daemon patches,
downgrade refusal, incomplete installs, prereleases, architecture checks, corrupt
payloads, legacy combined GUI migration, APT errors and `--check` without root.
They never install host packages or start services.

`run_installers.sh` uses a disposable Debian-based Python container with
`--network none`. APT/dpkg are real; package payloads contain only synthetic text
files and `systemctl` is faked. It verifies CLI → GUI, updates, daemon reuse,
downgrade refusal, auto/manual dependency tracking and removing GUI while keeping
CLI and daemon. The image must be available or downloaded before the run. Never
run `test_installers.py` directly on the host. The manual CI workflow runs both
checks in its Linux installer job. These checks do not validate real VPNs or the
Tauri GUI package build.

## Shared Linux CLI/GUI runtime

Both frontends use `LinuxEngine` and the same protected profile store.
System connections belong to the daemon and must survive the last client
exiting without a user-runtime keeper. Local Xray SOCKS/HTTP uses one
unprivileged `netorch serve` process per data directory/daemon socket.
The systemd user manager starts it on demand; a manually started `netorch serve`
supports local proxies in isolated environments without that manager.
Do not run GUI as root. See the root `ARCHITECTURE_CONTRACT.md` for the target
cross-platform lifecycle and the native-platform verification boundary.

### Daemon-owned lifetime verification — 2026-11-08

- RED: the engine regression attempted user-runtime retention and rolled back;
  the daemon regression removed the connection after its client process died.
- GREEN: protocol coverage kills and reaps a real client child, closes IPC, waits
  36 seconds beyond the former grace/scan window, rejects another UID's
  disconnect and verifies that same-UID explicit disconnect releases the link.
  Network executors are fake; no host routes or interfaces are changed.
- A built `netorch`, run as UID 1000 in a disposable toolchain container, imported
  a synthetic WireGuard profile, connected through a fake Unix-socket daemon,
  observed Running from a new invocation, disconnected, and observed Stopped.
  `XDG_RUNTIME_DIR` pointed at a nonexistent directory; no user runtime started.
- Version checks/tests, workspace fmt/check/strict Clippy/tests (excluding native
  macOS crates on Linux) and `npm run build` passed.

This initial unit/smoke run did not verify real VPN traffic, native GUI interaction,
logout behavior or macOS/Windows service integration; the CLI-first acceptance
above adds real Linux backend/GUI evidence. The following package evidence
predates this lifetime cutover.

Verified on 2026-11-07 with the built Arch `0.14.0-1` package, installed only
inside disposable containers:

- Real pinned Xray served loopback HTTP through SOCKS as the unprivileged user.
  Independent CLI processes observed one child; duplicate `up` was rejected;
  extra command fields in runtime IPC were rejected without echoing their value.
- The native Tauri Profiles row displayed a CLI-started connection. Its actual
  switch disconnected/reconnected that same runtime; a CLI rename refreshed the
  rendered row without reloading. SOCKS auto-connect skipped an already-running
  profile with the privileged daemon absent.
- Window close followed by GUI process termination left real SOCKS traffic
  working; CLI `down` reaped the Xray child. Foreground SIGHUP disconnected
  instead of leaving the shared connection running.
- A real `systemd --user` unit started automatically as uid 1001. The real
  privileged daemon retained an armed static profile beyond its 30-second
  last-client grace after the CLI exited; the deferred profile changed no
  kernel routes. Explicit `down` removed both local and daemon-owned state.
- The existing packaged-WebView scenario installed and removed a proto-79
  route on a disposable dummy interface through the real daemon and the actual
  rendered switch. The daemon owner and route were absent after disconnect.

`e2e/linux/run_app_gui.sh` needs all three matching `.deb` packages (GUI in the
Tauri bundle directory, CLI/daemon in `target/release/packages`) or the combined
RPM. It starts a real user manager and uses its canonical D-Bus session.
Never run the route-mutating inspector scenario directly on the host.

The native status bar also renders an available Xray with no version metadata
as ready rather than absent.

Linux Rust checks omit the macOS-only bridge/helper crates; a full workspace
check on Linux fails at macOS `libc` APIs rather than validating those targets.


## Browser sandbox on macOS

```bash
npm run dev:sandbox
# Open http://localhost:1422 in a browser.
npm run test:sandbox
```

The sandbox uses synthetic WireGuard, OpenVPN, Xray subscription, and static
route profiles. All IPC calls are intercepted by Tauri's mock transport and
handled in memory. There is no native-command fallback, VPN process, file
import, subscription HTTP request, keyring write, OS route, DNS, or proxy
mutation. Unknown commands, interface changes, elevation, backend installation,
and process restart are rejected. The installer refuses to run in a native
Tauri window. Production builds exclude the sandbox.

The green banner identifies this mode. Reload resets the synthetic backend;
connection snippets use this browser origin's localStorage and survive reload.
File dialogs and confirmations return synthetic choices. Subscription delays,
config analysis, conflicts, and traffic counters are fixtures. IPv4 lookup is
simulated; IPv6 parsing, bulk CIDR parsing, OpenVPN probes, and real config
generation are covered by Rust tests instead. Do not use sandbox results as
evidence that real VPN credentials or connectivity work.

## Native proxy connections verification — 2026-10-01

The native client starts Xray in loopback SOCKS/HTTP mode and can drive the
macOS system proxy. RED: bridge tests rejected `runtime`, `connect` and
`set_system_proxy` as unknown; core tests lacked the macOS Xray layout and
`MacProxyAdapter`. GREEN: core managed Xray (synthetic archives plus the
official `Xray-macos-arm64-v8a.zip` via `XRAY_MACOS_ARCHIVE`, SHA-256
`9b99a351…63d6`), macOS proxy adapter on a fake `networksetup` runner
(service filtering, snapshot, loopback-only apply, restore, manager round
trip), and bridge runtime refusals/state passed.

Live acceptance (`NETORCH_LIVE_XRAY`): verified install from the official zip,
share-link import, connect, `curl` to https://www.youtube.com/ through the
client SOCKS port via a loopback VLESS server returned 200, then disconnect
and shutdown left no Xray process. The loopback server resolves over DoH:
with incy connected the system resolver returns fake IPs in 240.0.0.0/4,
which Xray's freedom outbound refuses as reserved.

Manual checks on the host, each restored immediately: `networksetup` can set
proxies without sudo for an admin user; while incy (packet tunnel on utun9)
is the primary service, proxies on Wi-Fi/Ethernet appear only under
`__SCOPED__` and the global proxy stays empty; proxies set on the incy service
itself are ignored. Hence the in-app override warning. No real user profile
was used.

## Native subscription URL verification — 2026-09-30

Import → Subscription now fetches HTTP/HTTPS URLs in the native client, with
optional HWID and profile name. Tauri and SwiftUI share subscription parsing,
import and managed configuration storage. Plain-text, padded/unpadded standard
Base64 and URL-safe Base64 lists are supported. Native connection cards offer
a server selector; selection only rewrites the saved configuration. Automatic
subscription refresh remains unavailable in this native stage.

RED: the bridge rejected `import_subscription` as an unknown method. GREEN:
479 Rust workspace tests and 11 Swift tests passed, including a local fake
HTTP import, HWID transmission, endpoint switching, redaction, invalid URLs,
empty/unsupported subscription bodies, save rollback, HTTP errors, the 1 MiB
response limit and HWID removal on cross-origin redirects. Existing Tauri
subscription tests passed after the shared import replaced its local copy.
The total fetch timeout is 30 seconds; redirects are limited to five and
HTTPS downgrade redirects are rejected. No real subscription URL was used.

Formatting, workspace check, strict Clippy, localization/sandbox tests and
frontend production build passed. The signed local native app also built.
Release build tools retain metadata to avoid stripping the `rustversion`
proc macro; the application remains stripped. Offscreen native acceptance
rendered 64 images under `target/macos/subscription-preview`, including both
import dialogs and a subscription server picker in both languages and themes.
These renders do not claim foreground native UI automation.

## Share-link import verification — 2026-09-30

Both clients offer Import → Link for a single `vless://`, `hysteria2://` or
`hy2://` connection, with an optional name. The shared Rust import stores a
private generated Xray revision, assigns distinct loopback proxy ports and
cleans the revision up if profile persistence fails. The Windows path keeps
DPAPI protection. Import never starts a tunnel or changes routes, DNS or the
system proxy. At that stage, HTTPS subscription fetching was only available
in Tauri; native support is recorded in the subscription verification above.

RED: the native bridge acceptance test initially rejected `import_share_link`
as an unknown method. GREEN: 473 workspace Rust tests, 10 Swift tests, seven
sandbox tests and ten localization tests passed, along with formatting,
workspace check, strict Clippy and the production frontend build. Native
acceptance rendered 60 images across both languages and themes, including
the new link dialog, under `target/macos/link-preview`.

Browser acceptance used a temporary sandbox tab: empty input disabled import;
an HTTPS URL produced a translated validation error; VLESS imported with its
fragment name; Hysteria2 imported with a custom Russian name. The form cleared
after success, all connections stayed off, and the temporary tab was closed.
Actual configuration generation, managed storage, rollback and duplicate IDs
were checked with synthetic Rust/Swift fixtures, rather than real credentials.
Native images are offscreen renders, not foreground UI automation.

## Local verification record — 2026-09-30

The app was launched on macOS with an isolated QA application identifier.
Browser checks used the sandbox above. Real Linux network checks used disposable
ARM64 Ubuntu containers in a separate Docker bridge with no published ports,
host networking, Docker socket mount, or user VPN files. WireGuard keys and
OpenVPN certificates/credentials were generated for the test peers. The initial
internal-only bridge prevented the full-tunnel underlay probe; the successful
run used the private bridge arrangement from the existing E2E contract.

This was a review of the main paths across core, daemon, Tauri commands, and
React, backed by tests and UI checks. It is not an exhaustive proof that every
line or every platform-specific path is correct.

| Area | Verification | Result |
| --- | --- | --- |
| macOS workspace | fmt, all-target check, strict clippy, workspace tests | 459 Rust tests passed |
| Linux x86_64 core + daemon | Docker Rust tests, daemon release build | 539 tests passed, including doc tests |
| Linux ARM64 core + daemon | fmt, strict all-target clippy, Rust tests | 530 tests passed, including doc tests |
| Frontend | TypeScript + production Vite build; pure sandbox tests | build passed; 6 tests passed; sandbox absent from dist |
| Native macOS shell | Tauri dev startup with QA identifier | launched; real host VPN connections were not attempted |
| Profiles UI | create static route, edit WireGuard, import file/subscription, delete, search/group controls | synthetic data only; passed |
| Connection UI | four concurrent backends, OpenVPN credential prompt, disconnect, save/apply connection snippet | synthetic data only; passed |
| Subscription UI | endpoint selection, refresh, interval, delay, disabled edits while active | synthetic data only; passed |
| Network and routes UI | adapters/details, route overview/table/tree/flow/by-interface, IPv4 longest-prefix lookup | synthetic data only; passed; display findings below |
| Recovery/settings UI | cleanup, diagnostics, always-on enable/disable and edit guard, login autostart, auth mode, executable selection/reset | synthetic data only; passed |
| Linux daemon | existing scenarios.sh, including IPv4/IPv6, policy rules, polkit/uid isolation, journal, restart/cleanup, 1,000 routes | all 45 checks passed |
| WireGuard | existing wg_scenarios.py, real split/full traffic, DNS, crash recovery, always-on | all 28 checks passed |
| OpenVPN | existing ovpn_scenarios.py, real split/full traffic, pushed DNS, crash recovery | all 19 checks passed |
| OpenVPN authentication/probe | existing ovpn_auth_scenarios.py | all 4 checks passed |
| Static always-on | existing always_on_scenarios.sh, pause/resume, repair, late interface, uid isolation | passed |
| Real Xray proxy/TUN | unit tests and sandbox only in this session | real traffic not verified; pinned Linux managed package is x86_64-only |
| Windows system proxy, DPAPI, UAC, tunnel services; desktop Linux polkit prompts/tray | applicable ordinary unit tests only | VM acceptance still required |
| Real subscription service / user's VPN | not used | network/provider behavior remains unverified |

### Reproduced and corrected

- macOS compilation accessed a nonexistent `net_route::Route.metric`; use the
  platform field only on Linux/Windows and an explicit unavailable-metric
  fallback elsewhere. Route conversion has a regression test.
- The Linux daemon's orchestration/process modules were exposed on macOS even
  though their DNS, D-Bus, and libc dependencies were Linux-only. Gate those
  modules by platform; neutral protocol/store tests still run on macOS.
- Concurrent `ProfileStore::upsert` operations could lose unrelated profiles
  or collide on the temporary file. Serialize write transactions on the shared
  store instance. A 12-thread regression failed before the fix and passed after.
  This lock does not provide coordination between separate processes or store
  instances pointing at the same file.
- Profile documents lacked private Unix permissions. Protect their directory
  and temporary document before atomic rename. The permission regression failed
  before the fix and now verifies modes 0700/0600.
- Xray profile validation accepted HTTP port 0 and identical SOCKS/HTTP ports.
  The regression failed before the fix; both invalid states are now rejected.
- Linux ARM64 daemon compilation referenced x86_64-only managed Xray helpers.
  ARM64 now builds and returns `Unsupported` for that managed executable;
  this does not add an ARM64 Xray package. Architecture-specific regression passed.
- Strict Linux clippy found three nonminimal boolean conditions in DNS/staging
  cleanup. Apply equivalent expressions and re-run the Linux tests.
- WireGuard E2E required a host `wg` tool although the documented prerequisite
  is Docker. Generate test keys through `wg` inside the disposable containers;
  the full integration suite passed with no host installation.
- Saved-profile warnings showed the old name or a new profile ID. Resolve the
  name from the returned saved profiles. Route lookup now asks for an IP literal
  rather than a hostname the backend does not resolve. The adapter panel close
  control has an accessible name.

### Remaining logic/display findings

1. **Linux local Xray auto-connect depends unnecessarily on the daemon.**
   `src-tauri/src/auto_connect.rs::connect_on_startup` calls `hello` and
   `owned.list` before starting any saved profile, even when all selected profiles
   are SOCKS Xray (`daemon_owner == None`). If the daemon is unavailable, local
   proxy auto-connect is skipped although the manual local process path does not
   require it. Separate local profiles from daemon-owned profiles and add an
   unavailable-daemon regression. Found by code inspection; not injected into a
   desktop Linux app during this session.
2. **Adapter details can display stale routes and hide read failures.**
   `src/components/InterfaceDetail.tsx` fetches only when `iface.ifIndex` changes,
   omits the `route-changed` subscription, and ignores errors. An open panel can
   keep an old route count; a failed initial read looks like an empty table.
   Subscribe and expose a read error. Found by code inspection.
3. **Traffic-flow profile identities and destination labels can mislead.**
   `src/components/RouteFlow.tsx` keys profiles by `ownerName`, so different
   profiles with the same permitted name merge. `destGroup` changes any IPv4
   prefix to `/16`, including broader routes such as `10.0.0.0/8`; this can show
   the wrong apparent coverage. The `/24` fixture rendered as `/16` in the UI.
   Use `ownerProfileId` for identity and mark aggregates clearly while preserving
   broader prefixes. Duplicate-name and broad-prefix cases were found by inspection.
4. **Occupied Xray HTTP listener preflight (fixed).**
   `src-tauri/src/commands/tunnels.rs::connect_profile` checks both generated
   listener ports and rewrites occupied SOCKS/HTTP ports in one managed revision.
   Unit tests cover HTTP-only and dual-port conflicts. A real Xray run with
   occupied ports remains unverified.

Sandbox browser logs included Tauri mock callback warnings during development
reloads/React effect cleanup; no browser error was observed in the completed
flows. These warnings are a mock-event limitation, not evidence of a native
backend failure. Production event behavior still needs platform UI acceptance.

## Linux daemon in a disposable container

`e2e/linux/run.sh` builds the daemon, starts an Ubuntu 26.04 (default) or
Fedora 44 (`E2E_DISTRO=fedora`; firewalld and resolved enabled, SELinux not
enforced in Docker) client and an Ubuntu peer container on a private Docker network, installs the service with systemd and
polkit in the client, and runs `scenarios.sh` there. The scenarios exercise
real netlink route and interface changes, polkit authorization, uid isolation,
restart recovery, shutdown cleanup, WireGuard and OpenVPN split/full tunnels
with real peer traffic and per-link DNS, OpenVPN management credentials,
Xray VLESS/Hysteria2 proxy through SOCKS5 and HTTP CONNECT, Xray TUN,
kernel policy-rule lookup, OpenVPN pushed-route probe, and WireGuard/static-route
always-on replay. Each container has
its own network namespace. Never run `scenarios.sh` directly on the host.

```bash
e2e/linux/run.sh
```

This requires Docker access and `/dev/net/tun`. `CONTAINER_ENGINE=podman`
runs the same suite under rootless Podman (systemd containers get
`--systemd=always` and `CAP_NET_RAW`, which `systemd-resolved` needs for
`SO_BINDTOINDEX` on per-link DNS sockets). The Xray scenarios take a host
binary via `XRAY_E2E_BINARY` (default `~/.local/bin/xray`) and pinned geo
assets via `XRAY_E2E_GEO_DIR` (default `~/.config/xray`, contents must match
the release hashes in `managed_xray.rs`). The harness grants the
client container `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and unconfined AppArmor so systemd
can remount cgroup2. Use it on a development machine or CI worker that accepts
those container privileges. The peer container needs `CAP_NET_ADMIN`. The
current harness verifies the daemon and backends directly. Real Ubuntu desktop
interaction, polkit prompt rendering and login-session autostart still need VM
acceptance.

After building a `.deb` or `.rpm`, the packaged WebView-to-daemon static-route
path can be checked in another disposable container (Ubuntu for `.deb`,
Fedora 44 for `.rpm`):

```bash
e2e/linux/run_app_gui.sh --blank-config
e2e/linux/run_app_gui.sh target/release/bundle/rpm/*.rpm
```

This uses a container-only polkit rule for its headless user session, then
checks save/connect/disconnect through the installed app's WebView and the
kernel route table. It does not verify a visible polkit prompt or Wayland.

## macOS 27 native client

The native SwiftUI client is built with `npm run build:macos` (or
`bash scripts/build-macos-native.sh`). It uses the Rust core directly rather
than the Tauri IPC/browser sandbox. Build and test commands, the independent
data directory and current feature boundaries are documented in
[`../macos/README.md`](../macos/README.md).

On 2026-09-30 the arm64 release bundle was built and launched on macOS 27.0
with Xcode 27.0. Its Mach-O load command and Info.plist both specify 27.0 as
the minimum OS; local ad-hoc signing verifies. The binary links SwiftUI/AppKit
and does not link WebKit. RSS samples were 84.3 MiB for the initial instance
and 137.4 MiB immediately after launching the final foreground bundle; these
are not a comparative memory benchmark. The full macOS Rust workspace gate passed
(467 tests), along with four Swift integration tests and the TypeScript/Vite
production build. Native window interaction/screenshot acceptance remains
pending: the Computer Use helper repeatedly closed its pipe, including after
reset. Automated integration tests are not a substitute for visible UI checks.

Native bridge tests cover persisted profiles, CIDR validation/aggregation,
managed imports, failed-import cleanup, bounded C ABI buffers and refusal of
network mutations. Swift tests cover actual FFI decoding, persisted profiles,
imported-config analysis and read-only Darwin loopback inventory/route lookup.
Ordinary macOS tests never start real VPNs or apply routes, DNS or proxies.

### Shared dark/light design verification

On 2026-09-30 the native screens were restyled to match the Tauri icon rail,
cards, typography, filters, route tabs and dialogs. Both clients use generated
colors and core layout metrics from `design/tokens.json`, with a stale-output
check in their build commands. Native vector assets preserve the original
`src/icons.tsx` geometry and have a checked source hash.

The redesign passed fmt, all-target workspace check, strict clippy and all
467 ordinary Rust tests, TypeScript/Vite build and six sandbox tests. Six Swift
tests passed with `NETORCH_DESIGN_PREVIEWS` enabled, including packaged-icon
verification and 28 offscreen SwiftUI renders: five pages, six route tabs and
three creation/import dialogs in each theme. The native renderer uses an
injected temporary store and synthetic network data. The Tauri browser preview
was also checked by switching its Settings theme between Light and Dark.

PNG renders are under `target/macos/design-preview`, with `dark`/`light`
subdirectories and `tauri-dark.png`/`tauri-light.png` browser references. Exact
pixel parity and foreground native window interaction remain unverified;
the Computer Use helper was unavailable. OS-native chrome and unavailable
backend actions intentionally reflect macOS capabilities. No real VPN was
started and no host network settings were changed.

### Shared language verification

On 2026-09-30 English/Russian/System selectors were added to Tauri and SwiftUI.
Catalogs and plural rules are shared in `locales/*.json`; generated outputs
and native bundle language metadata are checked/derived during builds. Adding
a catalog does not require editing either client's language list. See
[`../locales/README.md`](../locales/README.md) for the translator workflow and
the boundary between UI translations and raw backend diagnostics.

RED: initial runtime tests failed before the translation helper existed.
GREEN: four translation runtime tests and six Python catalog-validation tests
passed, together with nine Swift tests (including 56 English/Russian renders
in dark/light), six sandbox tests and the full required Rust/web quality gate
(467 ordinary Rust tests). The ad-hoc signed native release bundle includes
both catalogs and declares the language tags in Info.plist.

Browser acceptance checked English persisting after reload, live Russian
switching across windows and an open profile form keeping its `Language check`
name and static-routes backend when its labels changed to Russian. The draft
was discarded without saving; the second test tab was closed. The browser
was left on Russian Settings. Native foreground interaction remains limited
by the unavailable Computer Use helper; native localization/persistence are
verified through tests and offscreen renders. The PNGs are under
`target/macos/i18n-preview/{en,ru}/{dark,light}`, with a browser reference at
`target/macos/i18n-preview/tauri-ru-settings.png`. No real VPN was started.

## Windows on a disposable VM

`crates/core/tests/windows_e2e.rs` contains opt-in integration scenarios that
exercise real WireGuard/OpenVPN/Xray binaries and mutate the routing table.
They are `#[ignore]`d, serialized behind a global mutex, and refuse to run
without explicit safety markers.

## Warning

These scenarios install tunnel services, spawn VPN processes, and change
routes. **Run them only inside a disposable Windows VM** with no production
connectivity requirements. A kill-switch fixture (`/0` route) is rejected by
the harness before any mutation.

## Safety gate

Before any mutation every scenario requires:

- `NETWORK_ORCHESTRATOR_E2E=disposable-windows-vm`
- `NETWORK_ORCHESTRATOR_E2E_ACK=routes-and-vpn-will-change`
- an elevated process token
- all used fixture paths to point to regular files
- no default route (`/0`) in the analyzed fixture profile

## Environment contract

| Variable | Meaning |
| --- | --- |
| `NO_E2E_WG_CONFIG` | Path to a WireGuard `.conf` fixture |
| `NO_E2E_WG_INTERFACE` | Expected WireGuard interface friendly name |
| `NO_E2E_WG_CIDR` | Expected private CIDR installed by WireGuard |
| `NO_E2E_OVPN_CONFIG` | Path to an OpenVPN `.ovpn`/`.conf` fixture |
| `NO_E2E_OVPN_INTERFACE` | Expected OpenVPN TAP interface friendly name |
| `NO_E2E_OVPN_CIDR` | Expected private CIDR installed by OpenVPN |
| `NO_E2E_XRAY_CONFIG` | Path to an Xray JSON fixture |
| `NO_E2E_XRAY_LISTENER` | Optional `127.0.0.1:port` listener to probe |

Use only private ranges (for example `10.x.y.z/NN` placeholder CIDRs); never
commit real endpoints, keys, or URIs. Fixture values must live outside the
repository.

## Commands

```bash
# compile only (default `cargo test` never runs the mutating scenarios)
cargo test -p net-manager-core --test windows_e2e --no-run

# run on the fixture VM, elevated:
cargo test -p net-manager-core --test windows_e2e -- --ignored --test-threads=1
```

The `wireguard_killswitch_is_rejected_by_fixture_guard` test is not ignored —
it only verifies that the `/0` fixture guard refuses to connect, using a
temporary synthetic config.

## macOS privileged helper — manual QA (stage 1)

Automated: `cargo test -p network-orchestrator-macos-helper` (framing, hello,
peer policy, socket binding) and `cargo test -p net-manager-core helper_client`.
These never touch routes, interfaces or DNS and never install anything.

Manual, on a dev Mac (installs a launchd daemon; remove it afterwards):

1. `scripts/macos-dev.sh build`, open `target/macos/Network Orchestrator.app`.
2. Settings → Privileged helper → Install. Approve in System Settings → Login
   Items. The badge changes to Running with the helper version.
3. `sudo launchctl print system/com.netmanager.app.helper` shows the job;
   `/var/run/network-orchestrator/helper.sock` exists with mode 0666.
4. A foreign process is refused: `python3` connecting to the socket and sending
   `hello` receives `notAuthorized`.
5. Remove in Settings. The job and the socket disappear.

Local ad-hoc builds may need the app run from `/Applications` for launchd to
accept the bundle; that is expected until Developer ID signing is in place.
