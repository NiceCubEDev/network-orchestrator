# Platform support matrix

Which features work on which OS, and where the branch lives in code.
Update this when a capability flag or a `cfg!(…)` branch is added.

Legend: ✅ supported · ⚠️ a generic code path exists but has never been
built or tested on that OS · ❌ no code path · — not applicable.

Sources of truth:
- `get_platform_capabilities` → `src-tauri/src/commands/system.rs`
  (`PlatformCapabilities`, surfaced to the UI as `caps` via
  `usePlatformCapabilities()`)
- Linux delegates these flags to `crates/engine/src/linux_system.rs`; both
  frontends use the same services rather than independent GUI implementations.
- `#[cfg(target_os = …)]` blocks in `crates/core` and `crates/daemon`
- `caps.os === "linux"` / `caps.appUpdates` gates in `src/`

macOS is served by the **native SwiftUI client** (`macos/`, Rust core via
`crates/macos-bridge`), not by the Tauri shell. The macOS column describes
that client. Without a privileged helper it runs only user-level operations:
profiles, import, analysis, read-only network inventory, Xray in loopback
SOCKS/HTTP mode and the per-user system proxy. Everything that needs root
(so far only Xray TUN is implemented) goes through the launchd helper
(`docs/plans/2026-09-30-14-macos-privileged-helper.md`). Android and iOS are out of scope entirely.

## Backends

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| Several tunnels at once (primary + secondary by network) | — | ✅ WireGuard, OpenVPN, Xray TUN (daemon-enforced; split DNS via systemd-resolved) | ✅ Xray, WireGuard, OpenVPN | macOS: one primary connection, secondary ones carry only listed networks — `docs/plans/2026-10-14-18-macos-multi-tunnel.md` |
| NetBird | ✅ installed Windows service (mock-tested; live connection acceptance pending) | ✅ via the user's own daemon (unverified against a live daemon) | ✅ via the user's own daemon | `net_manager_core::netbird` shared by the clients; Windows: trusted installed CLI over its named pipe; Linux: Profiles → Services row; macOS: status/up/down through the NetBird CLI, SSO or setup key — `docs/plans/2026-10-14-18-macos-multi-tunnel.md` |
| WireGuard profile | ✅ | ✅ | ✅ helper, arm64 | Win: embedded tunnel lib + service install; Linux: `wireguard-tools` + daemon; macOS: userspace engine (`boringtun`) inside the privileged helper — `docs/plans/2026-10-14-17-macos-wireguard-openvpn.md` |
| OpenVPN profile | ✅ | ✅ | ✅ helper, arm64 | Win/Linux as before; macOS: pinned self-contained OpenVPN from the app bundle run by the helper, routes/DNS installed by the helper, credentials in the Keychain |
| Xray — SOCKS mode | ✅ | ✅ | ✅ native, arm64 | macOS: the shared unprivileged Engine runtime owner runs managed Xray for both GUI and CLI |
| Xray — TUN mode | ⚠️ managed interface + app-owned routes; native traffic acceptance pending | ✅ managed | ✅ helper, arm64 | Win: pinned Wintun, explicit physical uplink, IPv4/IPv6 capture through `PolicyManager`; new imports use TUN and older stored modes are preserved. Linux: daemon generates config (`xrayMode: "tun"` default); macOS: the launchd helper creates the `utun`, hands its fd to Xray (`XRAY_TUN_FD`, Xray runs as the console user) and owns routes + DNS — `docs/plans/2026-10-14-16-macos-xray-tun.md`; one tunnel at a time |
| Managed Xray TUN dual-stack capture | — | ✅ IPv4 + IPv6 | — | Linux primary defaults and four split-default halves; explicit/secondary scope preserved, captured-family FakeDNS, `/32` + `/128` ownership/recovery; requires daemon `xray.tun.ipv6` |
| Xray backup nodes and pinned domain egress | — | ✅ app + CLI | — | One TUN, ordered HTTPS-probed backups with automatic primary return; pinned domains fail closed, including when a subscription node disappears |
| Xray filtered pools and actual exit countries | — | ✅ app + CLI | — | Opt-in country/name filters, bounded candidate probes, explicit primary/backups/domain/DNS nodes excluded from automatic recruitment |
| Standalone Xray policy migration | — | ✅ app + CLI | — | Stopped-profile preview/apply; representable routing/DNS/runtime settings, atomic refusal of unsupported semantics; wrapper listeners excluded |
| Xray underlay/stall watchdog and QUIC rejection | — | ✅ daemon | — | Owned-child recovery, gateway/OIF/source migration, DNS/HTTPS/socket diagnostics; tunnel-scoped nftables UDP/443 REJECT |
| Static routes (`none`) | ✅ | ✅ | ✅ helper | Policy routes only, no tunnel; route mutation is IP Helper / netlink; macOS: the profile's routes are a routing intent `static-<id>` kept by the helper (armed while the interface is absent when "wait for the interface" is on); routes with their own gateway are not supported yet |
| Managed Xray install | ✅ x86_64 only | ✅ x86_64 only | ✅ arm64, download or local zip | `managedXrayInstall`; fixed-version, hash-pinned download. Win: app-local store; Linux: archive goes to the daemon (`xray.install`), which re-verifies hashes and installs root-owned files under `/usr/lib/network-orchestrator/xray`; macOS: per-user managed root |
| WireGuard standard `.conf` import | ✅ | — | — | `wireguardStandardImport` |

## System integration

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| Privileged ops | ✅ elevated relaunch | ✅ daemon | ✅ Xray TUN, WireGuard, OpenVPN | Win: `elevationRelaunch` respawn; Linux: `net-manager-daemon` (systemd + polkit + Unix socket); macOS: launchd helper (`SMAppService.daemon`) verifies the app and runs the Xray TUN, WireGuard and OpenVPN executors (utun, routes, DNS, journal); static-route profiles and routing intents run as intents in the helper (`docs/plans/2026-10-27-20-macos-route-intents.md`) |
| Ask for admin password (polkit policy) | — | ✅ | — | `get/set_vpn_auth_mode`; Settings → System |
| Always-on before sign-in | — | ✅ | — | WG + static routes only; daemon journal; OVPN/Xray unsupported |
| Start at login | — | ✅ | — | `get/set_login_autostart` |
| Conditional routes | — | ✅ | — | `CondRules` UI; condition = interface address in prefix; applied via daemon |
| External attach + endpoint bypass | — | ✅ | ❌ | `routes.apply` `attach` spec binds routes to an interface *name* (deferred while absent, rebinds on new ifindex); `/32`/`/128` endpoint bypasses pin to the physical default gateway, metric 50; reconcile re-asserts |
| NetworkManager VPN inventory | — | ✅ | ❌ | `nm.list`/`nm.setActive` via the daemon over system D-Bus; NM owns credentials, lifecycle and pushed DNS |
| Kernel route/rule inventory | — | ✅ | ❌ | `net.tables` via the daemon's rtnetlink: every table + all policy rules (`ip route`/`ip rule` equivalent); read-only, daemon-owned rows flagged by RTPROT |
| Tailscale service row | — | ✅ | ✅ via the user's own daemon | `tailscaled` proxied through the daemon's LocalAPI client; surfaced under Profiles → Services; macOS: status/up/down through the Tailscale CLI plus the helper's `tailscale.protect` guard (tailnet prefix pins and bypass routes for Tailscale's own traffic next to a primary tunnel) — `docs/plans/2026-10-20-macos-tailscale.md` |
| System proxy toggle | ✅ | ⚠️ GNOME via `gsettings`, KDE via `kwriteconfig`; other desktops hidden | ✅ `networksetup`, hardware services; ignored while a packet-tunnel VPN is primary | Win: registry; macOS: `system_proxy::macos::MacProxyAdapter`; Linux: `system_proxy::linux` — `GnomeProxyAdapter` (`org.gnome.system.proxy`) or `KdeProxyAdapter` (`kioslaverc`), offered only when one is usable |
| Command line (`netorch`) | ❌ | ✅ full Linux business-operation surface | ✅ native GUI business-operation surface | Linux: standalone CLI and optional GUI share typed services, credentials and daemon event subscriptions. System connections outlive clients without a keeper; `serve` is only for local proxies. `watch`, `diagnose` and explicit `recover --cleanup` complement shared commands; cleanup disconnects current-user sessions and pauses always-on. macOS: shared typed Engine services and one unprivileged runtime per data directory; system mutations remain helper-only — `macos/README.md`. Cross-platform target: root `ARCHITECTURE_CONTRACT.md` |
| In-app updater | ✅ | — | ❌ | `appUpdates` is `windows`-only; Linux ships `.deb`/`.rpm`/AUR → package manager |
| Per-link DNS | — | ✅ | — | `crates/daemon/src/dns.rs`, systemd-resolved; Windows relies on pushed/adapter DNS |
| Recovery prompt (leftover resources) | ✅ | ✅ | ✅ | Win: orphaned adapters/routes; Linux: stale daemon owners; macOS: the helper undoes a dead tunnel's routes/DNS on its own start; at launch the app lists what it still records for a tunnel that is not running (or a stale system proxy) and `recovery.cleanup` clears it on request, a running tunnel is never touched |
| App mode (orchestrator/manager/combined) | ✅ | ✅ | ✅ shared GUI + CLI state | UI capability filter in Settings → Profiles; `orchestrator` hides managed backend creation/connect, `manager` hides external orchestration; the native client and `netorch mode` use the same policy |

## Observability

Windows and Linux share these tabs. The native macOS client reads
interfaces and routes through `getifaddrs`/`net-route` (read-only) and has
its own route lookup and exit-IP check on Home, and a Monitor page (tunnel
throughput chart and per-tunnel rates from the interface byte counters); a Logs
page (app events, per-connection, helper, NetBird and import logs with level/text filters) a
per-connection Diagnostics report (`core::diagnostics`) and a DNS tab on Network
(system resolvers from `scutil --dns`, a one-off query with its route).

| Feature | Where |
|---|---|
| Interfaces, addresses, throughput rates | Network tab, `get_interfaces` |
| Exit-IP check per profile | Monitor tab, `ExitIpPanel` |
| Route map / tree / table / lookup / flow | Routes tab, `get_route_map`, `lookup_destination` |
| Per-endpoint delay measurement | Profiles → detail, `measure_subscription_endpoint_delay` (Xray spawn) |
| Diagnostics report | Profile → Diagnostics, `diagnose_profile` |
| App + daemon logs | Logs tab |

## Profiles & subscriptions (identical on both)

- Multiple profiles may run simultaneously. Linux Sets use protected shared
  `connection-sets.json` with insert-only browser migration; Windows retains
  localStorage `netmanager.connections.snippets`. Linux CLI and GUI share capture,
  apply, credential preflight, rollback and partial teardown reporting.
- Subscription profiles: multi-endpoint list, per-endpoint delay,
  refresh interval, traffic quota display.
- Windows subscription import offers a user-triggered stable HWID derived from
  the machine identifier without revealing it. Missing-HWID and device-limit
  response headers produce distinct errors; a new HWID can count as another
  device at the provider. External interface rows are read-only on Windows;
  supported NetBird controls live in the separate service row.
- Import: URI/file batch import (`ImportModal`); standard WireGuard `.conf`
  import on all three clients.
- Home (Linux Tauri and macOS): last-profile reconnect, running connections,
  copy `HTTP(S)_PROXY`/`ALL_PROXY` for the terminal. Opening a browser
  through a connection is macOS-only and is deliberately not ported.
- Domain/IP policies per profile (`block`/`proxy`/`direct`) — both OSes;
  conditional rules are Linux-only (see above).
- On macOS profile CRUD, subscriptions, sets and import are implemented and
  covered by the Swift/Rust tests.

## Deliberately absent

- Kill switch / lockdown mode — not implemented.
- Per-app split tunneling — not implemented.
- Android, iOS — out of scope, no port.

Notes:
- Every ✅ in this matrix should stay honest: when a row drifts, fix the
  code gate (`PlatformCapabilities` / `cfg!`) and this table together.
