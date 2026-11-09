# Changelog: Linux

The Linux app, the network daemon and `netorch` for Linux (they are versioned together; the packages are separate, see `docs/versioning.md`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- `versions.py prepare` automates release metadata, changelog promotion, lockfile
  refresh and the host quality gate, with a no-write preview and a project skill.

## [0.16.3] - 2026-11-09

Core 0.16.1.

### Fixed

- Associate NetBird and Tailscale service rows with their tunnel interfaces by
  reported addresses, showing the interface names without duplicate external
  rows. Keep unrelated tunnels and interfaces with unknown ownership visible.

## [0.16.2] - 2026-11-08

Core 0.16.1.

### Changed

- Open directly to Profiles and remove the redundant Home dashboard and its
  navigation shortcuts. Connection controls remain in Profiles and the tray.

## [0.16.1] - 2026-11-08

Core 0.16.1.

### Changed

- Default VPN authorization to `noPrompt` for installations without saved
  daemon settings. Active local sessions can connect full and split tunnels
  without a password; existing administrator-selected modes and system-network
  authorization are unchanged. Invalid settings still require a password.

## [0.16.0] - 2026-11-08

Core 0.16.0.

### Added

- Headless `netorch watch` JSONL snapshots, `diagnose` findings and explicit
  `recover` reporting/`recover --cleanup` for current-user resource teardown.
- Disposable CLI-first acceptance covering the native GUI, daemon lifetime,
  foreground signals, real local Xray and user-proxy crash recovery.

### Changed

- System daemon connections now outlive all CLI/GUI clients without a
  `netorch serve` keeper. Explicit disconnect, backend shutdown and recovery
  still clean owned resources. The user runtime is needed only for local
  Xray SOCKS/HTTP and user proxy supervision.
- GUI and CLI share bounded daemon event subscriptions; reconnect and event gaps
  refresh snapshots, while unavailable status is never cached as running.
- JSON-mode usage and operation failures have structured stderr and stable
  exit codes (2 and 1 respectively).

### Fixed

- Restore saved proxy settings when the user runtime restarts after failure;
  persist global ownership outside the session directory so another data root
  cannot adopt an unrestored proxy after logout or reboot.
- Roll back daemon-owned routes as well as local Xray when a mixed connection's
  route-apply reply is lost or malformed; preserve both cleanup errors.
- Reject stale GUI profile/config-form saves after CLI edits instead of
  overwriting newer names, routes or subscription settings.
- Allow explicit disconnect after local Xray dies and proxy rollback completes,
  rather than leaving a failed session that cannot be cleared.
- Release proxy ownership immediately even when another thread has forked a child
  that has not yet executed its program.
- Avoid repeated full-buffer scans while receiving daemon events, including
  oversized frames that must be rejected without exposing their contents.

## [0.15.1] - 2026-11-08

Core 0.15.1.

### Fixed

- Show the connected NetBird service when it uses a per-profile daemon socket.
- Exclude NetworkManager's external-device placeholders (including NetBird's
  `wt0`) from controllable VPN/WireGuard profiles; keep NM-managed connections.

## [0.15.0] - 2026-11-07

Core 0.15.0.

### Added

- CLI access to Linux profile settings, subscriptions, network routes/rules and
  DNS, provider services, always-on and conditional routing, diagnostics, logs,
  backend management and saved connection sets through shared Engine services.
- Dual-stack Linux Xray TUN capture, IPv6-only scoped routes, IPv6 tunnel
  addresses and negotiated daemon capability checks before network mutations.
- Shared protected connection sets with legacy GUI migration and explicit,
  per-profile OpenVPN credential input for interactive and CLI application.

### Changed

- Linux GUI commands use the same business operations as the CLI rather than a
  separate in-process tunnel/settings implementation.
- Connection-set and subscription endpoint changes validate retained connection
  inputs before teardown and restore previously running connections on failure;
  failed resources are cleaned without being restored as healthy connections.

### Fixed

- Scope fake-DNS pools to captured address families and route coverage; avoid
  claiming IPv4 default capture for explicit IPv6-only scopes.
- Preserve concurrent named-exit changes and cached subscription HWIDs.
- Keep remembered OpenVPN credentials unchanged after failed/unconfirmed
  connection attempts and protect unknown-status/always-on resources.

## [0.14.0] - 2026-11-07

Core 0.14.0.

### Added

- Shared unprivileged `netorch serve` user service for local Xray SOCKS/HTTP
  children and detached daemon connection lifetime. CLI and GUI control the
  same runtime; closing the window does not terminate it.
- Raw Xray JSON import in the CLI, defaulting to unprivileged SOCKS mode.
- Arch/CachyOS packages include GUI, CLI, daemon, pinned Xray, shell completions
  and tmpfiles configuration; Debian GUI installers also include the CLI runtime.

### Changed

- Linux CLI and GUI use one connection engine, data-directory convention,
  OpenVPN credential store and geodata preparation. CLI profile changes refresh
  the open GUI. OS file locks protect cross-process profile edits.
- Replace per-profile CLI keeper processes with the shared user service.
  A systemd user manager (or foreground `netorch serve`) is required; retaining
  user units across logout requires explicit linger configuration.
- Root connects require foreground mode. Foreground terminal hangup disconnects
  instead of leaving a shared connection running.

### Fixed

- Show a ready Xray executable with an unknown version as ready, not absent.
- Update vulnerable frontend build dependencies within compatible ranges.
- Preserve automatic installation marks when upgrading shared daemon/CLI dependencies.

## [0.13.1] - 2026-11-03

Core 0.13.0.

### Fixed

- Accept geosite category names containing `!` (for example,
  `category-ai-chat-!cn`) at the daemon boundary, matching generated profile
  rules. External asset selectors and path traversal remain rejected.

## [0.13.0] - 2026-11-03

Core 0.13.0.

### Added

- `netorch proxy set|list|remove` and `netorch proxy [--profile PROFILE] NAME --
  COMMAND` for user-defined rules/node/pool/direct exits of a connected Xray
  TUN profile. Configuration is offline; launches verify actual daemon bindings
  and never start/reload the tunnel. Stale exits refuse before execution.
- Independent ordered pool controllers with fail-closed missing/all-down
  members, and marked direct sockets that bypass the owned TUN. Commands retain
  literal arguments, terminal, native signals and exit status through `exec`;
  inherited HTTP/SOCKS proxy and no-proxy variables are replaced.
- Disposable real-CLI coverage of full-TUN direct bypass, pool affinity and
  isolation, failed exits, explicit bypass exceptions, command lifetime and
  listener cleanup. Loopback listeners remain unauthenticated; environment
  proxies are not process network isolation or arbitrary UDP routing.

## [0.12.0] - 2026-11-02

Core 0.12.0.

### Added

- `netorch checks list|add|remove|background|run` and a per-profile service
  availability editor. Users supply the HTTPS targets and explicit node pins;
  opening or saving the editor sends no service request.
- Opt-in diagnostic-only checks every 60 seconds while a TUN profile is active.
  Any HTTP response is transport evidence, not authenticated API success.
  Results and transition logs omit URLs; disabling/removing checks cancels the
  worker without reloading Xray, changing pins or selecting a fallback.

### Changed

- Stop inferring pinned service targets from routing domains and remove
  pin-specific restart requests. Global tunnel/failover health and underlay
  recovery remain separate from service-specific availability.

## [0.11.0] - 2026-11-02

Core 0.11.0.

### Added

- Xray subscription profiles can select ordered backup nodes and pin domain
  selectors to independent nodes from the app or `netorch backup` and
  `netorch route pin|unpin`. The daemon uses bounded HTTPS probes per node,
  prefers the primary and automatically returns after recovery. Missing pins
  stay fail-closed; all-down default traffic is blocked, never sent direct.
  Live status includes the selected node and candidate health.
- Opt-in filtered backup pools and real exit-country verification in the app
  and CLI. Country-only filters are supported; explicit domain/DNS nodes are
  excluded from automatic recruitment, and name-only mode does not need Xray.
- Stopped-profile preview/apply of standalone Xray policies, including fixed
  egress, DNS rewriting, IP/port guards, interface policies, TUN MTU/DNS and
  connection/socket settings. Unsupported semantics and conflicting pins
  refuse the whole import; ordinary profile edits preserve imported settings.
- Owned-child recovery for real underlay changes, HTTPS/pin stalls and UDP
  socket accumulation, with DNS and application connection-storm diagnostics.
  Unchanged DHCP identity preserves live streams; recovery waits while offline.
- Tunnel-scoped nftables QUIC rejection with ownership-safe cleanup.
- Single-file Debian/Ubuntu installers for CLI and GUI, each bundling its client
  and the shared daemon package. They install missing packages, update older
  versions, preserve a newer daemon patch from the same release line, and refuse
  client downgrades. `--check` previews the version plan without root or changes;
  `--yes` accepts the APT plan. A CLI-only build avoids the GUI/WebKit toolchain.

### Changed

- Linux Xray is pinned to 26.10.31 for DNS rewriting. Bundled GeoIP Lite and
  GeoSite Standard replace the old data set; explicit geodata overrides remain
  supported, and package notices describe the current data licenses.

### Fixed

- Endpoint bypasses migrate from an existing old gateway/interface without
  adopting foreign routes. Recovery acknowledges replaced children, cancels
  positively cleared queued stalls and does not charge a crash against the
  independent stall cooldown.
- Orphan cleanup verifies protected process ownership independently of the
  current Xray pin, including a deleted executable from an older package.

## [0.10.1] - 2026-10-30

Core 0.10.0.

### Added

- `netorch route` manages the routing rules of Xray profiles from the terminal:
  `show` lists them, `add` and `rm` change single selectors, `set` replaces
  all of them, and `check <host or IP> --profile <profile>` tells which rule
  decides it. Selectors are `domain:`, `full:`, `geosite:`, `geoip:`, an address
  or a CIDR network. A bare name such as `ru` is a substring match in Xray, and
  the command says so. A connected profile applies the change when it
  reconnects.
- `netorch version` also shows the core version the build includes.

### Changed

- The Linux `.deb` is split into three packages that share this line's
  version: `network-orchestrator-daemon` (the daemon, its systemd unit, the
  polkit policy and the pinned Xray), `netorch` (the command line client, with
  bash, zsh and fish completions) and `network-orchestrator` (the app). The
  app and `netorch` depend on a daemon of their own `major.minor` or newer, so
  installing either keeps a suitable daemon as it is and installs or upgrades
  an unsuitable one; the former single package is replaced
  (`Replaces`/`Breaks`, including version 0.10.0). A server needs only the
  daemon and `netorch`:
  `apt install ./network-orchestrator-daemon_*.deb ./netorch_*.deb`.
  `.rpm` and Arch packages are still one package.

### Fixed

- For supported TCP/raw, Hysteria and KCP transports, a system-wide Xray tunnel
  no longer stops carrying traffic when its server is given by name. The daemon
  now resolves the name before the tunnel comes up and has Xray dial the IP
  (the name stays the TLS/Reality server name), so a
  reconnect no longer needs the resolver that points into the tunnel. Because
  the server no longer has to be looked up, the DNS servers are not routed
  around the tunnel any more: on networks that drop DNS to outside resolvers
  the profile's DNS now works through the tunnel.
