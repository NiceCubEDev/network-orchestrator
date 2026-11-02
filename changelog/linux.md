# Changelog: Linux

The Linux app, the network daemon and `netorch` for Linux (they are versioned together; the packages are separate, see `docs/versioning.md`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

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
