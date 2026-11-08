# Changelog: Core

`net-manager-core` and `net-manager-engine`: the logic every product shares (models, static analysis, import, subscriptions, route planning, the daemon protocol, connection engines). Products ship a specific core version; their changelogs say which.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- Bounded Linux daemon event subscriptions shared by CLI and GUI, preserving
  partial frames across read timeouts and handling events during subscription.

### Fixed

- Keep in-memory system-proxy ownership when persisting the restored state fails,
  allowing a safe retry without losing the saved snapshot.
- Recover Linux user-proxy ownership under a persistent per-user lock and restore
  it before accepting new runtime commands.
- Compare whole-profile GUI replacements against an opaque canonical revision
  under the store lock; reject stale edits without losing concurrent narrow
  changes or hidden subscription metadata.
- Disconnect already-exited or health-reaped Xray/OpenVPN children cleanly,
  clearing their failure state; retain live child ownership if kill/reap fails.

## [0.14.0] - 2026-11-07

### Added

- Shared Linux connection engine for static routes, WireGuard, OpenVPN, Xray TUN
  and local proxies; unprivileged per-data-directory runtime coordination keeps
  privileged mutations in the calling client and system daemon.
- Common Linux data paths, protected OpenVPN credential storage and bounded
  geodata preparation for both frontends.

### Fixed

- Serialize independent profile-store writers with an OS file lock; preserve
  concurrent narrow profile edits and routing-selector additions.
- Preserve concurrent metadata edits when rewriting generated listener ports.

## [0.13.0] - 2026-11-03

### Added

- Strict data-only named proxy exit preferences: profile rules, a fixed
  subscription endpoint, an ordered pool, or direct, with explicit no-proxy
  exceptions and protected profile validation. Missing endpoint keys generate
  blackholes, not replacements; named nodes are excluded from automatic main
  pool recruitment without removing explicit primaries/manual backups.
- Linux connection plans carry dedicated named pin outbounds; the daemon
  protocol reports live bindings and per-pool health without subscription
  credentials or executable configuration.

## [0.12.0] - 2026-11-02

### Added

- Persisted user-owned HTTPS service-check specifications with empty/off defaults,
  protected profile validation and URL-redacted debug output. Bounded manual HEAD
  probes use only the current explicitly pinned subscription endpoint, never
  routing-derived targets, redirects, credentials or direct fallback.
- Typed, URL-free HTTP/timeout/TLS/transport/unavailable observations and a
  three-failure diagnostic streak, independent of tunnel recovery.

### Changed

- Replace inferred pinned-path status with explicit `serviceChecks` readings.
  Subscription refresh and ordinary profile edits retain service-check settings.

## [0.11.0] - 2026-11-02

### Added

- Secret-safe subscription endpoint keys, persisted backup references and
  pinned domain policies survive list reordering and credential rotation.
  Linux engine generation and the daemon protocol carry bounded multinode
  failover configuration and live node health.
- Typed advanced Xray routing/DNS/runtime settings and strict standalone-policy
  migration, with shared validation before generation, apply and persistence.
- Bounded exit-country probing and opt-in pool selection. Retained pools are
  sanitized against explicit choices, capacity and fresh country mismatches;
  disabled or newly pinned members cannot silently join default failover.

### Fixed

- Temporary delay and country probes wait for their Xray child to be killed
  and reaped before returning success, failure or timeout; cancellation retains
  the kill-on-drop guard.


