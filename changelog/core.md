# Changelog: Core

`net-manager-core` and `net-manager-engine`: the logic every product shares (models, static analysis, import, subscriptions, route planning, the daemon protocol, connection engines). Products ship a specific core version; their changelogs say which.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

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


