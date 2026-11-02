# Changelog: Core

`net-manager-core` and `net-manager-engine`: the logic every product shares (models, static analysis, import, subscriptions, route planning, the daemon protocol, connection engines). Products ship a specific core version; their changelogs say which.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

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


