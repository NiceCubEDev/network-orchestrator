# Changelog: Windows

The Windows app.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- A PowerShell helper for unsigned NSIS packaging with embedded frontend assets
  and temporary output outside the checkout.

- Managed Xray TUN and NetBird controls for internet VPN and private-network use.
- Automatic subscription device IDs, compatible server imports and cancelable
  background server-delay measurements.
- A tray icon with Open, Hide and Exit actions; closing the window keeps owned
  VPN connections running when the tray is available.
- Startup recovery choices for an existing instance, with bounded probing,
  graceful restart and explicit confirmation before forced termination.
- Reuse an already-running managed connection and select a free automatic TUN
  name when a previous adapter still occupies the default name.

### Fixed

- Resolve adapter names correctly when changing their administrative state and
  retain useful netsh errors.
- Report subscription device requirements precisely and keep server delay probes
  from opening console windows.
- Keep the native-icon consistency check independent of Windows line endings.

## [0.10.5] - 2026-11-09

Core 0.16.1.

### Fixed

- Match service-owned tunnel interfaces by reported addresses rather than device
  name prefixes, keeping unrelated external tunnels visible.

## [0.10.4] - 2026-11-08

Core 0.16.1.

### Changed

- Open directly to Profiles and remove the redundant Home dashboard and its
  navigation shortcuts. Connection controls remain in Profiles and the tray.

## [0.10.3] - 2026-11-08

Core 0.16.0.

### Fixed

- Reject stale shared profile-editor saves without overwriting newer settings
  from another client; show a localized reload conflict.
- Retain proxy and child-process ownership when cleanup must be retried.

## [0.10.2] - 2026-11-03

Core 0.13.0.

### Changed

- Preserve opaque named Xray proxy preferences across ordinary shared profile
  edits. Named process proxy execution remains Linux-only.

## [0.10.1] - 2026-11-02

Core 0.12.0.

### Changed

- Update shared profile models, canonical settings preservation and localization
  data for Core 0.12.0. The service-availability UI and background diagnostics
  remain Linux-only.

