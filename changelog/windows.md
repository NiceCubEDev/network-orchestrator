# Changelog: Windows

The Windows app.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

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

