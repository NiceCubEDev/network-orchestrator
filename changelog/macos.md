# Changelog: macOS

The native macOS app, its privileged helper, the JSON bridge and `netorch` for macOS (they are versioned together).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.10.2] - 2026-11-03

Core 0.13.0.

### Changed

- Keep shared Xray request, status and ownership models compatible with named
  proxy preferences. The macOS helper explicitly rejects Linux-only named
  process exits instead of silently accepting unsupported settings.

## [0.10.1] - 2026-11-02

Core 0.12.0.

### Fixed

- Keep shared Xray request and ownership constructors complete after the
  protocol/model extensions.

### Changed

- Refresh the shared localization catalog. Service-availability configuration
  and background diagnostics remain Linux-only.

