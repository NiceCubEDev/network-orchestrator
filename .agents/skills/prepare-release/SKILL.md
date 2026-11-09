---
name: prepare-release
description: >-
  Use when preparing a Network Orchestrator release, bumping core/macOS/Linux/Windows
  versions, or creating chore(release) commits. Uses scripts/versions.py prepare to
  synchronize versions, promote changelog notes, refresh Cargo.lock and run checks.
---

# Prepare a Network Orchestrator release

`versions.toml` is the only version source. This skill is project-specific.
Do not prepare a release merely because the user requested a feature or this script.

## Before preparing

1. Read `docs/versioning.md` and `versions.toml`. Determine the requested release
   lines and target SemVer values; do not reuse example versions or bump unrelated
   platforms. A core release does not automatically release every product.
2. Ensure each selected `changelog/<line>.md` has meaningful notes under
   `## [Unreleased]`. Commit the completed feature/fix and its notes first. The
   apply command requires a clean Git worktree; never stash someone else's work
   or reset files automatically to satisfy that requirement.
3. Use a host with Git, Python 3, Cargo (rustfmt and Clippy), npm and project build
   prerequisites installed. Dependencies must already be available (`npm ci`,
   `cargo fetch` as appropriate). Do not run as root. In a container, make the
   worktree's Git common directory accessible as well as the checkout.

## Preview, then apply

Set `NEXT_LINUX` and `NEXT_WINDOWS` to the selected target versions. These commands
show a two-line release; omit arguments for lines that are not being released.

```bash
python3 scripts/versions.py prepare "linux=$NEXT_LINUX" "windows=$NEXT_WINDOWS" --dry-run
python3 scripts/versions.py prepare "linux=$NEXT_LINUX" "windows=$NEXT_WINDOWS"
```

Prefer one line per invocation when producing independent release commits.
For a coordinated core/product update, pass all selected versions together so
product changelogs record the new core version.

The command validates every selected line before writing, synchronizes the
manifests/configs, moves Unreleased notes into dated sections, updates Cargo.lock
through Cargo, and runs the repository quality gate. Dry-run performs no writes
or subprocess checks. Existing history and unselected release lines are retained.
Do not manually edit generated version fields or Cargo.lock.

## Failure and verification

- Invalid/non-increasing versions, existing release sections and missing notes
  abort before metadata edits. Actual apply also rejects a dirty checkout or
  missing required tools.
- A failed quality command stops preparation with a nonzero exit. Review the
  retained uncommitted edits, fix the actual failure and run the failed and
  remaining quality-gate commands from `AGENTS.md`; do not call the release ready.
  Do not rerun prepare with the same version or erase the release edits blindly.
- The gate checks the current host. Non-macOS hosts exclude native macOS crates;
  Linux success does not establish native macOS or Windows parity. Run required
  native validation before shipping the corresponding product.

## Git and delivery

The script never commits, tags, pushes, builds installer packages or installs an
application. Perform those actions only when requested.

When commits are requested, use the commit skill. Keep feature/fix commits separate
from `chore(release): <line> X.Y.Z`. For a multi-line preparation, stage each line's
version/changelog/config changes separately, including the corresponding hunk in
`versions.toml` and any Cargo.lock changes. Merge through the repository workflow;
release tags belong on main, and main must not be pushed directly.

Report selected source versions, exercised checks, and any native-platform limits.
A prepared or committed version is not the version installed on the user's system.
