# Versioning and releases

## Release lines

There is no single version of "the app". The core and each operating system
have their own, and all of them follow [Semantic Versioning 2.0.0](https://semver.org/):

| Line | What it versions | Crates and artifacts |
| --- | --- | --- |
| `core` | the shared logic | `net-manager-core`, `net-manager-engine` |
| `macos` | the macOS app and `netorch` for macOS | `macos/`, `net-manager-macos-bridge`, `network-orchestrator-macos-helper`, `crates/cli` built for macOS |
| `linux` | the Linux app, the network daemon and `netorch` for Linux | `net-manager-app` built for Linux, `network-orchestrator-daemon`, `crates/cli` built for Linux, the packages |
| `windows` | the Windows app | `net-manager-app` built for Windows |

The only source of truth is [`versions.toml`](../versions.toml). Never edit a
version by hand elsewhere:

```bash
python3 scripts/versions.py get linux          # print a version
python3 scripts/versions.py prepare linux=0.16.4 --dry-run  # preview a release
python3 scripts/versions.py prepare linux=0.16.4            # update and run checks
python3 scripts/versions.py check              # fail if anything drifted (part of the quality gate)
python3 scripts/versions.py affected main...HEAD   # which lines a branch touches
```

Use `prepare` for releases. `set` and `sync` remain low-level synchronization
commands; they do not prepare changelogs, refresh Cargo.lock or run the gate.

`sync` writes the version into the `Cargo.toml` of every crate that belongs to
one line and into `src-tauri/tauri.<linux|windows>.conf.json`, which Tauri
merges into its config so each platform's bundle carries its own version.
`crates/cli` and `src-tauri` are built for two lines each; their `Cargo.toml`
says `0.0.0` and the build script (`build-support/product_version.rs`) puts the
version of the target operating system into `NETORCH_VERSION`.

Before 0.10.0 the project had one version for everything; that history is in
[`CHANGELOG.md`](../CHANGELOG.md). All four lines start at 0.10.0.

### Which line changes

A change belongs to the lines whose code it alters (`affected` prints them):

- logic in `crates/core` or `crates/engine` is a **core** change. A product
  ships a specific core version and says which in its changelog; a core
  release does not force every product to release;
- the helper, the bridge, the Swift client: **macos**;
- the daemon, `packaging/`, `crates/cli/src/linux`: **linux**;
- `src-tauri` and the frontend serve **linux** and **windows**;
- the shared locales and design tokens touch every product.

## What is breaking

The apps have no public API, so "breaking" is defined by what users and their
data depend on. A change is **breaking (MAJOR)** for a line when, after
updating, a user must do something or loses something:

- stored data (profiles, vault, settings, journal) cannot be read by the new
  version without a manual step, or cannot be migrated automatically;
- a feature, platform, backend, protocol or setting is removed, or its
  behavior changes so existing profiles, routing rules or `netorch`
  commands/flags/`--json` output stop working as before;
- the app, `netorch`, the privileged helper or the daemon stop being compatible
  with each other (`PROTOCOL_VERSION` break) so a partial update leaves a broken
  install;
- the minimum supported OS version is raised.

Internal refactors, UI redesigns, new options and anything migrated
automatically are not breaking.

| Change | Commit | Bump |
| --- | --- | --- |
| Bug fix, security fix, performance improvement | `fix`, `perf` | PATCH |
| New user-visible feature, platform or backend | `feat` | MINOR |
| Breaking change | `feat!`/`fix!` or `BREAKING CHANGE:` footer | MAJOR |
| `docs`, `chore`, `style`, `refactor`, `test`, `ci`, `build` | — | none by themselves |

While a line is `0.y.z`, breaking changes bump MINOR instead of MAJOR, and
`docs`/`build`/`test` changes that ship in a release are covered by a PATCH
bump.

Document format versions (`PROFILE_DOCUMENT_VERSION`, `JOURNAL_VERSION`,
`PROTOCOL_VERSION`, …) and pinned backend versions (`MANAGED_XRAY_VERSION`) are
independent of every line. Changing one of them is a reason to bump the lines
that ship it, not a replacement for it.

Pre-release builds may use SemVer suffixes such as `0.11.0-beta.1`.

## Compatibility between parts

Parts of one operating system are separate packages and can be updated apart
(on Linux: the daemon, the app, `netorch`), so a client checks the daemon
before it calls it (`net_manager_engine::linux_compat`, `netorch version`):

- the wire protocol (`PROTOCOL_VERSION`) must be the same, otherwise the
  client refuses and says which side to update;
- the daemon must list every method the client calls in its handshake
  (`capabilities`), otherwise the client refuses;
- a daemon from an older `major.minor` than the client only warns.

When a client starts to depend on something new in the daemon, raise the
client's minimum through a new method in `REQUIRED_METHODS` (or a protocol
bump for an incompatible change) and give the packages a matching dependency.

## Packages

Each operating system ships separate packages for the daemon, the app and
`netorch`, all versioned by that system's line; see
`docs/plans/2026-10-29-version-lines-and-packages.md`.

## Commits

Commit messages follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/),
in English, imperative mood, with a scope where it helps:

```text
<type>(<scope>): <Summary without a trailing period>

<Optional body: why the change is needed and what it affects.>

<Optional footer: BREAKING CHANGE: what breaks and how to migrate.>
```

Types: `feat`, `fix`, `perf`, `docs`, `chore`, `style`, `refactor`, `test`,
`build`, `ci`. A `!` or a `BREAKING CHANGE:` footer marks a breaking change.

Common scopes: `core`, `daemon`, `app`, `ui`, `i18n`, `macos`, `linux`,
`windows`, `xray`, `openvpn`, `wireguard`, `cli`, `e2e`, `packaging`,
`release`. Use `linux`, `macos` or `windows` when the change is specific to one
system; a commit that changes more than one line is fine, but say so in the
body.

Rules:

- Agents never add themselves as co-authors: no `Co-Authored-By` trailer and no
  "Generated with" line in commits or PR descriptions.
- Every commit has a type prefix. Messages like `fix`, `last commit` or
  `Edit foo.rs` are not allowed: tooling that builds the changelog and
  decides the version skips them, so the work would never reach a release.
- One commit is one logical change and one type. Do not mix `feat` and `fix`
  in a single commit; split them.
- A breaking change always carries `!` and/or a `BREAKING CHANGE:` footer that
  says what breaks for the user and how to migrate.
- Run the quality gate from `AGENTS.md` before pushing; a red gate blocks the
  release.
- Releases are cut only from `main`. Work happens on a personal branch and
  reaches `main` through a pull request; never push to `main` directly.
- With **squash** the PR title is the only commit and must carry the type
  prefix; with **merge** or **fast-forward** every commit of the branch is
  read, so each one needs its own prefix.

## Release preparation

A version bump happens after a group of related commits, not in every commit.
The project skill is [prepare-release](../.agents/skills/prepare-release/SKILL.md).

1. Finish and commit the feature/fix and its notes under `## [Unreleased]` in each
   selected `changelog/<line>.md`. Applying a release requires a clean Git
   checkout, Git, Cargo (rustfmt and Clippy), npm and the normal build dependencies.
2. Choose the target SemVer values. Preview one or several release lines without
   writes or subprocess checks, then apply the same selection:

   ```bash
   python3 scripts/versions.py prepare linux=0.16.4 windows=0.10.6 --dry-run
   python3 scripts/versions.py prepare linux=0.16.4 windows=0.10.6
   ```

   All selected lines are validated before writing. Versions must advance;
   missing/empty Unreleased sections and existing release sections are rejected.
   The command synchronizes versions, promotes the notes into dated sections,
   records the selected core version in product changelogs, refreshes Cargo.lock
   through Cargo and runs the repository quality gate. Pass `core=...` in the same
   invocation as product updates when their changelogs should name that new core.
3. Review the changes. The gate validates the current host; non-macOS hosts exclude
   native macOS crates. Native checks for other products remain required before
   shipping them. A failed check returns nonzero and leaves the metadata edits
   uncommitted for inspection; there is no automatic reset, commit, tag or push.
   Fix the failure and run the failed and remaining quality-gate commands from
   `AGENTS.md`. Preparing the same version again is rejected to protect history.
4. Commit only the version/changelog/lockfile changes:
   `chore(release): <line> X.Y.Z`. Keep independent lines in separate commits;
   multi-line preparation may require partial staging of `versions.toml`.
5. Merge through the normal review workflow. Create annotated release tags from
   main only, for example
   `git tag -a linux-v0.16.4 -m "Network Orchestrator Linux 0.16.4"`.

The command does not build installer packages or update an installed application.
Preparation is not publication.

Tags are pushed only together with the release branch after review; never push
directly to `main`. The tags `v0.1.2` … `v0.9.1` belong to the time of a single
version, and `v0.10.0` marks the commit where the lines were separated.
