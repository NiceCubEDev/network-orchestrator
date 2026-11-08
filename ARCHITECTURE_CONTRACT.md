# CLI-first backend contract

Status: accepted target architecture, 2026-11-08. Linux implementation and
verification are tracked below; this is not a claim of platform parity.
macOS and Windows must be migrated and verified on their native platforms.

## Product boundary

- `netorch` MUST be a complete, independently installable interface. Installing,
  configuring, connecting, observing, diagnosing and disconnecting supported
  backends MUST NOT require a GUI process or GUI-only initialization.
- GUI is OPTIONAL. It MUST use the same typed Rust engine/services and backend
  state as CLI, not invoke CLI commands and parse human-readable output. The
  existing macOS JSON C ABI bridge MAY remain the native GUI adapter.
- CLI MAY also host the unprivileged runtime entry point (`netorch serve`). This
  does not require a separate executable, nor make the CLI invocation the owner
  of a background connection.
- Shared semantics and capabilities are required; identical OS mechanisms are not.
  Unsupported operations MUST return an explicit capability/error, never fake success.

## Responsibilities and trust boundaries

| Component | Owns | MUST NOT own |
| --- | --- | --- |
| CLI / GUI | User interaction, authorization prompts, presentation | Background tunnel lifetime or authoritative runtime state |
| Shared Engine/services | Typed commands, plan derivation, validation, orchestration and rollback | An additional universal coordinator daemon |
| Privileged system backend | Tunnels, routes, interfaces, DNS, resource journal, reconciliation and recovery | Root/SYSTEM execution of user-writable binaries or user desktop proxy state |
| Unprivileged user runtime | Local Xray SOCKS/HTTP children, user proxy settings, child health and proxy rollback | Privileged route/interface/DNS mutations or a keepalive for system connections |

Every backend MUST validate requests at its trust boundary. Privileged requests
MUST authenticate and authorize the actual caller. A user runtime MUST NOT become
an implicitly trusted authorization proxy. Existing approved tunnel launch paths
may execute a verified binary after irreversibly dropping user credentials; the
system backend still owns the privileged tunnel resources.

Local Xray MUST run without root/SYSTEM privileges. User proxy changes MUST use
the appropriate user/session context and restore the prior snapshot on explicit
disconnect or detected child failure. Merely persisting a proxy setting does not
require a background process; supervising its target and restoring it does.
Secrets/config contents MUST NOT appear in events, logs or errors.

## Platform mapping

| Role | Linux | macOS | Windows |
| --- | --- | --- | --- |
| System backend | systemd system service | launchd privileged helper | Windows Service |
| User runtime, on demand | systemd user service | launchd LaunchAgent | Process in the user's interactive session |
| Local IPC | Unix sockets | Existing Unix socket helper protocol; native bridge for GUI | ACL-protected named pipes |
| Authorization | Peer credentials and polkit | Verified caller identity and helper authorization policy | Pipe ACLs, authenticated client tokens and explicit elevation where required |

Runtime isolation MUST include user identity and the selected data-directory /
system-backend endpoint. Production and development instances MUST NOT accidentally
share user proxy/process ownership. No installation may silently enable linger,
autostart or broader privileges to hide session lifetime limitations.

## Connection lifetime

- A successful normal `connect` / `netorch up` MUST create a background connection
  owned by the backend and authenticated user. Existing profile/owner identifiers
  MAY provide identity; no new identifier scheme is required by this contract.
- CLI exit, GUI exit, IPC EOF and death of the last client process MUST NOT
  disconnect a normal system connection, nor require `serve` to keep it alive.
- Explicit `disconnect` / `down` MUST remove the selected connection's owned
  resources. An authorized client can disconnect a connection started by another
  interface of the same user. Cross-user access remains subject to backend policy.
- Foreground mode MUST be explicit: its client requests disconnect on normal exit,
  supported termination signals and terminal hangup. Abrupt uncatchable process
  death MUST NOT be presented as guaranteed cleanup; this slice adds no lease or
  client-death teardown mechanism.
- Backend shutdown/restart MUST retain existing safe journal recovery/cleanup.
  Surviving frontend exit is NOT a promise of uninterrupted service across backend
  restart, logout or machine reboot.
- Reboot autoconnect is an explicit policy (for example always-on), distinct from
  crash recovery and ordinary background connection lifetime.
- User runtime MUST start only when user-level work is needed. It MUST require no
  manual startup in the normal installed flow, and MAY exit when it has no work.
  Local proxies remain bounded by the OS user-session service lifetime unless the
  administrator explicitly configures otherwise.

## State and client API

- Versioned, atomically protected user stores own profiles/settings. Clients MUST
  coordinate edits; neither interface may overwrite another's changes from a stale
  in-memory copy.
- System backend owns observed system connection/resource state. User runtime owns
  observed local proxy/child state. A client cache is never authoritative.
- Clients MUST obtain a current snapshot and consume change events. Reconnection
  or an event gap MUST trigger resynchronization rather than guessed state.
- CLI MUST expose structured JSON, stable exit semantics and a machine-readable
  event stream in addition to human-readable output. Secrets MUST NOT leak through
  either representation. Human-readable wording is not an IPC contract.
- Terminal authentication/secret prompts MUST work without GUI. Noninteractive
  calls MUST fail explicitly when authorization or missing secrets require input.
- Mixed connections (local proxy plus privileged routes) MUST roll back partial
  starts. Each backend MUST journal its own recoverable resources so client death
  mid-operation does not leave untracked changes. An ambiguous mutation response
  MUST NOT be treated as proof that no resources were created.

## Acceptance scenarios

1. Given CLI-only installation, connect a supported profile, exit CLI, then query
   status from a new CLI process: the same connection remains running.
2. Given that connection, open GUI, observe it, exit GUI and query CLI: no teardown.
   Explicitly disconnect from either client: owned resources are released.
3. Given a daemon-only Linux profile and no systemd user manager or sibling
   `netorch` executable, connect through the system backend: no user runtime starts.
4. Given all originating client processes have died, wait beyond the former
   client-death grace period: daemon-owned resources remain; a later authorized
   disconnect still removes them. This does not bypass UID authorization.
5. Given local SOCKS/HTTP Xray, CLI and GUI share one user runtime. When the child
   fails, prior proxy settings are restored without waiting for either UI.
6. Given foreground mode, normal exit/supported signals/hangup explicitly disconnect;
   no claim is made about SIGKILL. Ordinary background mode remains unaffected.
7. Given backend restart or a partially completed start, recovery reconciles known
   resources safely; only explicit autoconnect policy re-establishes connections.
8. Given a missing capability, rejected authorization, IPC loss or unavailable user
   manager, clients report the actual failure and never synthesize Running state.

## Implementation and verification boundary

Linux implements daemon-owned connection lifetime without `ObserveDaemon` /
`retain_connection`, preserving explicit disconnect, recovery, foreground cleanup,
peer identity and polkit. It also provides:

- `netorch watch [PROFILE]`: bounded daemon subscription plus snapshots on initial
  connect, event gaps and reconnect; local child/profile changes are also observed.
- `netorch diagnose [PROFILE]`: read-only capability/configuration/status findings.
- `netorch recover`: read-only owner/proxy recovery report.
- `netorch recover --cleanup`: explicit current-user daemon/local teardown and
  proxy restoration, including orphan resources; always-on is paused. This is
  not a stale-only cleanup and never deletes saved profiles.
- JSONL snapshots and structured JSON errors; CLI success/operation/usage exits
  are respectively 0/1/2. A report containing findings is still a successful report.
- GUI invalidation via the shared daemon event transport, including reconnect and
  resync, with short read-only observation deadlines.
- User-runtime failure restart, startup proxy recovery and a persistent global
  proxy owner marker under XDG state (not an ephemeral session directory).
- Compensating removal of scoped routes after an ambiguous mixed-connect failure,
  with both route and local cleanup errors preserved.
- GUI whole-profile edits capture an opaque revision with the displayed profile
  and compare it under the store file lock when saving. Stale replacements,
  including deleted/recreated profiles, are rejected without losing newer CLI
  edits. Narrow role/network updates operate on the current stored profile.

No Windows Service, macOS LaunchAgent or Windows CLI parity is claimed.

Verification MUST use protocol-level tests with fake network executors, plus a
safe running CLI/backend smoke scenario. Real Linux network mutations are allowed
only in the disposable `e2e/linux` container. macOS/Windows service, authorization,
proxy and lifecycle acceptance requires native-platform runs. Shared compilation
or Linux tests alone are not evidence of platform parity.

### Linux verification

The Linux lifecycle acceptance runs in `e2e/linux/run_cli_first.sh` against the
actual CLI, native Tauri window, system daemon, systemd user runtime and pinned
loopback Xray. It covers frontend-independent ownership, cross-client disconnect,
foreground signals, reconnect snapshots, explicit recovery, proxy restoration
after child/runtime death and stale GUI-save rejection.

The separate `e2e/linux/run.sh` suite exercises real WireGuard/OpenVPN/Xray
traffic, DNS, UID/polkit boundaries, daemon crash cleanup and always-on replay.
Protocol/subprocess regressions cover unavailable capabilities, malformed and
partial frames, bounded reads, broken pipes, proxy persistence failures and
optimistic edit boundaries. Native macOS/Windows and physical logout/reboot are
not verified by these Linux runs. Commands and observed evidence:
[`docs/testing.md`](docs/testing.md#linux-cli-first-architecture-acceptance).
