# Recovery and lifecycle

## Windows containment

- OpenVPN and Xray run as child processes inside a Windows Job Object with
  `KILL_ON_JOB_CLOSE`: if the app exits or crashes, the OS kills the
  children — they cannot be orphaned.
- WireGuard uses `wireguard.exe /installtunnelservice` — a real Windows
  service that survives process exit by design.

## Ownership records

Durable records make crash cleanup possible without guessing:

- `applied-routes.json` — policy routes the app created (profile id, CIDR,
  interface index, metric). Written atomically (temp + rename).
- `proxy-state.json` — system-proxy ownership: owning profile id, the exact
  pre-apply registry snapshot, and the applied values. Persisted **before**
  the registry write so a crash mid-apply still leaves evidence. ACL-protected
  like the config vault.
- WireGuard running state is discovered live by querying the tunnel service.

## Windows normal close

Window close / app exit runs `cleanup_all` under a shutdown flag:

1. `proxy.restore_any()` — restore snapshotted registry values (deleting
   values that did not exist before), then clear the record.
2. Remove every owned policy route and persist the emptied registry.
3. Stop every running tunnel (WireGuard service uninstall, child kill).

Close is deferred until cleanup finishes; failure keeps the app alive and
emits `shutdown-failed` instead of abandoning mutated state.

## Crash → startup prompt

On startup `get_recovery_report` inspects (no mutation):

- surviving WireGuard tunnel services for stored profiles,
- status-check failures,
- recorded route ownership: routes still present (`OwnedRoutes`), routes
  expected but absent (`MissingOwnedRoutes`), or records for deleted
  profiles (`OrphanRouteOwnership`),
- `proxy-state.json` ownership still applied (`ProxyOwnership`).

If issues exist, a prompt offers **Clean up** (runs `cleanup_all`, then
re-reports) or **Keep for now** (dismiss, no mutation). A failed inspection
shows `Recovery check failed` with **Retry** — cleanup is never offered
blindly. When cleanup needs administrator rights the app offers an elevated
restart; after restart the same check runs again.

## Safety properties

- Restore is idempotent: `restore_any` with no ownership is a no-op;
  `restore` for a non-owner fails instead of touching another profile's
  settings.
- Apply rollback: if the registry write fails, the snapshot is restored and
  ownership cleared; if that restore also fails, the ownership record is
  deliberately kept so recovery can still undo the partial apply.
- Read-back verification: the Windows adapter re-reads the registry after
  apply/restore and errors on mismatch before broadcasting
  `WM_SETTINGCHANGE`.

## Linux lifecycle and failure diagnostics

System tunnels belong to the privileged daemon, not to the GUI. Closing or
crashing the GUI must not disconnect them. Local SOCKS Xray and user proxy
ownership belong to the shared unprivileged `netorch serve` runtime. An exit of
both GUI and tunnel is not explained by the cleanup warning alone.

The diagnostic paths are:

- **GUI and CLI operations:** the existing private, bounded
  `<data-dir>/app-logs/events.json` store, shared by both clients (500 events).
  Records include operation/method, process and request context, outcome and
  elapsed time where available. Successful status polling is not recorded.
- **GUI lifecycle:** launch, setup, ready, close/hide, exit request and completed
  exit; WebKit renderer termination includes its reason. Linux GUI diagnostics
  are also sent to the journal with `SYSLOG_IDENTIFIER=net-manager-app`.
- **Rust GUI panic:** a pre-opened private `app-logs/gui-panic.log` retains the
  latest panic's timestamp, PID, version, source location and bounded symbol
  backtrace. It bypasses the normal log-store lock so a panic inside logging
  does not re-enter that lock. It does not retain the panic payload.
- **Frontend failures:** uncaught errors/rejections and React uncaught/recovered
  errors record an allowlisted error category and at most eight bundled-code
  source positions. Exception messages and arbitrary stack text are omitted.
- **Daemon and children:** the system journal records startup/shutdown, request
  results, background failures, netlink operation errors/timeouts, Xray/OpenVPN
  spawn, exit code/signal and termination. Xray recovery distinguishes transport
  loss from watchdog/egress decisions and records restart budget exhaustion and
  teardown failures. Raw Xray traffic-log tails are not copied into the journal.
- **User runtime:** connection/child failure and proxy restoration are recorded
  in the same app log. Event-stream disconnect/reconnect/resync is recorded by
  the observing CLI without logging every successful snapshot.

Read-only collection after an incident:

```bash
netorch version
netorch --json recovery report
netorch --json recover
netorch logs show --level error
netorch logs show --level warn
netorch logs daemon --lines 200
journalctl --since '30 minutes ago' SYSLOG_IDENTIFIER=net-manager-app
journalctl -u network-orchestrator.service --since '30 minutes ago'
coredumpctl info net-manager-app
```

Use the incident time, PID, operation/request identifiers and begin/end events
to correlate the layers. An unmatched begin event indicates an interrupted
operation, not proof of a particular crash cause. A GUI launch without a later
clean-exit record likewise does not prove why the process disappeared.

`SIGKILL`, native segmentation faults, OOM kills and power loss cannot reliably
write a final in-process log. Consult the kernel/system journal and coredump
metadata; availability depends on the host's journal/coredump configuration.
The panic artifact covers Rust panics, not every native crash.

Logs deliberately exclude configuration contents, credentials, subscription
URLs, raw IPC bodies and arbitrary private paths. Do not enable unrestricted
request/config/traffic dumps to investigate an incident. Retention remains
bounded by the app ring and the host journal policy; the panic file retains only
the latest panic.

`Clean up`, `netorch recovery cleanup` and `netorch recover --cleanup` mutate
state; they are not diagnostic collection commands. In particular,
`recover --cleanup` disconnects all current-user connections and pauses
always-on. Do not run it merely to dismiss a warning while a tunnel is active.
New source diagnostics appear only after building/installing the corresponding
GUI, CLI and daemon; merging source does not update an installed package.

Diagnostic writes do not wait for another frontend's log-store lock. On store
contention/failure they fall back to best-effort, nonblocking journal delivery
(`SYSLOG_IDENTIFIER=netorch`), without contaminating CLI stdout or JSON stderr.
If both the private store and journal are unavailable, that diagnostic may be
lost; logging must not indefinitely stall proxy restoration or connection work.
