# Security notes

## Threat model

Network Orchestrator manages VPN configurations that contain secrets
(WireGuard private keys, VLESS UUIDs, credentials) and performs privileged
system mutations (routes, interfaces, registry proxy values, child
processes). The main concerns:

- Secret exposure through files, errors, logs, UI, or crash dumps.
- Tampering with managed configs by other local users/processes.
- Stale or attacker-planted system state after crashes.
- Bugs in privileged mutations affecting unrelated OS state.

## Managed configuration vault

- Imported and generated configs are copied into
  `app_data/configs/<profile>/rev-N/` — the app never mutates external source
  files or their ACLs.
- Every managed directory and file gets an explicit protected DACL granting
  full control only to the current user SID, `SYSTEM`, and
  `Administrators` (SDDL `D:P(A;OICI;FA;;;<sid>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`).
  Inheritance is disabled; `inspect_path_protection` verifies the result via
  real `GetFileSecurityW` calls.
- Any ACL failure aborts the import/store and cleans up staged revisions.
- The vault root is hardened at app startup (`ensure_root_protected`).

## DPAPI for generated Xray configs

- `vless://` imports and generated SOCKS configs are stored as
  `config.json.dpapi`: `CryptProtectData` with
  `CRYPTPROTECT_UI_FORBIDDEN` and per-profile entropy
  (`network-orchestrator:xray:<profile-id>`).
- Decryption happens in memory only (`read_xray_config`); plaintext is fed
  to Xray via stdin and is never persisted again. Rewriting a legacy
  plaintext generated config (e.g. port reallocation) migrates it to DPAPI.
- Imported user-supplied Xray JSON stays plaintext but ACL-protected — the
  user chose an external full config.

## Plaintext constraints

- WireGuard `.conf` and OpenVPN `.ovpn` managed copies are ACL-protected but
  not encrypted — DPAPI only wraps generated Xray JSON. WireGuard private
  keys remain readable by the current user/SYSTEM/Administrators.
- The original external files are never modified; if the source is not
  protected, the managed copy is — but the source itself stays as-is.
- On Linux, the optional OpenVPN "Remember" choice stores credentials as
  plaintext in a user-only `0600` file under that profile's vault directory.
  Without "Remember", credentials are sent only for the current connection.
  The daemon answers OpenVPN management prompts over its private Unix socket
  and retains credentials in process memory for reconnect; they are not put
  in argv, staged config files, or the ownership journal.

## Redaction

- Runtime log tails shown in diagnostics pass through `redact_runtime_log`,
  which strips `vless://` URIs, UUID-shaped tokens, and values following
  `privatekey`/`password`/`token`/`authorization` (`=`/`:` separators) using
  ASCII case-insensitive byte matching that never slices transformed
  Unicode strings.
- Analysis failures surface profile name/id only — no config paths or
  contents in warnings or errors. E2E failure messages contain profile
  basenames only.

## External executable trust

- `wireguard.exe`, `openvpn.exe`, `xray.exe` (and `wg.exe` for health) are
  resolved from configured paths, install directories, or PATH and executed
  as-is. The app does not signature-verify configured or auto-detected
  executables — selecting a trusted backend is the operator's
  responsibility. The Profiles tab reports resolution results.
- Managed Xray is the single exception: it is installed only on explicit
  user action from the fixed official v26.7.28 release URL shown in the
  confirmation dialog. The compressed archive is checked against pinned
  SHA-256
  `c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1`;
  required extracted files (`xray.exe`, `geoip.dat`, `geosite.dat`) are
  individually hash-verified; extraction is limited to a strict root-level
  allowlist with bounded compressed/uncompressed sizes; the versioned
  directory under app data is ACL-protected; the installed binary is
  validated with `xray version`; and integrity is rechecked before
  diagnostics and connect. There is no silent or automatic download/update.
- WireGuard and OpenVPN are not managed-downloaded because their installers
  carry drivers and services.
- OpenVPN and Xray child processes run inside a Windows Job Object with
  `KILL_ON_JOB_CLOSE`, so a crashed app cannot orphan them.
- Xray receives its (decrypted) config via stdin, not a world-readable file.

## Privilege model

- Interface toggles, WireGuard service install, OpenVPN, and policy routes
  need administrator; the app offers an elevated restart via UAC.
- The Windows system proxy writes only to
  `HKCU\...\Internet Settings` and needs no elevation.
- The proxy ownership record (`proxy-state.json`) is ACL-protected like the
  vault.

### Linux daemon

- `network-orchestrator-daemon` runs as a systemd service with
  `CAP_NET_ADMIN`, restricted filesystems, address families, and device access.
  Its socket is world-connectable; socket permissions are not the
  authorization boundary.
- The daemon identifies each client through `SO_PEERCRED`. Mutating requests
  go through polkit `CheckAuthorization` for that process. Applying routes or
  changing an interface uses `com.netmanager.app.system-network`
  (`auth_admin_keep` for an active session). Removing owned routes uses
  `com.netmanager.app.connect-profile` (`allow_active=yes`). Read-only owner
  queries are filtered by uid, and an authorized user cannot remove another
  uid's owner.
- Connecting a VPN profile is governed by the administrator-chosen VPN
  password mode, stored by the daemon in
  `/var/lib/network-orchestrator/settings.json` (0600) and changeable only
  through `system-network`. `noPrompt` (default) authorizes every connect with
  `connect-profile`. `fullTunnelOnly` additionally requires
  `com.netmanager.app.connect-profile-admin` (`auth_admin_keep`) for
  connects that capture all traffic of the machine: a WireGuard or Xray TUN
  full tunnel (a default route or its halves, which also installs global DNS)
  and every OpenVPN profile, because its server may push a full tunnel on any
  (re)connect. `always` requires `connect-profile-admin` for every connect.
  The client never decides this. A missing settings file means
  `noPrompt`; an unreadable or invalid one fails closed to `always`.
  Route sets whose union covers a whole address family without being the
  canonical default route or its halves are rejected, so a split-looking
  profile cannot skip the full-tunnel prompt. Split tunnels still install their own routes and
  per-link DNS without a prompt in modes other than `always`.
  Saved administrator-selected modes are preserved on upgrades. For an active
  local session the default needs no VPN password prompt; inactive and remote
  sessions still require polkit administrator authorization.
- Routes are added with a dedicated protocol number and exclusive netlink
  creation so an existing route is not overwritten. The daemon writes its
  ownership journal to `/var/lib/network-orchestrator/state.json` with mode
  0600 before each mutation. On restart and graceful stop it attempts to
  remove journaled routes.
- A malformed or unsupported journal blocks daemon startup and remains on
  disk for inspection. It must be recovered before privileged mutations can
  resume; starting with empty ownership would risk leaving routes behind.
- Linux WireGuard links, OpenVPN processes, Xray TUN processes, full-tunnel
  rules and per-link DNS use the daemon's ownership journal and cleanup.
  Xray SOCKS/HTTP runs in the UI process. Docker E2E covers normal disconnect
  and daemon crash recovery; desktop acceptance remains pending. The daemon
  executes Xray TUN only from a root-owned, hash-verified package path and
  accepts only a restricted generated-config schema.
- Explicit always-on enrollment is currently limited to WireGuard and static
  routes. The daemon stores typed per-uid definitions under its root-owned
  state directory (`0700` directories, `0600` files), replays them after
  recovery, and keeps a persistent pause after "Disconnect all" until an
  authorized resume. OpenVPN and Xray TUN always-on enrollment is rejected.

## Known gaps

- Public Linux package release needs a geo-data provenance and freshness review.
  The pinned Xray archive includes `geoip.dat` built from sources that include
  MaxMind GeoLite data; the [GeoLite EULA](https://www.maxmind.com/en/geolite/eula)
  requires old databases to be replaced or destroyed after an update. The
  locally built packages are test artifacts, not a cleared release.
- Release artifacts are **unsigned** — no code-signing or update signing;
  SmartScreen warnings are expected.
- Tauri applies a local-resource CSP in production; `style-src 'unsafe-inline'`
  remains necessary for the app's dynamic inline styles. Development allows
  the Vite localhost WebSocket for HMR.
- Windows Xray health reports `Degraded` until listener/API/outbound
  verification is implemented; Windows OpenVPN health relies on log markers.
  Linux OpenVPN state comes from its management interface; Linux Xray TUN
  status checks the managed process and interface.
- No `ProxyAutoConfigURL`/`AutoConfigURL` handling — only the explicit
  `ProxyServer`/`ProxyOverride`/`ProxyEnable` values are managed.
