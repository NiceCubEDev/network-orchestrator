# Native macOS client

SwiftUI/AppKit application for macOS 27.0 or later. Its owned JSON C ABI
(`crates/macos-bridge`) adapts the same typed Engine services called directly by
`netorch`; Swift calls run on an actor away from the main UI actor. Both clients
share one unprivileged Unix-socket runtime owner per data directory, started on
demand through the user's launchd domain. There is no HTTP server or WebView.
The privileged helper remains separate from this user runtime.

## Build and run

```bash
bash scripts/build-macos-native.sh
open "target/macos/Network Orchestrator.app"
```

Requires Xcode 27, Rust and Python 3 on macOS 27. The build uses the host
architecture; the first verified bundle is Apple Silicon (arm64). Intel and
universal builds are not yet verified. Bundle version is generated from the
macOS release line in `versions.toml`. The local ad-hoc signature supports local development;
it is not a Developer ID signature or notarization for distribution.

## Available in this stage

- Home, connections, network, routes and settings screens styled after Tauri:
  icon rail, dense master-detail connection list, bottom status bar, interface filters, six route tabs and
  themed dialogs. Native file picker, menus, sheets and Command-R refresh.
- Import WireGuard `.conf`, OpenVPN `.ovpn` or Xray JSON via ConfigVault.
  Imported configurations are private, revisioned copies, not references to
  mutable original files. Keys and configuration contents are not displayed.
- Import `vless://`, `hysteria2://` and `hy2://` links in Import → Link.
  The name is optional and defaults to the URL fragment. Generated Xray
  configurations use managed revisions and distinct loopback proxy ports.
  Import does not start a VPN, set a system proxy or apply routes.
- Create static IPv4/IPv6 route profiles, rename/delete profiles, search and
  inspect declared routes and local listeners with the shared Rust analysis.
- Fetch an HTTP/HTTPS subscription in Import → Subscription, with optional
  HWID and name. Plain-text and Base64 lists of VLESS/Hysteria2 links are
  grouped into one profile with a server selector. Responses are bounded to
  1 MiB and 30 seconds. Cross-origin redirects do not receive the HWID; HTTPS
  downgrades are rejected. URL tokens, HWID and endpoint credentials stay in
  the protected store and are removed from all bridge profile responses.
- Read live Darwin interface names, indexes, operational state and addresses
  using `getifaddrs`; read system IPv4/IPv6 routes through `net-route`.
- Inspect saved route plans and longest-prefix lookup. macOS interface-scoped
  policy can affect actual kernel selection; the lookup is a table preview.
  Route metrics, DNS, MTU and traffic counters are not claimed when unavailable.

- Start and stop Xray connections in loopback SOCKS/HTTP mode (no root).
  Settings or the Connections notice install the pinned Xray v26.7.28
  (Apple Silicon): by download, or from a local copy of the official
  `Xray-macos-arm64-v8a.zip` for closed networks. Both paths are SHA-256
  verified before use.
- Per connection: drive the macOS system proxy, open a separate Chrome
  profile through the connection (`--proxy-server=socks5://…`, remote DNS),
  or copy `HTTP(S)_PROXY`/`ALL_PROXY` exports for a terminal.
- The system proxy is written only to enabled hardware services (Wi-Fi,
  Ethernet) via `networksetup`, with ownership snapshots in protected runtime
  storage. Explicit disconnect restores owned settings; closing GUI/CLI does
  not clear the shared proxy. Owner recovery verifies recorded process
  identities before cleanup.

When a packet-tunnel VPN such as incy is connected, it owns the primary
service and macOS takes proxy settings from it, so the system proxy toggle has
no effect; the status bar and a notice say so. Use "Open browser via
connection" or the terminal exports in that case.

WireGuard, OpenVPN, Xray TUN, static routes, DNS and interface changes go through
the privileged launchd helper
(`docs/plans/2026-09-30-14-macos-privileged-helper.md`). The unprivileged bridge
and CLI delegate these operations; a missing helper is an error, not simulated
success. The explicit root foreground mode uses the helper's own executors.

## Command line (`netorch`)

The bundle contains `Contents/MacOS/netorch`; link it into PATH with
`ln -s "/Applications/Network Orchestrator.app/Contents/MacOS/netorch" /usr/local/bin/netorch`.

```bash
netorch up 'vless://…'            # import + connect a background local proxy
netorch up https://sub.example/s  # subscription; probe with `netorch test <name>`
netorch up office.ovpn --auth-stdin < creds.txt
netorch up home --mode tun        # needs the helper (installed from the app)
sudo netorch up home -f           # in-process tunnel; helper must not be running
netorch route set home --direct geosite:ru --block domain:ads.example
netorch up home -f                # Ctrl+C stops only this activation
netorch down home                 # explicit disconnect from either client
netorch sets capture work --name Work
netorch mode show
netorch doctor                    # what is missing
sudo netorch service install      # the helper without the app (run from the bundle)
```

Loopback Xray (`--mode socks`, the default for links) belongs to the shared
unprivileged `netorch serve` owner, not the CLI or GUI process. Normal `up`
returns after connecting. Closing the terminal or GUI leaves the connection
running; `down` is explicit. `up --foreground` (`-f`) holds a generation lease:
client exit stops that activation, never a later replacement. Root connections
require `-f`, use the helper's in-process executors and never start this user owner.

The CLI covers existing native GUI business operations through shared services:

| Area | Commands |
|---|---|
| Profiles and subscriptions | `ls`, `add`, `import`, `static`, `edit`, `rename`, `reorder`, `rm`, `subscription` |
| Connections and diagnostics | `up`, `down`, `status`, `logs`, `test`, `inspect`, `diagnose`, `snapshot`, `doctor` |
| Routing and network | `route`, `network`, `proxy`, `capabilities` |
| Saved policy | `sets`, `mode`, `auto-connect`, `intents`, `conditions` |
| Credentials and providers | `credentials`, `netbird`, `tailscale`, `vpn` |
| Installation and recovery | `backend`, `service`, `recovery` |

Use `netorch COMMAND --help` for exact arguments. Presentation-only operations
(windows, clipboard, native dialogs and appearance) remain in the GUI.
Linux-only named process exits and service-availability monitoring are not
macOS commands.

OpenVPN credentials, passphrases and NetBird setup keys are never value arguments.
Use hidden prompts, protected input files or pipes. `--credentials-file FILE`
accepts a private JSON document with `authUserPass` and/or
`privateKeyPassphrase`; `-` reads piped stdin and rejects terminal stdin before
reading a secret. `--auth-stdin` / `--passphrase-stdin` support line-based input.
`--remember` saves credentials in the login Keychain only after a successful
connection; `credentials forget PROFILE` removes them.

## Storage and isolation

Default data: `~/Library/Application Support/com.netmanager.app.macos`.
Both clients also accept `NETORCH_MACOS_DATA_DIR`; the CLI's `--data-dir`
overrides it. Use a dedicated absolute directory for tests:

```bash
NETORCH_MACOS_DATA_DIR="$PWD/target/macos-qa-data" \
  "target/macos/Network Orchestrator.app/Contents/MacOS/NetworkOrchestrator"
```

The override selects shared profiles, settings, sets and user-runtime identity,
not a network sandbox. CLI and GUI using the same root intentionally control
the same connections. QA must use a separate root and fake adapters/runners;
real helper, interface, route, DNS and system-proxy operations can affect the host.

## Tests

```bash
scripts/macos-dev.sh test      # core + engine + bridge + CLI Rust tests, then Swift tests
scripts/macos-dev.sh preview   # offscreen renders: target/macos/preview/<lang>/<theme>
scripts/macos-dev.sh run       # dev bundle in the foreground, isolated QA data
scripts/macos-dev.sh du        # what occupies target/
scripts/macos-dev.sh clean     # drop incremental caches; --all for cargo clean
```

`macos/Package.swift` links the bridge from `target/macos-bridge`, which
`scripts/stage-macos-bridge.sh <profile>` fills (`release` for the bundle,
`release-fast` for development).

Opt-in live proxy acceptance (downloads Xray unless an official zip is given;
runs a loopback VLESS server; never touches the system proxy):

```bash
NETORCH_XRAY_ARCHIVE=/path/Xray-macos-arm64-v8a.zip \
NETORCH_LIVE_XRAY=https://www.youtube.com/ \
  swift test --package-path macos --scratch-path target/macos-swift --filter liveProxy
```

Tests use temporary stores and synthetic configurations. Native integration
tests also read real loopback interfaces and routes. They need ordinary route
socket access, but do not require administrator privileges or network changes.
SwiftPM may need permission to use Xcode/Swift caches in restricted sandboxes.

## Shared appearance

Both clients offer System, Light and Dark in Settings. Colors and core layout
metrics come from `design/tokens.json`; run `python3 scripts/generate-ui-theme.py`
after editing it. Both build scripts reject stale generated CSS/Swift output.
Native PDF icons reproduce the SVG geometry in `src/icons.tsx`; the source hash
is checked at build time. Regenerating them uses
`python3 scripts/generate-native-icons.py` with ReportLab installed; ordinary
builds use the checked-in PDFs and need no graphics Python dependencies.

The native client still uses SwiftUI/AppKit throughout. OS window chrome,
file pickers and popup menus follow macOS. Screens for unavailable features
show the native client's actual capabilities. A pixel-perfect match across
platforms has not been established.

Render every page, route tab and supported creation/import dialog in both
themes using synthetic data, without opening a window or starting a VPN:

```bash
NETORCH_DESIGN_PREVIEWS="$PWD/target/macos/design-preview" \
  swift test --package-path macos --scratch-path target/macos-swift
```

The optional acceptance test writes 64 native PNG renders across English,
Russian, dark and light; the normal test
suite also checks packaged vector icons. These renders check appearance;
they do not replace interactive testing of a foreground window.

## Interface language

Settings → Appearance → Language offers System, English and Russian. The
selection is saved in this application's preferences and updates the views
in place. Shared catalogs, plural rules and the new-language workflow are
documented in [`../locales/README.md`](../locales/README.md). Run
`npm run i18n:generate` after editing catalogs; native packaging includes the
generated JSON resource and rejects stale translations.
