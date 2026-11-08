import AppKit
import CryptoKit
import Foundation
import Observation
import OSLog

@MainActor @Observable final class AppModel {
  let core: CoreBridge
  /// Separate channel for multi-second delay probes so status polling and
  /// edits never wait behind them.
  let probeCore: CoreBridge
  /// Last measured delay per profile and endpoint index; nil = no response.
  var delays: [String: [Int: UInt64?]] = [:]
  /// Endpoint indices still being measured, per profile.
  var probing: [String: Set<Int>] = [:]
  var refreshing = Set<String>()
  /// Exit-IP results per route: "direct" or a running profile id.
  var exitIPs: [String: [ExitIpEntry]] = [:]
  var checkingExitIP = Set<String>()
  var externalVPNs: [ExternalVpn] = []
  /// The user's NetBird daemon, when one is installed.
  var netbird: NetBirdState?
  var netbirdBusy = false
  var showingNetBirdSetup = false
  /// The user's Tailscale, when one is installed, and what keeps it reachable
  /// next to a running tunnel.
  var tailscale: TailscaleState?
  var tailscaleGuard: TailscaleGuardState?
  var tailscaleBusy = false
  var switchingExternal = Set<String>()
  var snapshot: Snapshot?
  var capabilities: Capabilities?
  var section: Section = .home
  var search = ""
  /// User-facing error. Bridge errors are secret-free by design, so they are
  /// also mirrored to the unified log (Xcode console, Console.app).
  var error: String? {
    didSet {
      guard let error else { return }
      Self.log.error("\(error, privacy: .public)")
      if error != oldValue { appLog.add(.error, error) }
    }
  }
  /// The app's own events, shown on the Logs page.
  private(set) var appLog = AppLog()
  func record(_ level: LogLevel, _ message: String) { appLog.add(level, message) }
  private static let log = Logger(subsystem: "com.netmanager.app.macos", category: "app")
  var busy = false
  var subscriptionEndpoints: [String: [SubscriptionEndpoint]] = [:]
  var importSkippedCount = 0
  var inspecting: Profile?
  var inspection: Inspection?
  var lookup: Lookup?
  var userNetwork: UserNetworkSettings?
  var lookupDestination = ""
  var runtime: RuntimeState?
  var selectedProfileID: String?
  var inspections: [String: Inspection] = [:]
  var pending = Set<String>()
  var installingXray = false
  /// Interface carrying the system default route, e.g. `en0` or a VPN `utun9`.
  var primaryInterface: String?
  var notice: String?
  var helperRegistration: HelperRegistration = .notRegistered
  var helperStatus: HelperStatus?

  private let usesProductionDefaults: Bool
  private var legacyStateLoaded = false
  private(set) var startEligibilities: [String: ProfileStartEligibility] = [:]
  private(set) var systemProxyOverridden = false
  init(dataDirectory: URL? = nil) {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    // Dedicated native store; does not modify the Tauri app's data.
    let root =
      dataDirectory ?? ProcessInfo.processInfo.environment["NETORCH_MACOS_DATA_DIR"].map {
        URL(fileURLWithPath: $0)
      }
      ?? base.appendingPathComponent("com.netmanager.app.macos", isDirectory: true)
    core = CoreBridge(root: root)
    probeCore = CoreBridge(root: root)
    usesProductionDefaults =
      root.standardizedFileURL.resolvingSymlinksInPath()
      == base.appendingPathComponent("com.netmanager.app.macos", isDirectory: true)
        .standardizedFileURL.resolvingSymlinksInPath()
  }

  /// The profile last connected from this app, for the Home quick action.
  private static let lastProfileKey = "lastConnectedProfile"
  var lastProfileID: String? = UserDefaults.standard.string(forKey: AppModel.lastProfileKey) {
    didSet { UserDefaults.standard.set(lastProfileID, forKey: Self.lastProfileKey) }
  }
  var lastProfile: Profile? {
    lastProfileID.flatMap { id in snapshot?.profiles.first { $0.id == id } }
  }

  private(set) var connectionSets: [ConnectionSet] = []

  /// Imports the old GUI-only values once, then reads the shared documents.
  /// A custom data root must never consume or erase production defaults.
  func reloadSharedState() async throws {
    if !legacyStateLoaded {
      if usesProductionDefaults {
        let defaults = UserDefaults.standard
        var args: [String: String] = [:]
        if let mode = defaults.string(forKey: "appMode") { args["appMode"] = mode }
        if let data = defaults.data(forKey: "connectionSets") {
          guard let payload = String(data: data, encoding: .utf8) else {
            throw CoreError(message: L10n.text("Saved connection sets could not be migrated."))
          }
          args["connectionSets"] = payload
        }
        let result: LegacyStateImport = try await core.call("import_legacy_state", args: args)
        if result.imported {
          defaults.removeObject(forKey: "connectionSets")
          defaults.removeObject(forKey: "appMode")
        }
      }
      legacyStateLoaded = true
    }
    let settings: AppSettings = try await core.call("settings")
    appMode = settings.appMode
    connectionSets = try await core.call("sets")
  }

  /// Capture is performed against the shared runtime, not this window's cache.
  func saveCurrentSet(name: String) async {
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    do {
      let _: ConnectionSet = try await core.call(
        "capture_set",
        args: ["id": UUID().uuidString, "name": trimmed.isEmpty ? L10n.text("sets.label") : trimmed])
      connectionSets = try await core.call("sets")
      error = nil
    } catch { self.error = error.localizedDescription }
  }

  func deleteSet(_ set: ConnectionSet) async {
    do {
      connectionSets = try await core.call("delete_set", args: ["id": set.id])
      error = nil
    } catch { self.error = error.localizedDescription }
  }

  func applySet(_ set: ConnectionSet) async {
    _ = await performBatch("apply_set", args: ["id": set.id], offerCredentials: true)
    await refreshAfterOperation()
  }

  @discardableResult
  private func performBatch(
    _ method: String, args: [String: String] = [:], offerCredentials: Bool = false
  ) async -> BatchOutcome? {
    do {
      let result: BatchOutcome = try await core.call(method, args: args)
      let failures = result.items.filter { $0.outcome == .failed }
      error = failures.isEmpty ? nil : failures.map {
        $0.error ?? L10n.text("The operation could not be completed")
      }.joined(separator: "\n")
      if offerCredentials,
        let item = result.items.last(where: { $0.credentialPrompt != nil }),
        let prompt = item.credentialPrompt,
        let profile = snapshot?.profiles.first(where: { $0.id == item.profileId })
      {
        presentCredentialPrompt(profile, prompt: prompt)
      }
      return result
    } catch {
      self.error = error.localizedDescription
      return nil
    }
  }

  private func refreshAfterOperation() async {
    let operationError = error
    await refresh()
    if let operationError { error = operationError }
  }
  /// Moves a profile within its backend group (drag and drop or Move up/down).
  func move(_ profile: Profile, to target: Profile? = nil, by offset: Int = 0) async {
    var group = (snapshot?.profiles ?? []).filter { $0.backend == profile.backend }.map(\.id)
    guard let from = group.firstIndex(of: profile.id) else { return }
    group.remove(at: from)
    var to = from + offset
    if let target, let index = group.firstIndex(of: target.id) { to = index }
    group.insert(profile.id, at: max(0, min(group.count, to)))
    _ = await change("reorder", args: ["backend": profile.backend, "ids": group.joined(separator: ",")])
  }
  var profiles: [Profile] {
    (snapshot?.profiles ?? []).filter {
      search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)
        || $0.kind.localizedCaseInsensitiveContains(search)
    }
  }
  var selectedProfile: Profile? {
    let all = snapshot?.profiles ?? []
    return all.first { $0.id == selectedProfileID } ?? profiles.first
  }
  func status(_ profile: Profile) -> TunnelStatus? {
    runtime?.statuses.first { $0.profileId == profile.id }
  }
  func isRunning(_ profile: Profile) -> Bool { status(profile)?.state == "running" }
  var activeCount: Int { runtime?.statuses.filter { $0.state == "running" }.count ?? 0 }
  var canStartConnections: Bool { capabilities?.proxyConnections ?? false }
  /// The helper answers and serves Xray tunnels (`xray.connect`).
  var helperServesTunnels: Bool {
    helperStatus?.reachable == true && helperStatus?.capabilities.contains("xray.connect") == true
  }
  /// The helper answers and advertises `capability`.
  func helperOffers(_ capability: String) -> Bool {
    helperStatus?.reachable == true && helperStatus?.capabilities.contains(capability) == true
  }
  func helperServes(_ profile: Profile) -> Bool {
    profile.helperCapability.map(helperOffers) ?? false
  }
  /// Whether this client can start `profile` right now: loopback Xray always,
  /// anything that needs a tunnel device once the privileged helper serves it.
  private(set) var appMode: AppMode = .combined

  func setAppMode(_ mode: AppMode) async {
    do {
      let settings: AppSettings = try await core.call("set_app_mode", args: ["mode": mode.rawValue])
      appMode = settings.appMode
      try await reloadStartEligibilities()
      error = nil
    } catch { self.error = error.localizedDescription }
  }

  private func reloadStartEligibilities() async throws {
    let rows: [ProfileStartEligibility] = try await core.call("start_eligibilities")
    startEligibilities = Dictionary(rows.map { ($0.profileId, $0) }, uniquingKeysWith: { _, last in last })
  }
  /// The mode forbids starting `profile`; a running one can still be stopped.
  func modeLocks(_ profile: Profile) -> Bool {
    !isRunning(profile) && (startEligibilities[profile.id]?.modeBlocked ?? false)
  }
  func canStart(_ profile: Profile) -> Bool { startEligibilities[profile.id]?.canStart ?? false }
  func canTryStart(_ profile: Profile) -> Bool {
    isRunning(profile) || (startEligibilities[profile.id]?.canTryStart ?? false)
  }
  /// Interfaces of tunnels this app runs itself.
  var ownTunnelInterfaces: Set<String> {
    Set(runtime?.statuses.compactMap { $0.state == "running" ? $0.interfaceName : nil } ?? [])
  }

  func refreshRuntime() async {
    helperStatus = try? await core.callConcurrently("helper_status")
    // A "helper is not running" banner left from before it was (re)enabled.
    if helperStatus?.reachable == true,
      error == "The privileged helper is not running. Install it in Settings."
    {
      error = nil
    }
    await retireOutdatedHelper()
    do { runtime = try await core.call("runtime") } catch { runtime = nil }
    if let list: [ExternalVpn] = try? await core.call("external_vpns") { externalVPNs = list }
    netbird = try? await core.callConcurrently("netbird_status")
    tailscale = try? await core.callConcurrently("tailscale_status")
    do {
      try await reloadSharedState()
      try await reloadStartEligibilities()
      let proxy: ProxyOverrideStatus = try await core.call("proxy_override")
      primaryInterface = proxy.primaryInterface
      systemProxyOverridden = proxy.overridden
    } catch { self.error = error.localizedDescription }
    await syncTailscaleGuard()
  }
  /// Asks the core to keep the tailnet reachable next to whatever tunnel is
  /// up (or to let go when none is). The core answers repeats from a cache.
  private func syncTailscaleGuard() async {
    guard tailscale?.installed == true else {
      tailscaleGuard = nil
      return
    }
    tailscaleGuard = try? await core.callConcurrently("tailscale_sync")
  }
  /// Another app's VPN entry that is really Tailscale's (shown by its own row).
  func isTailscaleService(_ vpn: ExternalVpn) -> Bool {
    tailscale?.installed == true && (vpn.provider ?? "").hasPrefix("io.tailscale.")
  }
  /// Connects Tailscale or, when it is on, disconnects it. The Mac app's own
  /// VPN service is switched like any other app's VPN; otherwise the CLI is.
  func toggleTailscale() async {
    guard !tailscaleBusy, let current = tailscale, current.canToggle else { return }
    tailscaleBusy = true
    defer { tailscaleBusy = false }
    do {
      tailscale = try await core.callConcurrently(current.isOn ? "tailscale_down" : "tailscale_up")
      error = nil
    } catch { self.error = error.localizedDescription }
    await refreshRuntime()
  }
  /// Connect or disconnect another app's VPN, as the VPN menu would.
  func setExternalVPN(_ vpn: ExternalVpn, connect: Bool) async {
    switchingExternal.insert(vpn.id)
    defer { switchingExternal.remove(vpn.id) }
    do {
      externalVPNs = try await core.call(
        "set_external_vpn", args: ["id": vpn.id, "connect": connect ? "true" : "false"])
      // Connecting takes a moment; pick up the settled state.
      try? await Task.sleep(for: .seconds(2))
      await refreshRuntime()
    } catch { self.error = error.localizedDescription }
  }
  func toggle(_ profile: Profile) async {
    guard !pending.contains(profile.id) else { return }
    if profile.needsHelper && !isRunning(profile) && !helperServes(profile) {
      helperPrompt = true
      return
    }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    do {
      if isRunning(profile) {
        runtime = try await core.call("disconnect", args: ["id": profile.id])
        record(.info, "Disconnected \(profile.name)")
      } else {
        if await connectProfile(profile) { lastProfileID = profile.id }
        return
      }
      try await reloadStartEligibilities()
      error = nil
    } catch {
      self.error = error.localizedDescription
      await refreshRuntime()
    }
  }
  func setSystemProxy(_ profile: Profile, enabled: Bool) async {
    do {
      runtime = try await core.call(
        "set_system_proxy", args: ["id": profile.id, "enabled": enabled ? "true" : "false"])
      if enabled && systemProxyOverridden {
        notice = "native.proxyOverridden"
      }
    } catch { self.error = error.localizedDescription }
  }
  /// Switches an Xray profile between loopback SOCKS and the system tunnel;
  /// a running connection restarts in the new mode.
  func setXrayMode(_ profile: Profile, mode: String) async {
    guard !pending.contains(profile.id) else { return }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    if await change("set_xray_mode", args: ["id": profile.id, "mode": mode]) {
      await refreshRuntime()
    }
  }
  func installXray(archive: URL? = nil) async {
    installingXray = true
    defer { installingXray = false }
    do {
      let _: [String: Bool] = try await core.call(
        "install_xray", args: archive.map { ["archivePath": $0.path] } ?? [:])
      await refreshRuntime()
    } catch { self.error = error.localizedDescription }
  }
  func loadInspection(_ profile: Profile) async {
    guard inspections[profile.id] == nil else { return }
    if let result: Inspection = try? await core.call("inspect", args: ["id": profile.id]) {
      inspections[profile.id] = result
    }
  }
  /// The shared service owns browser arguments and the per-profile directory.
  func openBrowser(_ profile: Profile) async {
    do {
      let _: [String: String] = try await core.call("open_browser", args: ["id": profile.id])
    } catch { self.error = error.localizedDescription }
  }
  func copyTerminalProxy(_ profile: Profile) async {
    do {
      let result: ProxyExports = try await core.call("proxy_exports", args: ["id": profile.id])
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(result.shell, forType: .string)
      notice = "native.copied"
    } catch { self.error = error.localizedDescription }
  }

  func refresh() async {
    guard !busy else { return }
    busy = true
    defer { busy = false }
    do {
      try await reloadSharedState()
      if capabilities == nil { capabilities = try await core.call("capabilities") }
      snapshot = try await core.call("snapshot")
      var endpoints: [String: [SubscriptionEndpoint]] = [:]
      for profile in snapshot?.profiles ?? [] where profile.subscription != nil {
        endpoints[profile.id] = try await core.call(
          "subscription_endpoints", args: ["id": profile.id])
      }
      subscriptionEndpoints = endpoints
      inspections = [:]
      await refreshRuntime()
      error = nil
    } catch { self.error = error.localizedDescription }
  }
  func createStatic(name: String, interface: String, cidrs: String, bypass: String = "") async
    -> Bool
  {
    await change(
      "create_static",
      args: [
        "id": UUID().uuidString, "name": name, "interfaceName": interface, "cidrs": cidrs,
        "bypass": bypass,
      ])
  }
  func importConfig(url: URL, backend: String, name: String) async -> Bool {
    let access = url.startAccessingSecurityScopedResource()
    defer { if access { url.stopAccessingSecurityScopedResource() } }
    return await change(
      "import", args: ["id": UUID().uuidString, "name": name, "backend": backend, "path": url.path])
  }
  func importShareLink(_ link: String, name: String) async -> Bool {
    await change("import_share_link", args: ["id": UUID().uuidString, "name": name, "link": link])
  }
  func rename(_ profile: Profile, name: String) async -> Bool {
    await change("rename", args: ["id": profile.id, "name": name])
  }
  func importSubscription(url: String, hwid: String, name: String) async -> Bool {
    guard !busy else { return false }
    busy = true
    importSkippedCount = 0
    error = nil
    do {
      let result: SubscriptionImportResult = try await core.call(
        "import_subscription",
        args: [
          "id": UUID().uuidString, "url": url.trimmingCharacters(in: .whitespacesAndNewlines),
          "hwid": hwid.trimmingCharacters(in: .whitespacesAndNewlines), "name": name,
        ])
      busy = false
      await refresh()
      importSkippedCount = result.skippedCount
      return true
    } catch {
      busy = false
      self.error = error.localizedDescription
      return false
    }
  }
  /// Stable per-device HWID, derived in the core from this Mac's hardware ID.
  func generateHWID() async -> String? {
    do {
      let value: String = try await core.call("generate_hwid")
      return value
    } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  /// Switching a running connection reconnects it on the new server.
  func switchEndpoint(_ profile: Profile, index: Int) async {
    guard !pending.contains(profile.id) else { return }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    _ = await change(
      "switch_subscription_endpoint", args: ["id": profile.id, "index": String(index)])
  }
  /// Name of the selected server of a subscription profile.
  func activeServer(_ profile: Profile) -> String? {
    guard let subscription = profile.subscription,
      let endpoints = subscriptionEndpoints[profile.id],
      endpoints.indices.contains(subscription.activeIndex)
    else { return nil }
    return profile.serverLabel(endpoints[subscription.activeIndex].name)
  }
  /// Probes every server, up to eight at once, publishing each result the
  /// moment it arrives so the list fills in live.
  func measureDelays(_ profile: Profile) async {
    let id = profile.id
    guard probing[id] == nil, let count = subscriptionEndpoints[id]?.count, count > 0 else {
      return
    }
    delays[id] = [:]
    probing[id] = Set(0..<count)
    defer { probing[id] = nil }
    let core = probeCore
    await withTaskGroup(of: (Int, Result<DelayResult, Error>).self) { group in
      var next = 0
      while next < min(8, count) {
        let index = next
        group.addTask {
          do {
            let result: DelayResult = try await core.callConcurrently(
              "measure_delay", args: ["id": id, "index": String(index)])
            return (index, .success(result))
          } catch { return (index, .failure(error)) }
        }
        next += 1
      }
      for await (index, outcome) in group {
        switch outcome {
        case .success(let result): delays[id, default: [:]][index] = .some(result.delayMs)
        case .failure(let failure):
          delays[id, default: [:]][index] = .some(nil)
          if failure.localizedDescription.hasPrefix("Install Xray") {
            self.error = failure.localizedDescription
          }
        }
        probing[id]?.remove(index)
        if next < count {
          let index = next
          group.addTask {
            do {
              let result: DelayResult = try await core.callConcurrently(
                "measure_delay", args: ["id": id, "index": String(index)])
              return (index, .success(result))
            } catch { return (index, .failure(error)) }
          }
          next += 1
        }
      }
    }
  }
  /// Re-fetches a subscription. The download runs off the core actor (the
  /// bridge only locks the store to apply it), so the UI keeps polling.
  func refreshSubscription(_ profile: Profile, quiet: Bool = false) async {
    guard !refreshing.contains(profile.id) else { return }
    refreshing.insert(profile.id)
    defer { refreshing.remove(profile.id) }
    do {
      let outcome: RefreshOutcome = try await probeCore.callConcurrently(
        "refresh_subscription", args: ["id": profile.id])
      delays[profile.id] = nil
      if !quiet {
        notice = L10n.text("native.refreshed", ["count": String(outcome.endpointCount)])
      }
    } catch {
      if !quiet { self.error = error.localizedDescription }
    }
    await refresh()
  }
  func setRefreshInterval(_ profile: Profile, minutes: UInt32?) async {
    _ = await change(
      "set_refresh_interval",
      args: ["id": profile.id, "minutes": minutes.map(String.init) ?? ""])
  }
  /// Refreshes subscriptions whose interval elapsed. Running connections are
  /// left alone so a background refresh never drops traffic.
  func autoRefreshDue() async {
    _ = await performBatch("refresh_subscriptions", args: ["dueOnly": "true"])
    await refresh()
  }
  /// Toolbar refresh: re-fetch every subscription, then reload everything.
  func refreshAll() async {
    _ = await performBatch("refresh_subscriptions", args: ["dueOnly": "false"])
    delays = [:]
    await refreshAfterOperation()
  }
  /// Checks the exit IP directly and through every running connection at
  /// once; each route's result appears as soon as its checkers finish.
  func checkExitIPs() async {
    let routes = ["direct"] + (snapshot?.profiles ?? []).filter { isRunning($0) }.map(\.id)
    exitIPs = exitIPs.filter { routes.contains($0.key) }
    let core = probeCore
    await withTaskGroup(of: (String, [ExitIpEntry]?).self) { group in
      for route in routes where !checkingExitIP.contains(route) {
        checkingExitIP.insert(route)
        group.addTask {
          let entries: [ExitIpEntry]? = try? await core.callConcurrently(
            "check_exit_ip", args: ["via": route])
          return (route, entries)
        }
      }
      for await (route, entries) in group {
        exitIPs[route] = entries ?? []
        checkingExitIP.remove(route)
      }
    }
  }
  /// OpenVPN is waiting for the user to type credentials.
  var credentialRequest: CredentialRequest?
  private func presentCredentialPrompt(_ profile: Profile, prompt: CredentialPrompt) {
    if let message = prompt.notice?.message { notice = message }
    credentialRequest = CredentialRequest(
      profile: profile.id, name: profile.name, needs: prompt.needs, rejected: prompt.rejected)
  }

  @discardableResult
  private func connectProfile(
    _ profile: Profile, arguments: [String: String] = [:], remember: Bool = false
  ) async -> Bool {
    var connected = false
    do {
      let result: ConnectProfileOutcome = try await core.call(
        "connect_profile",
        args: ["id": profile.id, "remember": remember ? "true" : "false"].merging(arguments) { $1 })
      switch result {
      case .connected(let outcome):
        connected = true
        if let message = outcome.notice?.message { notice = message }
        record(.info, "Connected \(profile.name)")
      case .credentialsRequired(let prompt):
        presentCredentialPrompt(profile, prompt: prompt)
      }
      error = nil
    } catch { self.error = error.localizedDescription }
    await refreshRuntime()
    return connected
  }
  /// Connects with what the user typed; keeps it in the Keychain on request.
  func submitCredentials(_ request: CredentialRequest, secrets: OpenVpnSecrets, remember: Bool) async {
    credentialRequest = nil
    guard let profile = snapshot?.profiles.first(where: { $0.id == request.profile }),
      !pending.contains(profile.id)
    else { return }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    await connectProfile(
      profile, arguments: secrets.arguments(for: request.needs), remember: remember)
  }
  /// Forgetting uses the same scoped Keychain policy as the CLI.
  func forgetCredentials(_ profile: Profile) async {
    do {
      let outcome: CredentialOutcome = try await core.call(
        "forget_credentials", args: ["id": profile.id])
      if let message = outcome.notice?.message { notice = message }
      error = nil
    } catch { self.error = error.localizedDescription }
  }
  /// Connects NetBird (a browser sign-in opens when it is needed) or, when it
  /// is on, disconnects it. A setup key is used once and never stored.
  func toggleNetBird(managementUrl: String? = nil, setupKey: String? = nil) async {
    guard !netbirdBusy, let current = netbird, current.canToggle else { return }
    netbirdBusy = true
    defer { netbirdBusy = false }
    do {
      if current.isOn && managementUrl == nil {
        netbird = try await core.callConcurrently("netbird_down")
      } else {
        var args: [String: String] = [:]
        if let managementUrl, !managementUrl.isEmpty { args["managementUrl"] = managementUrl }
        if let setupKey, !setupKey.isEmpty { args["setupKey"] = setupKey }
        netbird = try await core.callConcurrently("netbird_up", args: args)
      }
      error = nil
    } catch { self.error = error.localizedDescription }
    await refreshRuntime()
  }
  /// Live rates for the Monitor page, fed only while that page is open.
  var throughput = ThroughputSampler()
  private var interfaceIDs: [String: UInt32] = [:]
  func pollThroughput() async {
    guard let list: [NetworkInterface] = try? await core.callConcurrently("interfaces") else { return }
    let tracked = Set(
      runtime?.statuses.compactMap { $0.state == "running" ? $0.interfaceName : nil } ?? [])
    interfaceIDs = Dictionary(
      list.flatMap { item in [item.name, item.friendlyName].map { ($0, item.ifIndex) } },
      uniquingKeysWith: { first, _ in first })
    throughput.ingest(
      list.map {
        CounterReading(
          id: $0.ifIndex, names: [$0.name, $0.friendlyName], rx: $0.rxBytes, tx: $0.txBytes)
      }, tracked: tracked, now: Date())
  }
  /// The tunnel interface's current rate; nil for a loopback proxy, which has none.
  func rate(of profile: Profile) -> RateSample? {
    status(profile)?.interfaceName.flatMap { interfaceIDs[$0] }.flatMap { throughput.rates[$0] }
  }
  /// Leftovers of a previous session, offered for cleanup once per launch.
  /// Runs before auto-connect so a start never races a cleanup. An answer that
  /// cannot be read (no helper) is not an error: the helper banner covers it.
  var recoveryReport: RecoveryReport?
  var showingRecovery = false
  private var recoveryChecked = false
  func checkRecovery() async {
    guard !recoveryChecked else { return }
    recoveryChecked = true
    guard let report: RecoveryReport = try? await core.call("recovery_report"),
      !report.issues.isEmpty
    else { return }
    recoveryReport = report
    showingRecovery = true
    record(.warn, "Found \(report.issues.count) leftover item(s) from a previous session")
  }
  /// Asks the helper to undo the leftovers; what remains stays listed.
  func cleanUpRecovery() async {
    do {
      let report: RecoveryReport = try await core.call("recovery_cleanup")
      recoveryReport = report.issues.isEmpty ? nil : report
      showingRecovery = !report.issues.isEmpty
      record(
        report.issues.isEmpty ? .info : .warn,
        report.issues.isEmpty
          ? "Cleaned up the leftovers of a previous session"
          : "\(report.issues.count) leftover item(s) remain after cleanup")
      error = nil
    } catch {
      self.error = error.localizedDescription
      recoveryReport = nil
    }
    await refreshRuntime()
  }
  /// Starts the connections flagged "connect when the app starts", once per
  /// launch and in saved order. One that fails does not stop the others; the
  /// count is reported in a notice. A flagged connection that needs the
  /// privileged helper is skipped when it is not serving, never prompting.
  private var autoConnectDone = false
  func autoConnectOnLaunch() async {
    guard !autoConnectDone else { return }
    autoConnectDone = true
    guard let result = await performBatch("auto_connect") else { return }
    let failed = result.items.filter {
      $0.outcome != .succeeded && $0.outcome != .skippedRunning
    }.count
    if failed > 0 {
      record(.warn, "\(failed) connection(s) flagged to start with the app did not start")
      error = nil
      notice = failed == 1 ? "events.autoConnectFailed" : "events.autoConnectPartial"
      autoConnectFailures = failed
    }
  }
  var autoConnectFailures = 0
  private var monitoring: Task<Void, Never>?
  /// Keeps the runtime state fresh for as long as the app runs, window open
  /// or not: Xray can exit on its own (bad server, port taken), and the menu
  /// bar shows these states. Idempotent.
  func startMonitoring() {
    guard monitoring == nil else { return }
    monitoring = Task { [weak self] in
      var tick = 0
      while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(3))
        guard let self else { return }
        await self.refreshRuntime()
        tick += 1
        if tick % 20 == 0 { await self.autoRefreshDue() }
      }
    }
  }
  /// Disconnects every running connection (the menu bar's "Disconnect all").
  func disconnectAll() async {
    _ = await performBatch("disconnect_all")
    await refreshRuntime()
  }
  func setWaitForInterface(_ profile: Profile, enabled: Bool) async {
    _ = await change(
      "set_wait_for_interface", args: ["id": profile.id, "enabled": enabled ? "true" : "false"])
  }
  func setAutoConnect(_ profile: Profile, enabled: Bool) async {
    _ = await change(
      "set_auto_connect", args: ["id": profile.id, "enabled": enabled ? "true" : "false"])
  }
  /// Primary connections take all traffic; secondary ones only their networks.
  func setTunnelRole(_ profile: Profile, role: String) async {
    guard !pending.contains(profile.id) else { return }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    if await change("set_tunnel_role", args: ["id": profile.id, "role": role]) {
      await refreshRuntime()
    }
  }
  /// Saves a secondary connection's networks and split-DNS domains (typed
  /// text, validated by the core). Returns whether it was accepted.
  func setTunnelNetworks(_ profile: Profile, networks: String, dnsDomains: String) async -> Bool {
    let saved = await change(
      "set_tunnel_networks",
      args: ["id": profile.id, "networks": networks, "dnsDomains": dnsDomains])
    if saved { await refreshRuntime() }
    return saved
  }
  /// TUN was requested without a helper: the window offering to install it.
  var helperPrompt = false
  /// The helper was removed because the app changed; shown until it is installed again.
  var helperOutdated = UserDefaults.standard.bool(forKey: "helperOutdatedNotice")
  private var helperCheckDone = false
  private static let helperBuildKey = "helperRegisteredBuild"
  /// Identifies the helper this app ships: app version plus the helper's own
  /// code hash. launchd pins a registered helper to its code hash, so any
  /// change — a new release or just a rebuild — leaves the old registration
  /// unable to start; it is better removed and reinstalled with the user's
  /// knowledge than left as "not responding".
  nonisolated static func currentHelperBuild() -> String? {
    let url = Bundle.main.bundleURL.appendingPathComponent(
      "Contents/MacOS/network-orchestrator-helper")
    guard let data = try? Data(contentsOf: url) else { return nil }
    let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return "\(version ?? "?")|\(hash)"
  }
  /// Once per launch: a registered helper that belongs to another build of the
  /// app is unregistered and the user is told to install it again.
  private func retireOutdatedHelper() async {
    guard !helperCheckDone else { return }
    helperCheckDone = true
    guard HelperManager.registration != .notRegistered,
      let current = Self.currentHelperBuild(),
      UserDefaults.standard.string(forKey: Self.helperBuildKey) != current
    else { return }
    try? await HelperManager.unregister()
    UserDefaults.standard.removeObject(forKey: Self.helperBuildKey)
    UserDefaults.standard.set(true, forKey: "helperOutdatedNotice")
    helperOutdated = true
    await refreshHelper()
  }
  /// Re-reads the launchd registration and asks the helper's socket who answers.
  func refreshHelper() async {
    helperRegistration = HelperManager.registration
    helperStatus = try? await core.callConcurrently("helper_status")
  }
  /// Registers the helper; macOS may still wait for the approval in Login Items.
  func installHelper() async {
    do {
      try HelperManager.register()
      if let build = Self.currentHelperBuild() {
        UserDefaults.standard.set(build, forKey: Self.helperBuildKey)
      }
      UserDefaults.standard.removeObject(forKey: "helperOutdatedNotice")
      helperOutdated = false
    } catch { self.error = "native.helperFailed" }
    await refreshHelper()
    if helperRegistration == .requiresApproval { HelperManager.openSystemSettings() }
  }
  func removeHelper() async {
    do {
      try await HelperManager.unregister()
      UserDefaults.standard.removeObject(forKey: Self.helperBuildKey)
    } catch { self.error = "native.helperFailed" }
    await refreshHelper()
  }
  func connectionLog(_ profile: Profile) async -> String {
    (try? await core.call("log", args: ["id": profile.id]) as String) ?? ""
  }
  /// The helper offers all of `net.intent.*`.
  var canUseIntents: Bool {
    ["net.intent.list", "net.intent.set", "net.intent.del"].allSatisfy(helperOffers)
  }
  /// The helper offers all of `condRules.*`.
  var canUseRules: Bool {
    ["condRules.list", "condRules.put", "condRules.remove"].allSatisfy(helperOffers)
  }
  var rules: [ConditionalRuleEntry] = []
  func loadRules() async {
    guard canUseRules else {
      rules = []
      return
    }
    do {
      rules = try await core.callConcurrently("cond_rules")
    } catch { self.error = error.localizedDescription }
  }
  /// Adds or replaces a rule; the helper evaluates it at once.
  func saveRule(_ draft: RuleDraft) async -> Bool {
    do {
      let _: RuleStatus = try await core.call("put_cond_rule", args: draft.arguments)
      record(.info, "Saved conditional rule \(draft.id.trimmingCharacters(in: .whitespaces))")
      await loadRules()
      return true
    } catch {
      self.error = error.localizedDescription
      return false
    }
  }
  func deleteRule(_ entry: ConditionalRuleEntry) async {
    do {
      let _: [String: Bool] = try await core.call("delete_cond_rule", args: ["id": entry.id])
      record(.info, "Deleted conditional rule \(entry.id)")
      await loadRules()
    } catch { self.error = error.localizedDescription }
  }
  func setRuleEnabled(_ entry: ConditionalRuleEntry, enabled: Bool) async {
    var draft = RuleDraft(editing: entry)
    draft.enabled = enabled
    _ = await saveRule(draft)
  }
  var intents: [RouteIntent] = []
  /// Reads the intents from the helper; none (and no error) without it.
  func loadIntents() async {
    guard canUseIntents else {
      intents = []
      return
    }
    do {
      // Static-route profiles keep theirs here too; their own switch owns them.
      let all: [RouteIntent] = try await core.callConcurrently("intents")
      intents = all.filter { !$0.isProfileOwned }
    } catch { self.error = error.localizedDescription }
  }
  var suggestions: [IntentSuggestion] = []
  private var dismissedSuggestions = Set<String>()
  /// Doctor cards the user has not dismissed in this session.
  var visibleSuggestions: [IntentSuggestion] {
    suggestions.filter { !dismissedSuggestions.contains($0.key) }
  }
  func dismissSuggestion(_ suggestion: IntentSuggestion) {
    dismissedSuggestions.insert(suggestion.key)
  }
  /// Asks the doctor; a helper without intents, or any failure, means no
  /// cards and no banner: the doctor is advice, never an error.
  func loadSuggestions() async {
    guard canUseIntents,
      let list: [IntentSuggestion] = try? await core.callConcurrently("intent_doctor")
    else {
      suggestions = []
      return
    }
    suggestions = list
  }
  /// Creates the intents a card proposes, then refreshes both lists.
  func applyFix(_ suggestion: IntentSuggestion) async -> Bool {
    do {
      let payload = String(decoding: try JSONEncoder().encode(suggestion.fixes), as: UTF8.self)
      let result: IntentFixOutcome = try await core.call(
        "apply_intent_fixes", args: ["payload": payload])
      for fix in suggestion.fixes.prefix(result.applied) {
        record(.info, "Saved routing intent \(fix.id) proposed by the doctor")
      }
      await loadIntents()
      if let failure = result.error {
        error = failure
        return false
      }
      guard result.applied == suggestion.fixes.count else {
        error = L10n.text("The operation could not be completed")
        return false
      }
      dismissSuggestion(suggestion)
      await loadSuggestions()
      return true
    } catch {
      self.error = error.localizedDescription
      return false
    }
  }
  /// Adds or replaces an intent; the helper installs its routes at once.
  func saveIntent(_ draft: IntentDraft) async -> Bool {
    do {
      let _: [String: String] = try await core.call("set_intent", args: draft.arguments)
      record(.info, "Saved routing intent \(draft.id.trimmingCharacters(in: .whitespaces))")
      await loadIntents()
      return true
    } catch {
      self.error = error.localizedDescription
      return false
    }
  }
  func deleteIntent(_ intent: RouteIntent) async {
    do {
      let _: [String: String] = try await core.call("delete_intent", args: ["id": intent.id])
      record(.info, "Deleted routing intent \(intent.id)")
      await loadIntents()
    } catch { self.error = error.localizedDescription }
  }
  func setIntentEnabled(_ intent: RouteIntent, enabled: Bool) async {
    var draft = IntentDraft(editing: intent)
    draft.enabled = enabled
    _ = await saveIntent(draft)
  }
  /// The helper offers `link.set_state`, and this is not loopback or the
  /// device of a connection this app runs (those are stopped by disconnecting).
  func canSwitch(_ interface: NetworkInterface) -> Bool {
    helperOffers("link.set_state") && interface.name != "lo0"
      && !ownTunnelInterfaces.contains(interface.name)
  }
  /// What the confirmation says before an interface is turned off.
  func switchOffWarning(_ interface: NetworkInterface) -> String {
    interface.name == primaryInterface ? "native.link.offDefault" : "native.link.off"
  }
  var switchingInterface = false
  /// Turns an interface on or off through the helper, then reloads the lists.
  func setInterfaceState(_ interface: NetworkInterface, up: Bool) async -> Bool {
    switchingInterface = true
    defer { switchingInterface = false }
    do {
      let _: [String: String] = try await core.call(
        "set_interface_state", args: ["name": interface.name, "up": up ? "true" : "false"])
      record(.info, "\(up ? "Turned on" : "Turned off") \(interface.name)")
      await refresh()
      return true
    } catch {
      self.error = error.localizedDescription
      return false
    }
  }
  /// The system's DNS resolvers (`scutil --dns`), read-only.
  var dnsConfig: DnsConfig?
  func loadDns() async {
    do {
      dnsConfig = try await core.callConcurrently("dns_status")
    } catch { self.error = error.localizedDescription }
  }
  /// One real DNS query; with no `server` it goes where the system would send
  /// that name. Nil with `error` set when it cannot be done.
  func probeDns(host: String, server: String, ipv6: Bool) async -> DnsProbeAnswer? {
    do {
      return try await core.callConcurrently(
        "dns_probe", args: ["hostname": host, "server": server, "family": ipv6 ? "aaaa" : "a"])
    } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  /// Runs every check for one connection (the helper's and the app's view,
  /// static analysis, routes); nil with `error` set when it cannot be done.
  func diagnose(_ profile: Profile) async -> ProfileDiagnostics? {
    do {
      return try await core.call("diagnose", args: ["id": profile.id])
    } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  /// The text behind one entry of the Logs page.
  func logText(for source: LogSource) async -> String {
    switch source {
    case .app: appLog.text
    case .importer: await importLog()
    case .helper: (try? await core.call("helper_log") as String) ?? ""
    case .netbird: (try? await core.call("netbird_log") as String) ?? ""
    case .connection(let id):
      if let profile = snapshot?.profiles.first(where: { $0.id == id }) {
        await connectionLog(profile)
      } else {
        ""
      }
    }
  }
  func importLog() async -> String {
    (try? await core.call("import_log") as String) ?? ""
  }
  /// Saves the rule sets and DNS options; a running connection restarts to apply them.
  func setRoutingRules(_ profile: Profile, options: RoutingOptions) async -> Bool {
    var args = options.bridgeArgs
    args["id"] = profile.id
    return await change("set_routing_rules", args: args)
  }
  func routingOptions(_ profile: Profile) async -> RoutingOptions? {
    try? await core.call("routing_options", args: ["id": profile.id])
  }
  /// Parses a Happ/Incy export without touching the profile.
  func parseHappRouting(_ payload: String) async -> HappRouting? {
    do { return try await core.call("parse_happ_routing", args: ["payload": payload]) } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  /// Replays the draft rules for one host or IP, offline.
  func checkRoute(_ target: String, options: RoutingOptions) async -> RouteCheckResult? {
    var args = options.bridgeArgs
    args["target"] = target
    do { return try await core.call("check_route", args: args) } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  func remove(_ profile: Profile) async { _ = await change("delete", args: ["id": profile.id]) }
  private func change(_ method: String, args: [String: String]) async -> Bool {
    guard !busy else { return false }
    busy = true
    do {
      let _: [Profile] = try await core.call(method, args: args)
      busy = false
      await refresh()
      return true
    } catch {
      busy = false
      self.error = error.localizedDescription
      return false
    }
  }
  func inspect(_ profile: Profile) async {
    inspecting = profile
    inspection = nil
    do { inspection = try await core.call("inspect", args: ["id": profile.id]) } catch {
      self.error = error.localizedDescription
    }
  }
  /// Reads system files and the kernel table only; no store lock is taken.
  func loadUserNetwork() async {
    do { userNetwork = try await core.callConcurrently("user_network_settings") } catch {
      self.error = error.localizedDescription
    }
  }
  func lookupRoute() async {
    lookup = nil
    do {
      lookup = try await core.call(
        "lookup",
        args: ["destination": lookupDestination.trimmingCharacters(in: .whitespacesAndNewlines)])
    } catch { self.error = error.localizedDescription }
  }
}
