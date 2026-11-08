import Foundation
import Testing

@testable import NetworkOrchestrator

private let link = "vless://synthetic-private-id@node.test:443?security=tls#"

/// A model over a temp store holding the given connections (flags set through
/// the bridge, as the UI does). Starting is disabled, so nothing ever connects.
@MainActor private func model(
  _ names: [(name: String, autoConnect: Bool)],
  directory: URL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
) async throws -> (AppModel, [Profile]) {
  let core = CoreBridge(root: directory)
  for (index, entry) in names.enumerated() {
    let _: [Profile] = try await core.call(
      "import_share_link",
      args: ["id": "p\(index)", "name": "", "link": link + entry.name])
    if entry.autoConnect {
      let _: [Profile] = try await core.call(
        "set_auto_connect", args: ["id": "p\(index)", "enabled": "true"])
    }
  }
  // Shared policy prevents every managed start; the test never launches a service or VPN.
  let _: AppSettings = try await core.call("set_app_mode", args: ["mode": "orchestrator"])
  let model = AppModel(dataDirectory: directory)
  model.snapshot = try await core.call("snapshot")
  return (model, model.snapshot?.profiles ?? [])
}

private func running(_ ids: [String]) throws -> RuntimeState {
  try JSONDecoder().decode(
    RuntimeState.self,
    from: JSONSerialization.data(withJSONObject: [
      "xrayInstalled": true, "xrayVersion": "v", "systemProxyOwner": NSNull(),
      "statuses": ids.map { ["profileId": $0, "state": "running"] },
    ]))
}

@Test func theFlagIsSavedPerConnectionAndSurvivesTheSnapshot() async throws {
  let (_, profiles) = try await model([("a", false), ("b", true), ("c", false)])
  #expect(profiles.map(\.connectsOnLaunch) == [false, true, false])
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let core = CoreBridge(root: directory)
  let _: [Profile] = try await core.call(
    "import_share_link", args: ["id": "x", "name": "", "link": link + "x"])
  let on: [Profile] = try await core.call("set_auto_connect", args: ["id": "x", "enabled": "true"])
  #expect(on.first?.connectsOnLaunch == true)
  let off: [Profile] = try await core.call("set_auto_connect", args: ["id": "x", "enabled": "false"])
  #expect(off.first?.connectsOnLaunch == false)
  do {
    let _: [Profile] = try await core.call(
      "set_auto_connect", args: ["id": "missing", "enabled": "true"])
    Issue.record("An unknown connection must be rejected")
  } catch {
    #expect(error.localizedDescription == "Profile not found")
  }
}

@Test @MainActor func aConnectionWithoutTheFlagIsNeverStartedOrReported() async throws {
  let (model, _) = try await model([("a", false), ("b", false)])
  await model.autoConnectOnLaunch()
  #expect(model.notice == nil && model.error == nil && model.autoConnectFailures == 0)
}

@Test @MainActor func flaggedConnectionsThatCannotStartAreCountedNotPrompted() async throws {
  let (one, _) = try await model([("a", true), ("b", false)])
  await one.autoConnectOnLaunch()
  #expect(one.notice == "events.autoConnectFailed")
  #expect(one.autoConnectFailures == 1)
  #expect(!one.helperPrompt && one.error == nil && one.pending.isEmpty)

  let (several, _) = try await model([("a", true), ("b", true), ("c", true)])
  several.error = "stale"
  await several.autoConnectOnLaunch()
  #expect(several.notice == "events.autoConnectPartial")
  #expect(several.autoConnectFailures == 3)
  #expect(several.error == nil)  // the notice replaces a stale error
}


@Test @MainActor func autoConnectRunsOncePerLaunch() async throws {
  let (model, _) = try await model([("a", true)])
  await model.autoConnectOnLaunch()
  #expect(model.notice == "events.autoConnectFailed")
  model.notice = nil
  await model.autoConnectOnLaunch()  // e.g. the window is reopened
  #expect(model.notice == nil)
}


@Test @MainActor func disconnectAllDoesNothingWhenNothingRuns() async throws {
  let (model, _) = try await model([("a", true)])
  await model.disconnectAll()
  #expect(model.error == nil && model.pending.isEmpty)
  #expect(model.activeCount == 0)
}

@Test @MainActor func theMenuBarCountsOnlyRunningConnections() async throws {
  let (model, profiles) = try await model([("a", false), ("b", false), ("c", false)])
  #expect(model.activeCount == 0)
  model.runtime = try running(["p0", "p2"])
  #expect(model.activeCount == 2)
  #expect(profiles.filter { model.isRunning($0) }.map(\.id) == ["p0", "p2"])
}

@Test func recoveryReportsDecodeFromTheBridgeAnswer() async throws {
  let report = try JSONDecoder().decode(
    RecoveryReport.self,
    from: Data(
      #"{"issues":[{"kind":"leftoverTunnel","profileId":"wg1","message":"m"}],"requiresElevation":false}"#
        .utf8))
  #expect(report.issues.first?.kind == "leftoverTunnel")
  #expect(report.issues.first?.profileId == "wg1" && !report.requiresElevation)

  // The real method, read-only: it lists helper records or answers with none.
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let live: RecoveryReport = try await CoreBridge(root: directory).call("recovery_report")
  #expect(!live.requiresElevation)
}

