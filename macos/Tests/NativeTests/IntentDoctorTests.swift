import Foundation
import Testing

@testable import NetworkOrchestrator

private func suggestionJSON(
  key: String = "endpoint-via-tunnel:utun5:91.245.41.31", kind: String = "endpointViaTunnel",
  via: String? = "utun5", intent: String? = nil, destination: String? = nil,
  endpoints: [String] = ["91.245.41.31"], foreign: [String: Any]? = nil, withFix: Bool = true
) -> [String: Any] {
  var object: [String: Any] = [
    "key": key, "kind": kind, "endpoints": endpoints,
    "fixes": withFix
      ? [[
        "id": "bypass-utun5", "destinations": endpoints.map { "\($0)/32" },
        "path": ["kind": "direct"], "metric": 50,
      ]] : [],
  ]
  if let via { object["viaInterface"] = via }
  if let intent { object["intentId"] = intent }
  if let destination { object["destination"] = destination }
  if let foreign { object["foreignRoute"] = foreign }
  return object
}

private func decode(_ object: Any) throws -> [IntentSuggestion] {
  try JSONDecoder().decode(
    [IntentSuggestion].self, from: JSONSerialization.data(withJSONObject: object))
}

@Test func suggestionsDecodeFromTheBridgeAnswer() throws {
  let list = try decode([
    suggestionJSON(),
    suggestionJSON(
      key: "conflict:media:203.0.113.0/24", kind: "conflict", via: nil, intent: "media",
      destination: "203.0.113.0/24", endpoints: [],
      foreign: ["destination": "203.0.113.0", "prefixLen": 24, "gateway": NSNull(), "interfaceIndex": 4, "interfaceName": "en0", "metric": 0],
      withFix: false),
  ])
  #expect(list[0].kind == .endpointViaTunnel && list[0].viaInterface == "utun5")
  #expect(list[0].fixes.count == 1 && list[0].id == list[0].key)
  #expect(list[1].kind == .conflict && list[1].intentId == "media")
  #expect(list[1].foreignRoute?.interfaceName == "en0" && list[1].fixes.isEmpty)
}

@Test func aKindFromANewerClientDoesNotBreakTheList() throws {
  let list = try decode([suggestionJSON(kind: "somethingNew")])
  #expect(list[0].kind == .unknown)
}


@Test func theCardTextFollowsTheKind() throws {
  let list = try decode([
    suggestionJSON(),
    suggestionJSON(key: "u", kind: "uncoveredEndpoints", via: "utun9", endpoints: ["1.1.1.1", "2.2.2.2"]),
    suggestionJSON(
      key: "c", kind: "conflict", via: nil, intent: "media", destination: "203.0.113.0/24",
      endpoints: [],
      foreign: ["destination": "203.0.113.0", "prefixLen": 24, "interfaceIndex": 4, "interfaceName": "en0", "metric": 0],
      withFix: false),
  ])
  #expect(list[0].titleKey == "intents.doctor.endpointTitle" && list[0].detailKey == "intents.doctor.endpointDetail")
  #expect(list[1].titleKey == "intents.doctor.uncoveredTitle" && list[1].detailKey == "intents.doctor.endpointDetailPlural")
  #expect(list[2].titleKey == "intents.doctor.conflictTitle" && list[2].detailKey == "intents.doctor.conflictDetail")
  #expect(list[0].canFix && list[1].canFix && !list[2].canFix)
}

@Test @MainActor func aDismissedCardStaysHiddenForTheSession() throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.suggestions = try decode([suggestionJSON(key: "a"), suggestionJSON(key: "b")])
  #expect(model.visibleSuggestions.map(\.key) == ["a", "b"])
  model.dismissSuggestion(model.suggestions[0])
  #expect(model.visibleSuggestions.map(\.key) == ["b"])
  // The same card coming back from the next poll stays hidden.
  model.suggestions = try decode([suggestionJSON(key: "a"), suggestionJSON(key: "b")])
  #expect(model.visibleSuggestions.map(\.key) == ["b"])
}

@Test @MainActor func withoutAnIntentHelperThereAreNoSuggestionsAndNoError() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.suggestions = try decode([suggestionJSON()])
  await model.loadSuggestions()  // no helper offers intents here
  #expect(model.suggestions.isEmpty && model.error == nil)
}
