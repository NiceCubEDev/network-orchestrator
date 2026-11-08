import Foundation
import Network

/// The user's own NetBird daemon as the bridge summarises it (no keys, no events).
struct NetBirdState: Decodable, Sendable, Equatable {
  let installed: Bool
  /// connected, connecting, disconnected, needsLogin, daemonStopped,
  /// notInstalled or unavailable.
  let state: String
  var ip: String? = nil
  var fqdn: String? = nil
  var version: String? = nil
  var managementUrl: String? = nil
  var peersConnected: Int? = nil
  var peersTotal: Int? = nil
  var sessionExpiresAt: String? = nil
  var networks: [String]? = nil
  var isOn: Bool { state == "connected" || state == "connecting" }
  /// The daemon can be asked to connect.
  var canToggle: Bool { installed && state != "daemonStopped" && state != "unavailable" }
}

/// The user's own Tailscale as the bridge summarises it (no keys, no peer names).
struct TailscaleState: Decodable, Sendable, Equatable {
  let installed: Bool
  /// connected, connecting, disconnected, needsLogin, notInstalled or unavailable.
  let state: String
  var ip: String? = nil
  var tailnet: String? = nil
  var host: String? = nil
  var version: String? = nil
  var peersOnline: Int? = nil
  var peersTotal: Int? = nil
  var exitNode: Bool? = nil
  /// The page to finish signing in on; only while sign-in is needed.
  var authUrl: String? = nil
  var isOn: Bool { state == "connected" || state == "connecting" }
  var canToggle: Bool { installed && state != "unavailable" }
}

/// What the helper does to keep Tailscale reachable next to a tunnel.
struct TailscaleGuardState: Decodable, Sendable, Equatable {
  /// protected, idle, off, unsupported or unavailable.
  let state: String
  var interface: String? = nil
  var pinned: [String]? = nil
  var bypassed: Int? = nil
}

struct Capabilities: Decodable, Sendable {
  let os: String
  let minimumOS: String
  let nativeUI: Bool
  let networkMutations: Bool
  let proxyConnections: Bool?
  let version: String
}

struct TunnelStatus: Decodable, Sendable {
  let profileId: String
  let state: String
  let message: String?
  /// `utunN` of a running full tunnel; nil for loopback proxies.
  var interfaceName: String? = nil
}
struct RuntimeState: Decodable, Sendable {
  let xrayInstalled: Bool
  let xrayVersion: String
  let statuses: [TunnelStatus]
  let systemProxyOwner: String?
}

struct AppSettings: Decodable, Sendable {
  let appMode: AppMode
}

struct LegacyStateImport: Decodable, Sendable {
  let settings: AppSettings
  let sets: [ConnectionSet]
  let imported: Bool
}

struct ProfileStartEligibility: Decodable, Sendable {
  let profileId: String
  let canStart: Bool
  let canTryStart: Bool
  let modeBlocked: Bool
}

struct BatchOutcome: Decodable, Sendable {
  let items: [BatchItem]
}

struct BatchItem: Decodable, Sendable {
  let profileId: String
  let action: String
  let outcome: BatchItemOutcome
  let error: String?
  let credentialPrompt: CredentialPrompt?
}

enum BatchItemOutcome: String, Decodable, Sendable {
  case succeeded, skippedRunning, unavailable, credentialsRequired, failed
}

struct ProxyExports: Decodable, Sendable {
  let httpProxy: String
  let httpsProxy: String
  let allProxy: String
  let noProxy: String
  let shell: String
}

struct ProxyOverrideStatus: Decodable, Sendable {
  let primaryInterface: String?
  let overridden: Bool
  let reason: String?
}

struct IntentFixOutcome: Decodable, Sendable {
  let applied: Int
  let error: String?
}

struct Profile: Decodable, Identifiable, Sendable {
  let id: String
  let name: String
  let backend: String
  let interfaceName: String
  let routes: [PolicyRoute]
  let xraySocksPort: UInt16?
  let xrayHttpPort: UInt16?
  let subscription: SubscriptionMeta?
  let xrayMode: String?
  /// "primary" (default) or "secondary": a secondary connection carries only
  /// `tunnelNetworks`, the primary owns the default route and the system DNS.
  var tunnelRole: String? = nil
  var tunnelNetworks: [String]? = nil
  var tunnelDnsDomains: [String]? = nil
  var isSecondary: Bool { tunnelRole == "secondary" }
  /// Static-route profiles: arm the routes while the interface is absent.
  var waitForInterface: Bool? = nil
  /// Started once when the app launches.
  var autoConnect: Bool? = nil
  var connectsOnLaunch: Bool { autoConnect == true }
  var domainPolicies: [DomainPolicy]? = nil
  var privateLanDirect: Bool? = nil
  var xrayDns: DnsSummary? = nil
  /// Rule lines of one target (block / proxy / direct), comments included.
  func rules(_ target: String) -> [String] {
    (domainPolicies ?? []).filter { $0.target == target }.flatMap(\.domains)
  }
  /// Name shown for the profile: a generated "{provider} - {server}" name
  /// reads as the provider group, a user-chosen name is shown as typed.
  var groupName: String {
    guard let title = subscription?.providerTitle, !title.isEmpty,
      name == title || [" · ", " - "].contains(where: { name.hasPrefix(title + $0) })
    else { return name }
    return title
  }
  /// A server name without the provider prefix the panel repeats on each.
  func serverLabel(_ server: String) -> String {
    guard let title = subscription?.providerTitle, !title.isEmpty else { return server }
    for separator in [" · ", " - ", " – ", " — ", " | "] where server.hasPrefix(title + separator) {
      return String(server.dropFirst(title.count + separator.count))
    }
    return server
  }
  /// Xray in loopback SOCKS/HTTP mode is the only kind this client can start
  /// without the privileged helper.
  var startsWithoutHelper: Bool { backend == "xray" && (xrayMode ?? "socks") == "socks" }
  /// Xray as a system-wide tunnel; the privileged helper owns it.
  var isTun: Bool { backend == "xray" && xrayMode == "tun" }
  /// Fixed routes through a named interface, kept by the helper as an intent.
  var isStatic: Bool { backend == "none" }
  /// Everything that creates a tunnel device runs in the privileged helper:
  /// Xray TUN, WireGuard and OpenVPN.
  var runsTunnel: Bool { isTun || backend == "wireGuard" || backend == "openVpn" }
  /// Starting needs the helper: a tunnel's, or the route intents of a static
  /// profile.
  var needsHelper: Bool { runsTunnel || isStatic }
  /// Whether routes are armed while the interface is absent.
  var waitsForInterface: Bool { waitForInterface == true }
  /// The helper capability that serves this profile.
  var helperCapability: String? {
    switch backend {
    case "wireGuard": "wireguard.connect"
    case "openVpn": "openvpn.connect"
    case "xray": isTun ? "xray.connect" : nil
    case "none": "net.intent.set"
    default: nil
    }
  }
  var kind: String {
    switch backend {
    case "wireGuard": "WireGuard"
    case "openVpn": "OpenVPN"
    case "xray": "Xray"
    default: "Static routes"
    }
  }
  var symbol: String {
    switch backend {
    case "wireGuard": "shield.lefthalf.filled"
    case "openVpn": "lock.shield"
    case "xray": "network"
    default: "arrow.triangle.branch"
    }
  }
}

struct SubscriptionMeta: Decodable, Sendable {
  let endpointCount: Int
  let activeIndex: Int
  let userInfo: SubscriptionUsage?
  var refreshIntervalMinutes: UInt32? = nil
  var lastRefreshAtUnix: UInt64? = nil
  var lastRefreshError: String? = nil
  /// What the provider announces about the subscription (response headers).
  let providerTitle: String?
  let announce: String?
  let supportUrl: String?
  let webPageUrl: String?
  let updateIntervalHours: UInt32?
  let skippedProtocols: [String]?
}
struct DomainPolicy: Decodable, Sendable {
  let domains: [String]
  let target: String
}
struct SubscriptionUsage: Decodable, Sendable {
  let uploadBytes: UInt64
  let downloadBytes: UInt64
  let totalBytes: UInt64?
  let expiresAtUnix: UInt64?
}
struct DelayResult: Decodable, Sendable {
  let index: Int
  let delayMs: UInt64?
}
struct RefreshOutcome: Decodable, Sendable {
  let endpointCount: Int
  let activeIndex: Int
  let skippedCount: Int
  let fallbackUsed: Bool
}
struct SubscriptionEndpoint: Decodable, Sendable {
  let name: String
  let active: Bool
  var `protocol`: String? = nil
}
struct SubscriptionImportResult: Decodable, Sendable {
  let profiles: [Profile]
  let skippedCount: Int
}

struct PolicyRoute: Decodable, Sendable {
  let destination: String
  let metric: UInt32
  let via: String?
}
struct NetworkAddress: Decodable, Sendable {
  let address: String
  let prefixLen: UInt8
  let family: String
}
enum InterfaceKindValue: Decodable, Sendable {
  case named(String)
  case other(String)
  init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer()
    if let name = try? value.decode(String.self) {
      self = .named(name)
    } else {
      self = .other(try value.decode([String: String].self)["other"] ?? "Other")
    }
  }
  var label: String {
    switch self {
    case .named(let value):
      value == "ethernet" ? "Ethernet" : value == "loopback" ? "Loopback" : value.capitalized
    case .other(let value): value
    }
  }
}
struct NetworkInterface: Decodable, Identifiable, Sendable {
  let name: String
  let friendlyName: String
  let ifIndex: UInt32
  let state: String
  let addresses: [NetworkAddress]
  let category: String
  let kind: InterfaceKindValue
  let physical: Bool
  let description: String
  let mtu: UInt32?
  let mac: String?
  let gateway: String?
  let ipv6Gateway: String?
  let dnsServers: [String]
  let dnsSuffix: String?
  let linkSpeedMbps: UInt64?
  let rxBytes: UInt64?
  let txBytes: UInt64?
  let tunnelType: String?
  var id: UInt32 { ifIndex }
}
struct Route: Decodable, Identifiable, Sendable {
  let destination: String
  let prefixLen: UInt8
  let gateway: String?
  let interfaceIndex: UInt32
  let interfaceName: String
  let metric: UInt32
  var cidr: String { "\(destination)/\(prefixLen)" }
  var id: String { "\(cidr)|\(interfaceIndex)|\(gateway ?? "")|\(metric)" }
}
/// Routing settings a person made on this Mac (`user_network_settings`).
struct UserNetworkSettings: Decodable, Sendable {
  struct PersistentRoute: Decodable, Sendable {
    let service: String
    let interface: String?
    let destination: String
    let gateway: String?
    let active: Bool
  }
  struct StaticRoute: Decodable, Sendable {
    let destination: String
    let gateway: String
    let interface: String
    let flags: String
    let source: String
  }
  struct StartupJob: Decodable, Sendable {
    let label: String
    let path: String
    let scope: String
    let command: String
    let runAtLoad: Bool
    let intervalSeconds: UInt64?
    let route: String?
    let active: Bool?
  }
  struct Resolver: Decodable, Sendable {
    let domain: String
    let nameservers: [String]
    let port: UInt16?
    let searchOrder: UInt32?
  }
  struct HostEntry: Decodable, Sendable {
    let address: String
    let names: [String]
  }
  struct Setting: Decodable, Sendable {
    let kind: String
    let value: String
  }
  struct Service: Decodable, Sendable {
    let service: String
    let interface: String?
    let enabled: Bool
    let items: [Setting]
  }
  let persistentRoutes: [PersistentRoute]
  let staticRoutes: [StaticRoute]
  let startupJobs: [StartupJob]
  let resolvers: [Resolver]
  let hosts: [HostEntry]
  let services: [Service]
  let unreadable: [String]
}
struct PlannedRoute: Decodable, Sendable {
  let destination: String
  let ownerProfileId: String
  let ownerName: String
  let interfaceName: String?
  let active: Bool
  let source: String
  let metric: UInt32?
}
struct RouteDiff: Decodable, Sendable {
  let kind: String
  let destination: String
  let message: String
}
struct RouteMap: Decodable, Sendable {
  let predicted: [PlannedRoute]
  let warnings: [String]
  let diffs: [RouteDiff]
}
/// What a crashed session left behind (leftover tunnels, a stale system proxy).
struct RecoveryIssue: Decodable, Sendable, Equatable {
  let kind: String
  let profileId: String?
  let message: String
}
struct RecoveryReport: Decodable, Sendable, Equatable {
  let issues: [RecoveryIssue]
  let requiresElevation: Bool
}

enum DiagnosticLevel: String, Decodable, Sendable, Comparable {
  case healthy, warning, error
  private var rank: Int {
    switch self {
    case .healthy: 0
    case .warning: 1
    case .error: 2
    }
  }
  static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}
struct DiagnosticCheck: Decodable, Sendable, Identifiable {
  let name: String
  let level: DiagnosticLevel
  let message: String
  var id: String { name + "\u{1}" + message }
}
struct DiagnosticCounts: Equatable, Sendable {
  var warnings: Int
  var errors: Int
}
/// The checks `diagnose` returns for one connection.
struct ProfileDiagnostics: Decodable, Sendable {
  let profileId: String
  let status: TunnelStatus
  let checks: [DiagnosticCheck]
  var worst: DiagnosticLevel { checks.map(\.level).max() ?? .healthy }
  var counts: DiagnosticCounts {
    DiagnosticCounts(
      warnings: checks.filter { $0.level == .warning }.count,
      errors: checks.filter { $0.level == .error }.count)
  }
}

/// One block of `scutil --dns`.
struct DnsResolver: Decodable, Sendable, Identifiable {
  let index: UInt32
  let domain: String?
  let searchDomains: [String]
  let nameservers: [String]
  let port: UInt16?
  let scoped: Bool
  let interface: String?
  let ifIndex: UInt32?
  let supplemental: Bool
  let mdns: Bool
  let reachable: Bool
  let order: UInt32?
  let timeout: UInt32?
  let flags: [String]
  /// The same index appears in both sections, so the section is part of it.
  var id: String { "\(scoped ? "scoped" : "global")-\(index)" }
  /// The domain it is for; nil for the default resolver.
  var title: String? { domain }
  /// `10.0.0.1`, or `[fd00::1]:5353` when the port is not the DNS default.
  var serverTexts: [String] {
    nameservers.map { address in
      guard let port, port != 53 else { return address }
      return address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
    }
  }
}
struct DnsConfig: Decodable, Sendable {
  let resolvers: [DnsResolver]
  let scoped: [DnsResolver]
}
struct DnsProbe: Decodable, Sendable {
  let server: String
  let port: UInt16
  let status: String
  let answers: [String]
  let truncated: Bool
  let fakePool: Bool
  let rttMs: UInt64
}
struct DnsProbePath: Decodable, Sendable {
  let interfaceName: String
  let gateway: String?
}
struct DnsProbeAnswer: Decodable, Sendable {
  let probe: DnsProbe
  let resolverIndex: UInt32?
  let resolverDomain: String?
  let path: DnsProbePath?
}

/// How an intent compares with the system, as the helper reports it. A status
/// a newer helper adds reads as `unknown` instead of breaking the list.
enum IntentStatus: String, Decodable, Sendable {
  case effective, active, deferred, conflicted, missing, disabled, unknown
  init(from decoder: Decoder) throws {
    let text = try decoder.singleValueContainer().decode(String.self)
    self = IntentStatus(rawValue: text) ?? .unknown
  }
  var badgeColor: String {
    switch self {
    case .effective, .active: "up"
    case .deferred: "info"
    case .conflicted: "down"
    case .missing: "warn"
    case .disabled, .unknown: "unknown"
    }
  }
  var label: String {
    switch self {
    case .effective, .active: "native.intents.status.effective"
    case .deferred: "native.intents.status.deferred"
    case .conflicted: "native.intents.status.conflicted"
    case .missing: "native.intents.status.missing"
    case .disabled: "native.intents.status.disabled"
    case .unknown: "native.intents.status.unknown"
    }
  }
}
/// "These networks go this way", kept and enforced by the helper.
struct RouteIntent: Decodable, Identifiable, Sendable {
  struct Path: Codable, Sendable {
    let kind: String
    let interface: String?
  }
  let id: String
  let destinations: [String]
  let path: Path
  let metric: UInt32
  let enabled: Bool
  let status: IntentStatus
  let detail: String
  let installed: Int
  let wanted: Int
  /// Created for a static-route profile (`core::route_intents::STATIC_PREFIX`);
  /// its connection switch owns it, not the Intents page.
  var isProfileOwned: Bool { id.hasPrefix("static-") }
  var isDirect: Bool { path.kind == "direct" }
  var pathText: String { isDirect ? "direct" : (path.interface ?? "?") }
  /// All of the internet, or its halves (`0.0.0.0/1`): what a full tunnel
  /// uses. The page warns before and after such an intent exists.
  static func capturesDefault(_ destinations: [String]) -> Bool {
    destinations.contains { text in
      let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/")
      guard parts.count == 2, let prefix = Int(parts[1]), prefix <= 1 else { return false }
      let address = String(parts[0])
      return IPv4Address(address) != nil || IPv6Address(address) != nil
    }
  }
}
/// What the intent doctor noticed. A kind a newer core adds reads as `unknown`.
enum SuggestionKind: String, Decodable, Sendable {
  case endpointViaTunnel, uncoveredEndpoints, conflict, unknown
  init(from decoder: Decoder) throws {
    let text = try decoder.singleValueContainer().decode(String.self)
    self = SuggestionKind(rawValue: text) ?? .unknown
  }
}
/// A ready-made intent the doctor proposes.
struct IntentFix: Codable, Sendable {
  let id: String
  let destinations: [String]
  let path: RouteIntent.Path
  let metric: UInt32?
  let enabled: Bool?
}
struct IntentSuggestion: Decodable, Identifiable, Sendable {
  let key: String
  let kind: SuggestionKind
  let viaInterface: String?
  let intentId: String?
  let destination: String?
  let endpoints: [String]
  let foreignRoute: Route?
  let fixes: [IntentFix]
  var id: String { key }
  var canFix: Bool { !fixes.isEmpty }
  /// Catalogue keys shared with the web client.
  var titleKey: String {
    switch kind {
    case .endpointViaTunnel: "intents.doctor.endpointTitle"
    case .uncoveredEndpoints: "intents.doctor.uncoveredTitle"
    case .conflict, .unknown: "intents.doctor.conflictTitle"
    }
  }
  var detailKey: String {
    switch kind {
    case .endpointViaTunnel: "intents.doctor.endpointDetail"
    case .uncoveredEndpoints: "intents.doctor.endpointDetailPlural"
    case .conflict, .unknown: "intents.doctor.conflictDetail"
    }
  }
}
/// Whether a conditional rule currently holds. A state a newer helper adds
/// reads as `unknown`.
enum RuleState: String, Decodable, Sendable {
  case active, inactive, disabled, error, unknown
  init(from decoder: Decoder) throws {
    let text = try decoder.singleValueContainer().decode(String.self)
    self = RuleState(rawValue: text) ?? .unknown
  }
  var badgeColor: String {
    switch self {
    case .active: "up"
    case .error: "down"
    case .inactive, .disabled, .unknown: "unknown"
    }
  }
  /// Catalogue keys shared with the web client.
  var label: String {
    switch self {
    case .active: "cond.stateActive"
    case .inactive: "cond.stateInactive"
    case .disabled: "cond.stateDisabled"
    case .error, .unknown: "cond.stateError"
    }
  }
  var hint: String {
    switch self {
    case .active: "cond.hintActive"
    case .inactive: "cond.hintInactive"
    case .disabled: "cond.hintDisabled"
    case .error, .unknown: "cond.hintError"
    }
  }
}
struct RuleStatus: Decodable, Sendable {
  let state: RuleState
  let matchedInterface: String?
  let appliedRoutes: Int
  let detail: String?
}
struct RuleRoute: Decodable, Sendable {
  let destination: String
  let metric: UInt32
  let via: String?
  /// As the form takes it: `10.99.0.0/24` or `10.99.0.0/24 via 10.1.1.1`.
  var text: String { via.map { "\(destination) via \($0)" } ?? destination }
}
/// A route set that exists only while a condition holds.
struct ConditionalRule: Decodable, Sendable {
  struct Condition: Decodable, Sendable {
    let kind: String
    let prefix: String
  }
  let id: String
  let name: String
  let enabled: Bool
  let condition: Condition
  let routes: [RuleRoute]
  var prefix: String { condition.prefix }
}
struct ConditionalRuleEntry: Decodable, Identifiable, Sendable {
  let rule: ConditionalRule
  let status: RuleStatus
  var id: String { rule.id }
}
/// The add/edit form for a conditional rule.
struct RuleDraft: Equatable {
  var id = ""
  var name = ""
  var prefix = ""
  /// One route per line: `network` or `network via gateway`.
  var routes = ""
  var enabled = true
  var editing = false
  init() {}
  init(editing entry: ConditionalRuleEntry) {
    id = entry.rule.id
    name = entry.rule.name
    prefix = entry.rule.prefix
    routes = entry.rule.routes.map(\.text).joined(separator: "\n")
    enabled = entry.rule.enabled
    editing = true
  }
  var isComplete: Bool {
    !id.trimmingCharacters(in: .whitespaces).isEmpty
      && !name.trimmingCharacters(in: .whitespaces).isEmpty
      && !prefix.trimmingCharacters(in: .whitespaces).isEmpty
      && !routes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
  }
  var arguments: [String: String] {
    [
      "id": id.trimmingCharacters(in: .whitespaces),
      "name": name.trimmingCharacters(in: .whitespaces),
      "prefix": prefix.trimmingCharacters(in: .whitespaces),
      "routes": routes,
      "enabled": enabled ? "true" : "false",
    ]
  }
}
/// The add/edit form for an intent.
struct IntentDraft: Equatable {
  var id = ""
  var destinations = ""
  var useInterface = false
  var interface = ""
  var enabled = true
  /// Editing keeps the name: it is the identity.
  var editing = false
  init() {}
  init(editing intent: RouteIntent) {
    id = intent.id
    destinations = intent.destinations.joined(separator: "\n")
    useInterface = !intent.isDirect
    interface = intent.path.interface ?? ""
    enabled = intent.enabled
    editing = true
  }
  var isComplete: Bool {
    !id.trimmingCharacters(in: .whitespaces).isEmpty
      && !destinations.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      && (!useInterface || !interface.trimmingCharacters(in: .whitespaces).isEmpty)
  }
  var arguments: [String: String] {
    [
      "id": id.trimmingCharacters(in: .whitespaces),
      "destinations": destinations,
      "kind": useInterface ? "interface" : "direct",
      "interface": useInterface ? interface.trimmingCharacters(in: .whitespaces) : "",
      "enabled": enabled ? "true" : "false",
    ]
  }
}

struct Snapshot: Decodable, Sendable {
  let profiles: [Profile]
  let interfaces: [NetworkInterface]
  let routes: [Route]
  let routeMap: RouteMap
  let networkError: String?
}
struct Lookup: Decodable, Sendable {
  let destination: String
  let matchedRoute: Route
  let interfaceName: String
}
struct AnalyzedRoute: Decodable, Sendable {
  let destination: String
  let source: String
}
struct Listener: Decodable, Sendable {
  let address: String
  let port: UInt16
  let `protocol`: String
}
struct RemoteEndpoint: Decodable, Sendable {
  let address: String
  let port: UInt16?
  var label: String { port.map { "\(address):\($0)" } ?? address }
}
struct ConfigPeer: Decodable, Sendable {
  let endpoint: RemoteEndpoint?
  let routes: [AnalyzedRoute]
}
struct ConfigField: Decodable, Sendable {
  let field: String
  let value: String
}
struct Inspection: Decodable, Sendable {
  let endpoints: [RemoteEndpoint]
  let peers: [ConfigPeer]
  let interfaceDetails: [ConfigField]
  let osRoutes: [AnalyzedRoute]
  let internalRoutes: [AnalyzedRoute]
  let listeners: [Listener]
  let warnings: [String]
  let routeKnowledgeComplete: Bool
}

/// Presentation of the shared Engine start policy.
enum AppMode: String, Decodable, CaseIterable, Identifiable, Sendable {
  case combined, orchestrator, manager
  var id: Self { self }
  var titleKey: String {
    switch self {
    case .combined: "settings.modeCombined"
    case .orchestrator: "settings.modeOrchestrator"
    case .manager: "settings.modeManager"
    }
  }
}

enum Section: String, CaseIterable, Identifiable {
  case home = "Home"
  case connections = "Connections"
  case network = "Network"
  case routes = "Routes"
  case monitor = "Monitor"
  case logs = "Logs"
  case settings = "Settings"
  var id: Self { self }
  var iconName: String {
    switch self {
    case .home: "HomeIcon"
    case .connections: "ProfileIcon"
    case .network: "NetworkIcon"
    case .routes: "RouteIcon"
    case .monitor: "ActivityIcon"
    case .logs: "LogsIcon"
    case .settings: "SettingsIcon"
    }
  }
  var symbol: String {
    switch self {
    case .home: "square.grid.2x2"
    case .connections: "shield.lefthalf.filled"
    case .network: "network"
    case .routes: "arrow.triangle.branch"
    case .monitor: "chart.xyaxis.line"
    case .logs: "doc.text"
    case .settings: "gearshape"
    }
  }
}

struct ExitIpEntry: Decodable, Sendable {
  let name: String
  let ip: String?
  let country: String?
  let error: String?
}

/// A VPN configured by another app (e.g. incy), toggled with `scutil --nc`.
struct ExternalVpn: Decodable, Identifiable, Sendable {
  let id: String
  let name: String
  let state: String
  let provider: String?
  let enabled: Bool
}

/// A combination of connections kept in the shared per-data-directory store.
struct ConnectionSet: Codable, Identifiable, Sendable, Equatable {
  var id: String
  var name: String
  var profileIds: [String]
}

/// Counts of a profile's custom DNS policy, for the detail summary.
struct DnsSummary: Decodable, Sendable {
  let servers: [DnsServerStub]?
  let hosts: [String: [String]]?
  var serverCount: Int { servers?.count ?? 0 }
  var hostCount: Int { hosts?.count ?? 0 }
}
struct DnsServerStub: Decodable, Sendable {}
/// Editor state of a profile's Xray routing options, as plain text fields.
struct RoutingOptions: Decodable, Sendable {
  var block = ""
  var proxy = ""
  var direct = ""
  var privateLanDirect = false
  var domainStrategy = ""
  var domainMatcher = ""
  var dnsServers = ""
  var dnsHosts = ""
  var fakeDns = false
  var queryStrategy = ""
  /// Custom geo data (https), empty for the managed files.
  var geoipUrl = ""
  var geositeUrl = ""
}
/// Fields recovered from a pasted Happ/Incy routing export; absent fields
/// were not mentioned and keep their current value in the editor.
struct HappRouting: Decodable, Sendable {
  let name: String?
  let block: String
  let proxy: String
  let direct: String
  let privateLanDirect: Bool?
  let domainStrategy: String?
  let domainMatcher: String?
  let dnsServers: String?
  let dnsHosts: String?
  let fakeDns: Bool?
  let queryStrategy: String?
  let geoipUrl: String?
  let geositeUrl: String?
  let warnings: [String]
}
struct RouteCheckResult: Decodable, Sendable {
  let target: String
  let outbound: String
  let source: String
  let policyIndex: Int?
  let matchedSelector: String?
  let certainty: String
  let notes: [String]
}

extension RoutingOptions {
  var bridgeArgs: [String: String] {
    [
      "block": block, "proxy": proxy, "direct": direct,
      "privateLanDirect": privateLanDirect ? "true" : "false",
      "domainStrategy": domainStrategy, "domainMatcher": domainMatcher,
      "dnsServers": dnsServers, "dnsHosts": dnsHosts,
      "fakeDns": fakeDns ? "true" : "false", "queryStrategy": queryStrategy,
      "geoipUrl": geoipUrl, "geositeUrl": geositeUrl,
    ]
  }
  /// Applies the fields a Happ export mentions and keeps the rest.
  mutating func apply(_ happ: HappRouting) {
    block = happ.block
    proxy = happ.proxy
    direct = happ.direct
    if let value = happ.privateLanDirect { privateLanDirect = value }
    if let value = happ.domainStrategy { domainStrategy = value }
    if let value = happ.domainMatcher { domainMatcher = value }
    if let value = happ.dnsServers { dnsServers = value }
    if let value = happ.dnsHosts { dnsHosts = value }
    if let value = happ.fakeDns { fakeDns = value }
    if let value = happ.queryStrategy { queryStrategy = value }
    if let value = happ.geoipUrl { geoipUrl = value }
    if let value = happ.geositeUrl { geositeUrl = value }
  }
}
