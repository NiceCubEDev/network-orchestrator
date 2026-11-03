export type InterfaceKind =
  | "ethernet"
  | "wifi"
  | "wireGuard"
  | "openVpn"
  | "xray"
  | "loopback"
  | { other: string };

export type InterfaceState = "up" | "down" | "unknown";

export interface InterfaceAddress {
  address: string;
  prefixLen: number;
  family: "Ipv4" | "Ipv6";
}

export type InterfaceCategory =
  | "physical"
  | "vpn"
  | "virtual"
  | "system"
  | "tunnel"
  | "filter";

export interface NetworkInterface {
  name: string;
  friendlyName: string;
  kind: InterfaceKind;
  state: InterfaceState;
  addresses: InterfaceAddress[];
  dnsServers: string[];
  dnsSuffix: string | null;
  mtu: number | null;
  ifIndex: number;
  physical: boolean;
  mac: string | null;
  gateway: string | null;
  ipv6Gateway: string | null;
  rxBytes: number | null;
  txBytes: number | null;
  linkSpeedMbps: number | null;
  category: InterfaceCategory;
  description: string;
  ifType: number;
  tunnelType: string | null;
}

export interface RouteEntry {
  destination: string;
  prefixLen: number;
  gateway: string | null;
  interfaceIndex: number;
  interfaceName: string;
  metric: number;
}

export interface RouteLookupResult {
  destination: string;
  matchedRoute: RouteEntry;
  interfaceName: string;
  table?: string | null;
}

export function formatKind(kind: InterfaceKind): string {
  if (typeof kind === "string") {
    switch (kind) {
      case "ethernet": return "Ethernet";
      case "wifi": return "WiFi";
      case "wireGuard": return "WireGuard";
      case "openVpn": return "OpenVPN";
      case "xray": return "Xray";
      case "loopback": return "Loopback";
      default: return kind;
    }
  }
  return kind.other;
}

export const CATEGORY_ORDER: InterfaceCategory[] = [
  "physical",
  "vpn",
  "virtual",
  "system",
  "tunnel",
  "filter",
];

// IANA ifType values (https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib)
export const IF_TYPE_NAMES: Record<number, string> = {
  1: "Other",
  6: "Ethernet",
  7: "Bluetooth",
  9: "IEEE 802.11 (WiFi)",
  23: "PPP",
  24: "Software Loopback",
  53: "Prop Virtual (TAP/Wintun)",
  71: "IEEE 802.11 (WiFi)",
  106: "WWAN (Cellular)",
  131: "Tunnel",
  144: "IEEE 1394 (FireWire)",
};

export function ifTypeName(ifType: number): string {
  return IF_TYPE_NAMES[ifType] ?? `Type ${ifType}`;
}

export type TunnelBackend = "none" | "wireGuard" | "openVpn" | "xray";

export interface PolicyRoute {
  destination: string;
  metric: number;
  via?: string | null;
}

export interface DaemonStatus {
  state: "notRequired" | "notInstalled" | "notRunning" | "incompatible" | "ready" | "error";
  message: string;
}

export type AlwaysOnKind = "wireGuard" | "staticRoutes";

export interface AlwaysOnListResult {
  profiles: { kind: AlwaysOnKind; profileId: string; enabled: boolean }[];
  paused: boolean;
  supportedKinds: AlwaysOnKind[];
}

export interface AlwaysOnSetResult {
  stored: boolean;
  active: boolean;
}

export type DomainRouteTarget = "proxy" | "direct" | "block";

export interface DomainPolicy {
  domains: string[];
  target: DomainRouteTarget;
}

/** Linux multinode: selectors routed fail-closed through one specific
 * subscription node (`node-<endpointKey>`); a missing or down node blocks
 * them — they never fall back to direct or another node. */
export interface PinnedRoute {
  selectors: string[];
  endpointKey: string;
  /** The node left the subscription; kept so it works if it reappears. */
  missing?: boolean;
}

/** Linux `netorch proxy NAME`: where a spawned command's traffic exits —
 * the normal profile rules, one fixed node, an ordered pool or direct. */
export type ProxyTarget =
  | { kind: "rules" }
  | { kind: "node"; endpointKey: string }
  | { kind: "pool"; endpointKeys: string[] }
  | { kind: "direct" };

/** One named proxy exit; owned by the proxy commands — a profile form save
 * carries it back unchanged, never edits it. */
export interface NamedProxyExit {
  name: string;
  target: ProxyTarget;
  /** Explicit per-command proxy opt-outs; empty means proxy everything. */
  noProxy?: string[];
}

export interface ServiceCheck {
  id: string;
  name: string;
  url: string;
  endpointKey: string;
  background: boolean;
}

export type ServiceCheckOutcome = "http" | "timeout" | "tlsError" | "transportError" | "unavailable";

export interface ServiceCheckResult {
  id: string;
  name: string;
  endpointKey: string;
  outcome: ServiceCheckOutcome;
  httpStatus: number | null;
  latencyMs: number | null;
  checkedAtUnix: number;
  consecutiveFailures: number;
  degraded: boolean;
}

/** A remembered node reference in `backupKeys`: key plus last known name. */
export interface EndpointRef {
  key: string;
  name: string;
}

/** Opt-in pool: a node joins when ANY filter matches; a filter is name
 * substrings plus an optional verified exit country (`CC:word` in the CLI). */
export interface NodePoolFilter {
  nameContains: string[];
  exitCountry: string | null;
}

export interface NodePoolSettings {
  filters: NodePoolFilter[];
  /** Probe each candidate's real exit country through a temporary Xray. */
  verifyExitCountry: boolean;
}

/** One candidate's verdict from a pool rebuild (NodePoolReport entry). */
export interface PoolProbeEntry {
  key: string;
  name: string;
  verdict: "member" | "explicit" | "unreachable" | "wrongCountry" | "skipped";
  exitCountry: string | null;
}

export interface NodePoolReport {
  probedAtUnix: number;
  members: EndpointRef[];
  entries: PoolProbeEntry[];
  poolChanged: boolean;
  /** Nothing usable answered; the previous pool was kept. */
  keptPrevious: boolean;
}

/** Real exit verification of one failover candidate (backup verify). */
export interface SubscriptionExitCheck {
  key: string;
  name: string;
  role: string;
  /** Country the display name claims (flag emoji), if any. */
  namedCountry: string | null;
  exitCountry: string | null;
  exitIp: string | null;
  /** Named country ≠ verified exit. */
  mismatch: boolean;
  error: string | null;
}

/** Sanitized client view of a local Xray policy migration. */
export interface XrayPolicyPreview {
  direct: number;
  proxy: number;
  block: number;
  pinnedCount: number;
  privateLanDirect: boolean;
  quicReject: boolean;
  domainStrategy: XrayDomainStrategy | null;
  domainMatcher: XrayDomainMatcher | null;
  endpointBypassCount: number;
  hasGeoipOverride: boolean;
  hasGeositeOverride: boolean;
  hasDns: boolean;
  hasSockopts: boolean;
  trafficRuleCount: number;
  interfaceRouteCount: number;
  dnsServerCount: number;
  dnsHostCount: number;
  dnsRewriteRuleCount: number;
  tunDnsServerCount: number;
  tunMtu: number | null;
  connectionIdleSecs: number | null;
  directDomainStrategy: string | null;
  dnsEnableParallelQuery: boolean | null;
  hasDnsOutbound: boolean;
  backupCount: number | null;
  skipped: string[];
  /** Rules with no equivalent — apply is refused while non-empty. */
  refused: string[];
}

export type XrayDomainStrategy = "asIs" | "ipIfNonMatch" | "ipOnDemand";
export type XrayDomainMatcher = "mph" | "hybrid" | "linear";
export type XrayDnsQueryStrategy = "useIp" | "useIpv4" | "useIpv6";
export type XrayDnsRoute = "none" | "proxy" | "direct";

export interface XrayDnsServer {
  address: string;
  port: number | null;
  domains: string[];
  skipFallback: boolean;
  route: XrayDnsRoute;
}

export interface XrayDnsConfig {
  servers: XrayDnsServer[];
  hosts: Record<string, string[]>;
  fakeDns: boolean;
  queryStrategy: XrayDnsQueryStrategy | null;
  enableParallelQuery?: boolean | null;
  outboundKey?: string | null;
  outbound?: XrayDnsOutboundSettings | null;
}

export interface XraySockopts {
  tcpKeepAliveIdle?: number | null;
  tcpKeepAliveInterval?: number | null;
  tcpUserTimeout?: number | null;
  tcpNoDelay: boolean;
}

export interface XrayTrafficRule {
  ips: string[];
  port: number;
  network: string;
  target: DomainRouteTarget;
}

export interface XrayInterfaceRoute {
  selectors: string[];
  interfaceName: string;
  domainStrategy?: string | null;
}

export interface XrayDnsRewriteRule {
  action: string;
  qType?: string | null;
  rCode?: number | null;
  domain?: string[];
}

export interface XrayDnsOutboundSettings {
  rewriteAddress?: string | null;
  rewriteNetwork?: string | null;
  rewritePort?: number | null;
  rules?: XrayDnsRewriteRule[];
}

/** Result of `parse_happ_routing`: fields recovered from a Happ/Incy
 * routing-profile export. Absent fields mean "not mentioned in the
 * payload" — the form keeps its current values. */
export interface HappRoutingImport {
  name: string | null;
  domainPolicies: DomainPolicy[];
  privateLanDirect: boolean | null;
  domainStrategy: XrayDomainStrategy | null;
  domainMatcher: XrayDomainMatcher | null;
  dns: XrayDnsConfig;
  geoipUrl: string | null;
  geositeUrl: string | null;
  warnings: string[];
}

/** Result of `xray_test_route` — which generated rule decides a target. */
export type RouteCheckOutbound = "proxy" | "direct" | "block" | "dns";
export type RouteCheckSource =
  | "dnsCapture"
  | "policy"
  | "resolverPin"
  | "multicast"
  | "privateLan"
  | "default";
export type RouteCheckStepOutcome = "match" | "miss" | "unknown" | "skipped";

export interface RouteCheckStep {
  label: string;
  selector?: string;
  outcome: RouteCheckStepOutcome;
}

export interface RouteCheckResult {
  target: string;
  port?: number;
  targetKind: "domain" | "ip";
  outbound: RouteCheckOutbound;
  source: RouteCheckSource;
  policyIndex?: number;
  matchedSelector?: string;
  certainty: "certain" | "probable";
  steps: RouteCheckStep[];
  notes: string[];
}

export interface SubscriptionMeta {
  url: string;
  hwid: string;
  endpointCount: number;
  activeIndex: number;
  /** Stable key of the primary node; `activeIndex` is only a legacy hint. */
  activeKey?: string | null;
  /** Ordered, user-chosen backup nodes; keys may be absent from the current
   * subscription list (kept, shown as missing). */
  backupKeys?: EndpointRef[];
  /** Probe the primary over HTTPS and return when healthy; absent = true. */
  autoReturnPrimary?: boolean | null;
  refreshIntervalMinutes: number | null;
  lastRefreshAtUnix: number | null;
  lastRefreshError: string | null;
  userInfo: SubscriptionUserInfo | null;
  providerTitle: string | null;
  announce: string | null;
  supportUrl: string | null;
  webPageUrl: string | null;
  updateIntervalHours: number | null;
  skippedProtocols: string[];
  /** Opt-in filtered pool (`null` = off); members verified by rebuild. */
  nodePool?: NodePoolSettings | null;
  /** Verified pool members appended after `backupKeys` in failover order. */
  poolKeys?: EndpointRef[];
}

export interface SubscriptionUserInfo {
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number | null;
  expiresAtUnix: number | null;
}

export interface SubscriptionEndpointInfo {
  /** Stable 16-hex key of the node (never the share-link URL). */
  key: string;
  name: string;
  active: boolean;
  protocol: string | null;
  /** Member of the ordered backup chain. */
  isBackup: boolean;
  /** Kept from backups/pins but gone from the subscription list. */
  isMissing: boolean;
  /** Verified member of the opt-in filtered pool. */
  inPool?: boolean;
}

/** One suspected outbound connection storm the watchdog saw. */
export interface ConnStorm {
  destination: string;
  process: string | null;
  count: number;
}

/** Bounded recovery diagnostics from the daemon's connect watchdog
 * (TunnelStatus.watchdog; `null` when the core doesn't provide it). */
export interface WatchdogStatus {
  /** Physical uplink answers; `null` = not measured yet. */
  uplink: boolean | null;
  /** Fingerprint of the egress route (gw+dev+src), not a secret. */
  egressSignature: string | null;
  lastEgressChangeUnix: number | null;
  httpsStallStreak: number;
  httpsLatencyMs: number | null;
  dnsStallStreak: number;
  /** Explicit opt-in service diagnostics; absent means no readings. */
  serviceChecks?: ServiceCheckResult[];
  /** UDP sockets xray holds — a leak foreshadows port exhaustion. */
  xrayUdpSockets: number;
  connStorm: ConnStorm | null;
  lastRecoveryUnix: number | null;
  /** Human-readable anomalies the watchdog noticed (sanitized). */
  anomalies: string[];
}

/** Per-node failover health from the daemon (TunnelStatus.failover). */
export interface XrayNodeStatus {
  key: string;
  /** null = not probed yet. */
  healthy: boolean | null;
  lastProbeUnix: number | null;
  latencyMs: number | null;
}

export interface XrayFailoverStatus {
  primaryKey: string;
  activeKey: string;
  autoReturnPrimary: boolean;
  failoverActive: boolean;
  nodes: XrayNodeStatus[];
}

export interface SubscriptionRefreshResult {
  endpointCount: number;
  activeIndex: number;
  skippedCount: number;
  fallbackUsed: boolean;
  cleanupFailed: boolean;
  poolReport?: NodePoolReport | null;
}

export interface SubscriptionDelayResult {
  delayMs: number | null;
  error: string | null;
}

export interface WireGuardFields {
  privateKey: string;
  address: string;
  dns: string;
  peerPublicKey: string;
  peerEndpoint: string;
  allowedIps: string;
  presharedKey: string;
  persistentKeepalive: number | null;
}

export type XrayMode = "socks" | "tun";

export interface Profile {
  id: string;
  name: string;
  backend: TunnelBackend;
  configPath: string;
  interfaceName: string;
  routes: PolicyRoute[];
  autoConnect: boolean;
  domainPolicies: DomainPolicy[];
  privateLanDirect: boolean;
  xraySocksPort: number | null;
  xrayHttpPort: number | null;
  useSystemProxy: boolean;
  proxyBypass: string[];
  subscription: SubscriptionMeta | null;
  xrayMode: XrayMode;
  /** Linux: domain selectors fail-closed to a specific subscription node. */
  pinnedPolicies?: PinnedRoute[];
  xrayServiceChecks?: ServiceCheck[];
  /** macOS: a secondary connection carries only `tunnelNetworks`. */
  tunnelRole?: "primary" | "secondary";
  tunnelNetworks?: string[];
  tunnelDnsDomains?: string[];
  xrayTunInterface: string | null;
  xrayTunIp: string | null;
  /** Optional HTTPS URLs overriding the bundled geoip.dat / geosite.dat. */
  xrayGeoipUrl?: string | null;
  xrayGeositeUrl?: string | null;
  xrayDomainStrategy?: XrayDomainStrategy | null;
  xrayDomainMatcher?: XrayDomainMatcher | null;
  xrayDns?: XrayDnsConfig;
  /** Linux TUN: def1 halves instead of a single default route. */
  xraySplitDefault?: boolean;
  /** Linux TUN: kernel rejects outbound UDP/443 on the tunnel interface so
   * QUIC fails fast and browsers fall back to TCP (instead of the silent
   * blackhole a plain routing rule gives). */
  xrayQuicReject?: boolean;
  xraySockopts?: XraySockopts | null;
  xrayTrafficRules?: XrayTrafficRule[];
  xrayInterfaceRoutes?: XrayInterfaceRoute[];
  xrayConnectionIdleSecs?: number | null;
  xrayTunMtu?: number | null;
  xrayTunDnsServers?: string[];
  xrayDirectDomainStrategy?: string | null;
  /** Linux `netorch proxy` named exits; opaque to the profile form. */
  xrayProxyExits?: NamedProxyExit[];
  /** Hosts pinned to the physical uplink, bypassing foreign capture tunnels. */
  endpointBypasses?: string[];
  /** Keep declared routes armed while the target interface is absent. */
  waitForInterface?: boolean;
}

export type TunnelState = "stopped" | "running" | "failed";

export interface SystemProxyStatus {
  ownerProfileId: string | null;
  ownerName: string | null;
}

export interface TunnelStatus {
  profileId: string;
  state: TunnelState;
  message: string | null;
  /** Live kernel interface name reported by the daemon when running. */
  interfaceName?: string | null;
  /** Linux multinode: which node carries traffic and per-node health. */
  failover?: XrayFailoverStatus | null;
  /** Linux: bounded recovery diagnostics from the connect watchdog. */
  watchdog?: WatchdogStatus | null;
}

export interface AutoConnectResult {
  failedCount: number;
  startupFailed: boolean;
}

export type LogLevel = "info" | "warn" | "error";
export type LogSource = "app" | "daemon";

export interface LogEvent {
  tsUnix: number;
  level: LogLevel;
  source: LogSource;
  message: string;
}

export interface AnalyzedRoute {
  destination: string;
  source: string;
}

export type OpenVpnPlanConflict =
  | "activeConnection"
  | "activeProbe"
  | "interfaceOccupied"
  | "stagingLeftover";

export interface OpenVpnPlan {
  profileId: string;
  owner: string;
  interfaceName: string;
  fallbackInterfaceName: string;
  stagingDir: string;
  configPath: string;
  managementSocket: string;
  conflicts: OpenVpnPlanConflict[];
}

export interface LocalListener {
  address: string;
  port: number;
  protocol: string;
}

export interface RemoteEndpoint {
  address: string;
  port: number | null;
  protocol: string;
}

export type ConflictKind = "routeOverlap" | "listenerCollision";

export interface ProfileConflict {
  kind: ConflictKind;
  message: string;
  otherProfileId: string | null;
  blocking: boolean;
}

export interface ConfigPeer {
  endpoint: RemoteEndpoint | null;
  routes: AnalyzedRoute[];
}

export interface ConfigField {
  field: string;
  value: string;
}

export interface ConfigAnalysis {
  profileId: string;
  osRoutes: AnalyzedRoute[];
  internalRoutes: AnalyzedRoute[];
  listeners: LocalListener[];
  endpoints: RemoteEndpoint[];
  domainPatterns: string[];
  warnings: string[];
  routeKnowledgeComplete: boolean;
  peers: ConfigPeer[];
  interfaceDetails: ConfigField[];
}

export interface ProfileInspection {
  analysis: ConfigAnalysis;
  conflicts: ProfileConflict[];
  managedConfig: boolean;
}

export type DiagnosticLevel = "healthy" | "warning" | "error";

export interface DiagnosticCheck {
  name: string;
  level: DiagnosticLevel;
  message: string;
}

export interface ProfileDiagnostics {
  profileId: string;
  status: TunnelStatus;
  inspection: ProfileInspection | null;
  checks: DiagnosticCheck[];
}

export type RecoveryIssueKind =
  | "survivingWireGuardService"
  | "ownedRoutes"
  | "missingOwnedRoutes"
  | "orphanRouteOwnership"
  | "statusCheckFailed"
  | "proxyOwnership"
  | "leftoverTunnel";

export interface RecoveryIssue {
  kind: RecoveryIssueKind;
  profileId: string | null;
  message: string;
}

export interface RecoveryReport {
  issues: RecoveryIssue[];
  requiresElevation: boolean;
}

export interface PlannedRoute {
  destination: string;
  ownerProfileId: string;
  ownerName: string;
  source: string;
  interfaceName: string | null;
  metric: number | null;
  active: boolean;
}

export type RoutePlanDiffKind =
  | "missing"
  | "interfaceMismatch"
  | "exactCompetition";

export interface RoutePlanDiff {
  kind: RoutePlanDiffKind;
  destination: string;
  message: string;
  profileIds: string[];
}

export interface RouteMap {
  predicted: PlannedRoute[];
  effective: RouteEntry[];
  diffs: RoutePlanDiff[];
  warnings: string[];
  pushedRoutes: PlannedRoute[];
}

export type BackendExecutableSource = "autoDetected" | "configured" | "managed";

export interface BackendAvailability {
  backend: TunnelBackend;
  available: boolean;
  path: string | null;
  source: BackendExecutableSource | null;
  version: string | null;
  message: string;
}

export interface BackendInstallProgress {
  backend: TunnelBackend;
  stage:
    | "downloading"
    | "verifying"
    | "installing"
    | "validating"
    | "ready"
    | "cancelled";
  downloaded: number;
  total: number | null;
}

/** Daemon-enforced rule for when connecting a VPN asks for an admin password. */
export type VpnAuthMode = "noPrompt" | "fullTunnelOnly" | "always";

export interface PlatformCapabilities {
  os: string;
  systemProxy: boolean;
  wireguardStandardImport: boolean;
  managedXrayInstall: boolean;
  elevationRelaunch: boolean;
  appUpdates: boolean;
  executableExtensions: string[];
}

export interface ManagedXrayOffer {
  version: string;
  sourceUrl: string;
  sha256: string;
  maxDownloadBytes: number;
}

export interface BatchImportError {
  path: string;
  error: string;
}

export interface BatchImportResult {
  profiles: Profile[];
  errors: BatchImportError[];
}

export interface ExitIpEntry {
  name: string;
  ip: string | null;
  country: string | null;
  error: string | null;
}

export interface TailscalePeer {
  hostName: string;
  dnsName?: string | null;
  tailscaleIps: string[];
  /** Subnet routes this peer advertises (its own /32,/128 addresses excluded). */
  routes: string[];
  exitNode: boolean;
  exitNodeOption: boolean;
  online: boolean;
  os: string;
}

export interface TailscaleStatusResult {
  /** False when tailscaled is absent or unreachable — a state, not an error. */
  available: boolean;
  /** ipnstate BackendState verbatim: "Running", "Stopped", "NeedsLogin"… */
  backendState: string;
  tailnet?: string | null;
  magicDnsSuffix?: string | null;
  selfHostName?: string | null;
  selfDnsName?: string | null;
  selfIps: string[];
  exitNodeActive: boolean;
  peers: TailscalePeer[];
}

// ── NetworkManager connections (Linux daemon) ─────────────────────────

export type NmConnectionKind = "wireGuard" | "openVpn" | "vpn" | "other";

export type NmConnectionState = "inactive" | "activating" | "active";

/** A NetworkManager VPN/WireGuard profile. The uuid is the activation
 * handle only — never shown in the UI. */
export interface NmConnection {
  uuid: string;
  id: string;
  kind: NmConnectionKind;
  /** Bound device interface while the connection is active. */
  interfaceName: string | null;
  state: NmConnectionState;
}

export interface NmListResult {
  connections: NmConnection[];
  /** False when NetworkManager is absent or D-Bus is unreachable. */
  available: boolean;
}

// ── Kernel routing tables (Linux daemon, `ip route`/`ip rule`) ────────

/** One nexthop of a multipath route. */
export interface SystemNexthop {
  gateway: string | null;
  interfaceIndex: number;
  interfaceName: string | null;
  weight: number;
}

/** A kernel route from any routing table. */
export interface SystemRoute {
  family: "ipv4" | "ipv6";
  /** CIDR; `0.0.0.0/0`/`::/0` render as `default`. */
  destination: string;
  /** Kernel table id (254 main, 253 default, 255 local). */
  table: number;
  /** `unicast` | `local` | `blackhole` | … as `ip route` prints it. */
  routeType: string;
  /** `universe` | `site` | `link` | `host` | `nowhere` | `scope N`. */
  scope: string;
  /** rt_proto byte. */
  protocol: number;
  /** Installed by this daemon (RTPROT marker). */
  managed: boolean;
  gateway: string | null;
  interfaceIndex: number | null;
  interfaceName: string | null;
  metric: number | null;
  prefSource: string | null;
  nexthops: SystemNexthop[];
}

/** A policy-routing rule (`ip rule` equivalent) with every selector. */
export interface SystemRule {
  family: "ipv4" | "ipv6";
  priority: number;
  /** `lookup` | `goto` | `unreachable` | `blackhole` | `prohibit` | `nop`. */
  action: string;
  table: number;
  goto: number | null;
  from: string | null;
  to: string | null;
  fwmark: number | null;
  fwmask: number | null;
  iifname: string | null;
  oifname: string | null;
  uidRange: [number, number] | null;
  sourcePortRange: [number, number] | null;
  destinationPortRange: [number, number] | null;
  ipProtocol: string | null;
  suppressPrefixLength: number | null;
  suppressIfGroup: number | null;
  tunId: number | null;
  tos: number;
  /** `ip rule ... not`. */
  invert: boolean;
  protocol: number;
  managed: boolean;
}

export interface NetTablesResult {
  routes: SystemRoute[];
  rules: SystemRule[];
  /** False when the daemon cannot dump kernel state. */
  available: boolean;
}

// ── Localhost proxy discovery (opt-in scan) ───────────────────────────

export type LocalProxyKind = "socks5" | "socks4" | "http";

/** A loopback listener that passed a real SOCKS/HTTP proxy handshake probe. */
export interface LocalProxy {
  address: string;
  port: number;
  kind: LocalProxyKind;
}

// ── Conditional rules (Linux daemon) ──────────────────────────────────

/** When a conditional rule's routes may be installed. */
export type RouteCondition = {
  kind: "interfaceAddressIn";
  /** Active while a physical uplink holds a global address inside this. */
  prefix: string;
};

export interface ConditionalRouteRule {
  id: string;
  name: string;
  enabled: boolean;
  condition: RouteCondition;
  routes: PolicyRoute[];
}

export type ConditionalRuleState = "disabled" | "inactive" | "active" | "error";

export interface ConditionalRuleStatus {
  state: ConditionalRuleState;
  /** Interface that satisfied the condition during the last evaluation. */
  matchedInterface?: string | null;
  appliedRoutes: number;
  detail?: string | null;
}

export interface ConditionalRuleEntry {
  rule: ConditionalRouteRule;
  status: ConditionalRuleStatus;
}

export interface CondRulesListResult {
  rules: ConditionalRuleEntry[];
}

export interface CondRulesPutResult {
  stored: boolean;
  status: ConditionalRuleStatus;
}

export interface CondRulesRemoveResult {
  removed: boolean;
}

// ── Manual route/rule editing + reconcile explainability (Linux daemon) ──

/** Payload of `net_route_add` — a daemon-owned unicast route. */
export interface NetRouteAddParams {
  /** CIDR destination. */
  destination: string;
  /** Kernel table id; absent = main (254). */
  table?: number;
  gateway?: string;
  /** Exactly one of interfaceName/interfaceIndex is required. */
  interfaceName?: string;
  interfaceIndex?: number;
  metric?: number;
  /** Preferred source (`src`). */
  prefSource?: string;
}

/** Payload of `net_rule_add` — a `lookup` policy rule. */
export interface NetRuleAddParams {
  family: "ipv4" | "ipv6";
  /** Explicit priority; 0 is reserved by the kernel local rule. */
  priority: number;
  /** Lookup target table. */
  table: number;
  from?: string;
  to?: string;
  fwmark?: number;
  fwmask?: number;
  iifname?: string;
  oifname?: string;
  invert?: boolean;
}

/** What a `net.*.del` call did with the kernel object. */
export type NetEditOutcome = "deleted" | "suppressed";

export interface NetEditResult {
  outcome: NetEditOutcome;
}

/** Reconciliation status of one journaled intent piece. */
export type ExplainStatus =
  | "effective"
  | "deferred"
  | "conflicted"
  | "missing"
  | "active"
  | "disabled";

export interface ExplainEntry {
  /** Journal owner: `wg:…`, `manual`, `cond:…`, a client owner. */
  owner: string;
  state: "applying" | "applied" | "stale";
  /** `route` | `rule` | `attach` | `suppressed-route` | `suppressed-rule` | `link` | `dns` | `process`. */
  kind: string;
  subject: string;
  status: ExplainStatus;
  /** Why it is in this status (English, daemon-composed). */
  detail: string;
}

export interface NetExplainResult {
  entries: ExplainEntry[];
  /** False when the kernel dump was unavailable. */
  available: boolean;
}

// ── Routing intents (Linux daemon) ────────────────────────────────────

/** Where an intent sends its destinations: a named link or the uplink. */
export interface NetIntentPath {
  /** `interface` | `direct` */
  kind: string;
  interface?: string;
}

export interface NetIntentSetParams {
  id: string;
  destinations: string[];
  path: NetIntentPath;
  metric?: number;
  /** false stores the intent without enforcing it; absent means on. */
  enabled?: boolean;
}

/** One stored intent with its live reconciliation status. */
export interface NetIntentView {
  id: string;
  destinations: string[];
  path: NetIntentPath;
  metric: number;
  /** False when the intent is stored but not enforced. */
  enabled: boolean;
  status: ExplainStatus;
  detail: string;
  /** Desired routes currently present in the kernel. */
  installed: number;
  /** Routes the spec wants right now (0 while deferred). */
  wanted: number;
}

export interface NetIntentListResult {
  intents: NetIntentView[];
}

// ── DNS inventory + probe (Linux daemon) ─────────────────────────────

export interface DnsDomain {
  domain: string;
  routeOnly: boolean;
}

/** Per-link resolver state as systemd-resolved reports it. */
export interface DnsLinkStatus {
  interfaceIndex: number;
  interfaceName: string;
  servers: string[];
  currentServer: string | null;
  domains: DnsDomain[];
  defaultRoute: boolean;
}

export interface NetDnsStatusResult {
  links: DnsLinkStatus[];
  /** False when systemd-resolved is unreachable. */
  available: boolean;
  /** `nameserver` lines of /etc/resolv.conf — the stub view apps use. */
  resolvConf: string[];
}

/** Result of `net_dns_probe`: one real query plus its egress path. */
export interface NetDnsProbeResult {
  /** Resolver that was queried. */
  server: string;
  /** Source address the kernel picked for the packet. */
  source: string | null;
  interfaceIndex: number | null;
  interfaceName: string | null;
  gateway: string | null;
  /** dig-style `name TTL TYPE data` answer lines. */
  answers: string[];
  /** `NOERROR` | `NXDOMAIN` | `SERVFAIL` | … */
  status: string;
  rttMs: number;
}

/** The user's own NetBird daemon as the backend summarises it (no keys, no events). */
export interface NetBirdState {
  installed: boolean;
  /** connected, connecting, disconnected, needsLogin, daemonStopped, notInstalled or unavailable. */
  state: string;
  ip?: string | null;
  fqdn?: string | null;
  version?: string | null;
  managementUrl?: string | null;
  peersConnected?: number;
  peersTotal?: number;
  sessionExpiresAt?: string | null;
  networks?: string[];
}
