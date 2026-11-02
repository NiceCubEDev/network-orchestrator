import type {
  AlwaysOnListResult, BackendAvailability, ConditionalRuleEntry, ConditionalRouteRule,
  ConfigAnalysis, DomainPolicy, NetIntentView, NetworkInterface, NodePoolSettings, PinnedRoute,
  PoolProbeEntry, Profile, ProfileInspection, RouteEntry, RouteMap, TunnelStatus, VpnAuthMode,
  XrayPolicyPreview,
  ServiceCheck, ServiceCheckOutcome, ServiceCheckResult,
} from "../types.ts";

// This module intentionally has no I/O imports, fetch, or process calls.
// It models UI transitions only; Rust tests verify actual backend behavior.
function profile(id: string, name: string, backend: Profile["backend"], cidr?: string, endpointBypasses?: string[]): Profile {
  return {
    id, name, backend, configPath: backend === "none" ? "" : `/sandbox/${id}.${backend === "xray" ? "json" : backend === "openVpn" ? "ovpn" : "conf"}`,
    interfaceName: backend === "none" ? "qa-ethernet" : `qa-${id}`,
    routes: cidr ? [{ destination: cidr, metric: 5, via: null }] : [],
    autoConnect: false, domainPolicies: [], privateLanDirect: false,
    xraySocksPort: backend === "xray" ? 10808 : null,
    xrayHttpPort: backend === "xray" ? 10809 : null,
    useSystemProxy: false, proxyBypass: [], subscription: null,
    xrayMode: "socks", xrayTunInterface: null, xrayTunIp: null,
    pinnedPolicies: [],
    xrayServiceChecks: [],
    endpointBypasses,
    // Linux TUN flag; the fixture profiles are SOCKS so it stays off.
    xrayQuicReject: false,
  };
}

function iface(name: string, index: number, physical: boolean, state: NetworkInterface["state"], kind: NetworkInterface["kind"] = "ethernet"): NetworkInterface {
  return {
    name, friendlyName: name, ifIndex: index, physical, state,
    kind, category: physical ? "physical" : "vpn",
    addresses: [{ address: physical ? "192.0.2.2" : kind === "openVpn" ? "10.88.0.2" : "10.77.0.2", prefixLen: 24, family: "Ipv4" }],
    dnsServers: ["192.0.2.53"], dnsSuffix: null, mtu: 1500, mac: null,
    gateway: physical ? "192.0.2.1" : null, ipv6Gateway: null,
    rxBytes: 1048576, txBytes: 524288, linkSpeedMbps: 1000,
    description: "Synthetic interface; no OS adapter", ifType: 6, tunnelType: null,
  };
}

export class SandboxBackend {
  private serviceResults = new Map<string, ServiceCheckResult[]>();
  private serviceDue = new Map<string, number>();
  private serviceAttempts = new Map<string, Map<string, number>>();

  private serviceBindings(p: Profile): Set<string> {
    return new Set([
      ...(p.pinnedPolicies ?? []).map((route) => route.endpointKey),
      p.xrayDns?.outboundKey,
    ].filter((key): key is string => Boolean(key)));
  }

  private validateServiceSpecs(p: Profile, value: unknown): ServiceCheck[] {
    const invalid = () => new Error("Invalid service-check settings");
    if (!Array.isArray(value) || value.length > 16) throw invalid();
    if (value.length && (p.backend !== "xray" || !p.subscription)) {
      throw invalid();
    }

    const ids = new Set<string>();
    return value.map((raw: unknown) => {
      if (!raw || typeof raw !== "object") throw invalid();
      const item = raw as Record<string, unknown>;
      const { id, name, url, endpointKey } = item;
      const background = item.background ?? false;

      if (
        typeof id !== "string" ||
        !/^[A-Za-z0-9_-]{1,64}$/.test(id) ||
        ids.has(id) ||
        typeof name !== "string" ||
        !name.trim() ||
        [...name].length > 80 ||
        /[\p{Cc}]/u.test(name) ||
        typeof url !== "string" ||
        new TextEncoder().encode(url).length > 2048 ||
        typeof endpointKey !== "string" ||
        !/^[0-9a-f]{16}$/.test(endpointKey) ||
        typeof background !== "boolean"
      ) throw invalid();

      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw invalid();
      }
      if (
        /[\s\\]/u.test(url) ||
        !url.split("://")[1]?.split(/[/?#]/u)[0] ||
        url.split("://")[1]?.split(/[/?#]/u)[0]?.includes("@") ||
        parsed.port === "0" ||
        parsed.protocol !== "https:" ||
        !parsed.hostname ||
        parsed.username ||
        parsed.password ||
        url.includes("#")
      ) throw invalid();

      ids.add(id);
      return { id, name, url, endpointKey, background };
    });
  }

  private serviceSnapshot(p: Profile): string {
    return JSON.stringify([
      p.backend,
      p.configPath,
      p.xrayServiceChecks ?? [],
      p.pinnedPolicies ?? [],
      p.xrayDns?.outboundKey ?? null,
      p.xraySockopts ?? null,
      p.subscription?.activeKey ?? null,
    ]);
  }

  private resetServiceWorker(p: Profile, now = Date.now()): void {
    this.serviceDue.delete(p.id);
    this.serviceResults.delete(p.id);
    this.serviceAttempts.delete(p.id);
    if (
      this.running.has(p.id) &&
      p.backend === "xray" &&
      p.subscription &&
      p.xrayMode === "tun" &&
      (p.xrayServiceChecks ?? []).some((check) => check.background)
    ) {
      // Never sample on save/connect. First eligibility is one interval later.
      this.serviceDue.set(p.id, now + 60_000);
    }
  }

  private clearServiceState(profileId: string): void {
    this.serviceDue.delete(profileId);
    this.serviceResults.delete(profileId);
    this.serviceAttempts.delete(profileId);
  }

  private sampleService(
    p: Profile,
    check: ServiceCheck,
    channel: "manual" | "background",
    now: number,
    previous?: ServiceCheckResult,
  ): ServiceCheckResult {
    let outcome: ServiceCheckOutcome = "unavailable";
    let httpStatus: number | null = null;
    let latencyMs: number | null = null;

    const available =
      p.backend === "xray" &&
      Boolean(p.subscription) &&
      this.serviceBindings(p).has(check.endpointKey) &&
      this.endpointKeys.includes(check.endpointKey);

    if (available) {
      let attempts = this.serviceAttempts.get(p.id);
      if (!attempts) {
        attempts = new Map();
        this.serviceAttempts.set(p.id, attempts);
      }
      const identity = `${channel}:${check.id}`;
      const attempt = attempts.get(identity) ?? 0;
      attempts.set(identity, attempt + 1);

      // Stateful, URL-independent observations. 403/503 remain HTTP proof;
      // three successive non-HTTP failures demonstrate degradation.
      const outcomes: readonly ServiceCheckOutcome[] = [
        "http", "http", "http",
        "timeout", "tlsError", "transportError", "http",
      ];
      const statuses: readonly (number | null)[] = [
        204, 403, 503, null, null, null, 302,
      ];
      const index = attempt % outcomes.length;
      outcome = outcomes[index];
      httpStatus = statuses[index];
      latencyMs = outcome === "http" ? 42 + index * 7 : null;
    }

    const consecutiveFailures =
      outcome === "http" || outcome === "unavailable"
        ? 0
        : (previous?.consecutiveFailures ?? 0) + 1;

    return {
      id: check.id,
      name: check.name,
      endpointKey: check.endpointKey,
      outcome,
      httpStatus,
      latencyMs,
      checkedAtUnix: Math.floor(now / 1000),
      consecutiveFailures,
      degraded: consecutiveFailures >= 3,
    };
  }

  private tickServiceChecks(p: Profile, now: number): void {
    const due = this.serviceDue.get(p.id);
    if (due === undefined || now < due) return;

    if (
      !this.running.has(p.id) ||
      p.backend !== "xray" ||
      !p.subscription ||
      p.xrayMode !== "tun"
    ) {
      this.serviceDue.delete(p.id);
      this.serviceResults.delete(p.id);
      return;
    }

    const previous = this.serviceResults.get(p.id) ?? [];
    const results = (p.xrayServiceChecks ?? [])
      .filter((check) => check.background)
      .map((check) => this.sampleService(
        p,
        check,
        "background",
        now,
        previous.find((result) =>
          result.id === check.id &&
          result.endpointKey === check.endpointKey),
      ));
    this.serviceResults.set(p.id, results);

    // Skip missed intervals; never manufacture catch-up rounds.
    this.serviceDue.set(p.id, now + 60_000);
  }

  private async runServiceChecks(
    p: Profile,
    value: unknown,
  ): Promise<ServiceCheckResult[]> {
    const checks = structuredClone(p.xrayServiceChecks ?? []);
    if (
      value !== undefined &&
      value !== null &&
      (!Array.isArray(value) || value.some((id) => typeof id !== "string"))
    ) throw new Error("Invalid service-check selection");

    const selected = value === undefined || value === null
      ? null
      : new Set(value as string[]);
    if (selected && [...selected].some(
      (id) => !checks.some((check) => check.id === id),
    )) throw new Error("Unknown service check");

    const targets = checks.filter((check) =>
      selected === null || selected.has(check.id));
    if (targets.length === 0) return [];

    const snapshot = this.serviceSnapshot(p);
    const profileId = p.id;
    await Promise.resolve();

    const current = this.profiles.find((item) => item.id === profileId);
    if (!current || this.serviceSnapshot(current) !== snapshot) {
      throw new Error("Service-check configuration changed; run again");
    }

    // Manual runs are fresh observations, not background streak updates.
    const now = Date.now();
    return targets.map((check) =>
      this.sampleService(current, check, "manual", now));
  }
  private intents: NetIntentView[] = [
    {
      id: "office-via-openvpn",
      destinations: ["10.88.0.0/24", "10.20.0.0/16"],
      path: { kind: "interface", interface: "qa-ovpn" },
      metric: 100,
      enabled: true,
      status: "deferred",
      detail: "interface qa-ovpn is absent; armed until it appears",
      installed: 0,
      wanted: 2,
    },
    {
      id: "everything-via-mihomo",
      destinations: ["0.0.0.0/1", "128.0.0.0/1"],
      path: { kind: "interface", interface: "Mihomo" },
      metric: 100,
      enabled: true,
      status: "effective",
      detail: "2 route(s) enforced",
      installed: 2,
      wanted: 2,
    },
    {
      id: "vpn-endpoint-direct",
      destinations: ["91.245.41.31/32"],
      path: { kind: "direct" },
      metric: 50,
      enabled: true,
      status: "effective",
      detail: "pinned to the physical uplink",
      installed: 1,
      wanted: 1,
    },
    {
      id: "stale-conflict",
      destinations: ["203.0.113.0/24"],
      path: { kind: "interface", interface: "qa-wg" },
      metric: 100,
      enabled: true,
      status: "conflicted",
      detail: "a foreign route occupies the destination",
      installed: 0,
      wanted: 1,
    },
    {
      id: "paused-media",
      destinations: ["192.0.2.0/24"],
      path: { kind: "interface", interface: "qa-wg" },
      metric: 100,
      enabled: false,
      status: "disabled",
      detail: "disabled — routes are withdrawn",
      installed: 0,
      wanted: 1,
    },
  ];
  private profiles: Profile[] = [
    profile("wg", "QA WireGuard", "wireGuard", "10.77.0.0/24"),
    profile("ovpn", "QA OpenVPN", "openVpn", "10.88.0.0/24", ["203.0.113.7"]),
    profile("xray", "AcmeVPN · ⚡ Нидерланды", "xray"),
    profile("static", "QA Static routes", "none", "203.0.113.0/24"),
  ];
  private running = new Set<string>();
  // Foreign tunnels raised outside the app (wg-quick, another VPN app).
  private externalIfaces = [
    iface("wg-home", 90, false, "up", "wireGuard"),
    iface("tun-happ", 91, false, "up", "xray"),
  ];
  private enrollment: AlwaysOnListResult = { profiles: [], paused: false, supportedKinds: ["wireGuard", "staticRoutes"] };
  private loginAutostart = false;
  private authMode: VpnAuthMode = "fullTunnelOnly";
  private recovered = false;
  private endpoints = [
    "AcmeVPN · ⚡ Нидерланды", "AcmeVPN · 🇩🇪 Германия", "AcmeVPN · 🇫🇮 Финляндия",
    "AcmeVPN · 🇯🇵 Япония", "AcmeVPN · 🇺🇸 США", "AcmeVPN · 🇧🇷 Бразилия",
    "AcmeVPN · 🇸🇬 Сингапур", "AcmeVPN · 🇬🇧 Великобритания",
  ];
  private endpointKeys = this.endpoints.map((_, i) => `00000000000000${(i + 1).toString(16).padStart(2, "0")}`);
  // Independent synthetic measurements, not countries inferred from names.
  private readonly exitCountries = ["NL", "NL", "FI", "JP", "US", "BR", "SG", "GB"];
  private backendPaths = new Map<string, string>();
  private xrayManaged = false;
  private condRules: ConditionalRuleEntry[] = [
    {
      rule: {
        id: "cond-lan",
        name: "QA LAN bypass",
        enabled: true,
        condition: { kind: "interfaceAddressIn", prefix: "192.168.0.0/16" },
        routes: [{ destination: "10.228.32.0/21", metric: 5, via: null }],
      },
      status: { state: "active", matchedInterface: "qa-ethernet", appliedRoutes: 1, detail: null },
    },
  ];

  constructor() {
    // QA WireGuard wants the same interface the external wg-home tunnel holds:
    // demonstrates the "interface occupied" conflict until it is connected.
    this.profiles[0].interfaceName = "wg-home";
    const sub = this.profiles[2];
    sub.subscription = {
      url: "", hwid: "", endpointCount: this.endpoints.length, activeIndex: 0,
      activeKey: this.endpointKeys[0],
      backupKeys: [
        { key: this.endpointKeys[1], name: this.endpoints[1] },
        { key: "deadbeefdeadbeef", name: "AcmeVPN · 🇵🇱 Польша" },
      ],
      autoReturnPrimary: true,
      nodePool: {
        filters: [
          { nameContains: ["Герман"], exitCountry: "DE" },
          { nameContains: ["Великобритан"], exitCountry: "GB" },
        ],
        verifyExitCountry: true,
      },
      poolKeys: [{ key: this.endpointKeys[7], name: this.endpoints[7] }],
      refreshIntervalMinutes: null, lastRefreshAtUnix: null, lastRefreshError: null,
      providerTitle: "AcmeVPN",
      announce: "Maintenance window on Saturday 03:00–05:00 UTC.\nNL endpoints may flap briefly.",
      supportUrl: "https://support.example.invalid/chat",
      webPageUrl: "https://cabinet.example.invalid/dashboard",
      updateIntervalHours: 12,
      skippedProtocols: ["trojan", "ss"],
      userInfo: { uploadBytes: 1048576, downloadBytes: 2097152, totalBytes: 1073741824, expiresAtUnix: Math.floor(Date.now() / 1000) + 5 * 86400 },
    };
    // One pinned route, plus one whose node left the list (fail-closed demo).
    sub.pinnedPolicies = [
      { selectors: ["domain:bank.example", "geosite:category-gov"], endpointKey: this.endpointKeys[4] },
      { selectors: ["domain:only-pl.example"], endpointKey: "deadbeefdeadbeef", missing: true },
    ];
    // Linux subscription profiles run as daemon TUN tunnels — needed for the
    // QUIC-reject toggle to be visible in the sandbox.
    sub.xrayMode = "tun";
  }

  private poolMembers(profile: Profile) {
    const sub = profile.subscription;
    if (!sub?.nodePool) return [];
    const explicit = new Set([
      sub.activeKey ?? this.endpointKeys[sub.activeIndex],
      ...(sub.backupKeys ?? []).map((node) => node.key),
      ...(profile.pinnedPolicies ?? []).map((route) => route.endpointKey),
      profile.xrayDns?.outboundKey,
    ]);
    return (sub.poolKeys ?? []).filter((node) => !explicit.has(node.key));
  }

  private flagCountry(name: string): string | null {
    const indicators = Array.from(name).map((character) => character.codePointAt(0)!)
      .filter((code) => code >= 0x1f1e6 && code <= 0x1f1ff);
    return indicators.length === 2
      ? String.fromCharCode(...indicators.map((code) => code - 0x1f1e6 + 65))
      : null;
  }

  private rebuildPool(p: Profile) {
    const subscription = p.subscription;
    const pool = subscription?.nodePool;
    if (!subscription || !pool) throw new Error("Set backup-pool filters before rebuilding the pool");
    const primary = subscription.activeKey ?? this.endpointKeys[subscription.activeIndex];
    const explicit = new Set([primary, ...(subscription.backupKeys ?? []).map((node) => node.key),
      ...(p.pinnedPolicies ?? []).map((route) => route.endpointKey), p.xrayDns?.outboundKey]);
    const capacity = Math.max(0, 8 - 1 - (subscription.backupKeys?.length ?? 0));
    let selected = 0;
    let candidates = 0;
    const entries = this.endpoints.flatMap<PoolProbeEntry>((name, index) => {
      const filters = pool.filters.filter((filter) => filter.nameContains.length === 0 ||
        filter.nameContains.some((term) => name.toLowerCase().includes(term.toLowerCase())));
      if (filters.length === 0) return [];
      const key = this.endpointKeys[index];
      if (explicit.has(key)) return [{ key, name, verdict: "explicit", exitCountry: null }];
      if (candidates++ >= 32) return [{ key, name, verdict: "skipped", exitCountry: null }];
      const exitCountry = pool.verifyExitCountry ? this.exitCountries[index] : null;
      const accepted = !pool.verifyExitCountry ||
        filters.some((filter) => filter.exitCountry?.toUpperCase() === exitCountry);
      const verdict: PoolProbeEntry["verdict"] = !accepted ? "wrongCountry"
        : selected >= capacity ? "skipped" : "member";
      if (verdict === "member") selected++;
      return [{ key, name, verdict, exitCountry }];
    });
    let members = entries.filter((entry) => entry.verdict === "member")
      .map((entry) => ({ key: entry.key, name: entry.name }));
    const previous = subscription.poolKeys ?? [];
    let keptPrevious = false;
    if (members.length === 0) {
      const seen = new Set<string>();
      members = previous.filter((node) => {
        const index = this.endpointKeys.indexOf(node.key);
        if (explicit.has(node.key) || seen.has(node.key) ||
          entries.some((entry) => entry.key === node.key && entry.verdict === "wrongCountry")) return false;
        seen.add(node.key);
        return index < 0 || pool.filters.some((filter) => filter.nameContains.length === 0 ||
          filter.nameContains.some((term) => this.endpoints[index].toLowerCase().includes(term.toLowerCase())));
      }).slice(0, capacity);
      keptPrevious = members.length > 0;
    }
    const poolChanged = JSON.stringify(members) !== JSON.stringify(previous);
    subscription.poolKeys = members;
    return { probedAtUnix: Math.floor(Date.now() / 1000),
      members, entries, poolChanged, keptPrevious };
  }

  private migrationPreview(p: Profile, path: string): XrayPolicyPreview {
    const conflict = (p.pinnedPolicies ?? []).some((route) =>
      route.selectors.includes("domain:ai.example") && route.endpointKey !== this.endpointKeys[0]);
    return {
      direct: 2, proxy: 1, block: 0, pinnedCount: p.subscription ? 1 : 0,
      privateLanDirect: false, quicReject: true,
      domainStrategy: "ipIfNonMatch", domainMatcher: null,
      endpointBypassCount: 1, hasGeoipOverride: true, hasGeositeOverride: true,
      hasDns: true, hasSockopts: true,
      trafficRuleCount: 2, interfaceRouteCount: 1, dnsServerCount: 1, dnsHostCount: 1,
      dnsRewriteRuleCount: 3, tunDnsServerCount: 2, tunMtu: 8500,
      connectionIdleSecs: 120, directDomainStrategy: "ForceIPv4",
      dnsEnableParallelQuery: false, hasDnsOutbound: true,
      backupCount: p.subscription ? 2 : null,
      skipped: ["wrapperInbound"],
      refused: path.includes("unsupported") ? ["unsupportedRule"]
        : conflict ? ["conflictingPinnedRoute"] : [],
    };
  }

  private find(id: unknown): Profile {
    const found = this.profiles.find((p) => p.id === id);
    if (!found) throw new Error("Sandbox profile not found");
    return found;
  }

  private stopped(p: Profile) {
    if (this.running.has(p.id)) throw new Error("Disconnect the profile before editing or deleting");
  }

  private allocateProxyPorts(p: Profile) {
    const used = new Set(this.profiles.filter((other) => other.id !== p.id).flatMap((other) => [other.xraySocksPort, other.xrayHttpPort]));
    let port = 10808;
    while (used.has(port) || used.has(port + 1)) port += 2;
    p.xraySocksPort = port;
    p.xrayHttpPort = port + 1;
  }

  private statuses(): TunnelStatus[] {
    return this.profiles.map((p) => {
      const running = this.running.has(p.id);
      this.tickServiceChecks(p, Date.now());
      const sub = p.subscription;
      const keys = sub ? [...new Set([
        sub.activeKey ?? this.endpointKeys[sub.activeIndex],
        ...(sub.backupKeys ?? []).map((node) => node.key),
        ...this.poolMembers(p).map((node) => node.key),
      ])].filter((key) => this.endpointKeys.includes(key)).slice(0, 8) : [];
      const multinode = (sub?.backupKeys?.length ?? 0) > 0 ||
        this.poolMembers(p).length > 0 ||
        (p.pinnedPolicies?.length ?? 0) > 0 || Boolean(p.xrayDns?.outboundKey);
      const failover = running && sub && multinode
        ? {
            primaryKey: keys[0],
            activeKey: keys[1] ?? keys[0],
            autoReturnPrimary: sub.autoReturnPrimary ?? true,
            failoverActive: keys.length > 1,
            nodes: keys.map((key, index) => ({
              key, healthy: index > 0 || keys.length === 1,
              lastProbeUnix: Math.floor(Date.now() / 1000) - 30,
              latencyMs: index > 0 || keys.length === 1 ? 62 : null,
            })),
          } : null;
      // Recovery diagnostics the daemon reports while a daemon-managed xray
      // tunnel runs — bounded, sanitized fields only.
      const watchdog = running && p.backend === "xray" && p.xrayMode === "tun"
        ? {
            uplink: true,
            egressSignature: "6f34752319a0e831",
            lastEgressChangeUnix: Math.floor(Date.now() / 1000) - 3600,
            httpsStallStreak: 0,
            httpsLatencyMs: 240,
            dnsStallStreak: 0,
            serviceChecks: this.serviceResults.get(p.id) ?? [],
            xrayUdpSockets: 312,
            connStorm: null,
            lastRecoveryUnix: null,
            anomalies: [],
          }
        : null;
      return { profileId: p.id, state: running ? "running" as const : "stopped" as const, message: null, failover, watchdog };
    });
  }

  private interfaces(): NetworkInterface[] {
    // Managed tunnel interfaces exist only while the tunnel runs — same as on
    // a real system. A foreign device holding the same name stays listed and
    // surfaces as the external-tunnel conflict in Profiles.
    const managed = this.profiles.filter((p) => p.backend !== "none" && !(p.backend === "xray" && p.xrayMode === "socks") && this.running.has(p.id)).map((p, i) => iface(p.interfaceName, i + 2, false, "up", p.backend === "none" ? "ethernet" : p.backend));
    const runningNames = new Set(this.profiles.filter((p) => this.running.has(p.id)).map((p) => p.interfaceName));
    return [iface("qa-ethernet", 1, true, "up"), ...managed, ...this.externalIfaces.filter((e) => !runningNames.has(e.name))];
  }

  private routes(): RouteEntry[] {
    // Foreign tunnels contribute real-looking overlapping routes while up —
    // /30 containing /32s and an IPv6 link-local, like a live kernel table.
    const external = this.externalIfaces.filter((e) => e.state === "up").flatMap((e) => {
      if (e.name === "tun-happ") return [
        { destination: "0.0.0.0", prefixLen: 0, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 1 },
        { destination: "172.19.0.0", prefixLen: 30, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 0 },
        { destination: "172.19.0.1", prefixLen: 32, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 0 },
        { destination: "172.19.0.3", prefixLen: 32, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 0 },
        { destination: "fe80::", prefixLen: 64, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 256 },
      ];
      if (e.name === "wg-home") return [
        { destination: "0.0.0.0", prefixLen: 0, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 5 },
      ];
      return [];
    });
    return [
      { destination: "0.0.0.0", prefixLen: 0, gateway: "192.0.2.1", interfaceIndex: 1, interfaceName: "qa-ethernet", metric: 100 },
      ...external,
      ...this.profiles.filter((p) => this.running.has(p.id)).flatMap((p) => p.routes.map((r) => {
        const [destination, prefix] = r.destination.split("/");
        return { destination, prefixLen: Number(prefix), gateway: r.via ?? null, interfaceIndex: this.interfaces().find((i) => i.name === p.interfaceName)?.ifIndex ?? 1, interfaceName: p.interfaceName, metric: r.metric };
      })),
    ];
  }

  private inspect(p: Profile): ProfileInspection {
    const analysis: ConfigAnalysis = {
      profileId: p.id, osRoutes: p.routes.map((r) => ({ destination: r.destination, source: "profile" })),
      internalRoutes: [], listeners: p.backend === "xray" ? [{ address: "127.0.0.1", port: p.xraySocksPort ?? 10808, protocol: "socks" }] : [],
      endpoints: p.backend === "none" ? [] : [{ address: "vpn.example.invalid", port: 443, protocol: p.backend }],
      domainPatterns: p.domainPolicies.flatMap((d) => d.domains), warnings: ["Synthetic configuration: no network traffic is sent."], routeKnowledgeComplete: true,
      peers: p.backend === "wireGuard" ? [{
        endpoint: { address: "vpn.example.invalid", port: 51820, protocol: "wireGuard" },
        routes: p.routes.map((r) => ({ destination: r.destination, source: "WireGuard AllowedIPs" })),
      }] : [],
      interfaceDetails: p.backend === "wireGuard" ? [{ field: "address", value: "10.203.0.2/32" }] : [],
    };
    return { analysis, conflicts: [], managedConfig: true };
  }

  private routeMap(includeInactive: unknown): RouteMap {
    return {
      predicted: this.profiles.filter((p) => includeInactive || this.running.has(p.id)).flatMap((p) => p.routes.map((r) => ({ destination: r.destination, ownerProfileId: p.id, ownerName: p.name, source: "profile", interfaceName: p.interfaceName, metric: r.metric, active: this.running.has(p.id) }))),
      effective: this.routes(), diffs: [], warnings: ["Sandbox route table; the host routing table is unchanged."], pushedRoutes: [],
    };
  }

  invoke(command: string, args: Record<string, unknown> = {}): unknown {
    // Clone responses to prevent UI edits from mutating backend state by reference.
    const result = this.dispatch(command, args);
    // Slow synthetic commands (delay probes) resolve later; clone on arrival.
    if (result instanceof Promise) return result.then((value) => structuredClone(value));
    return structuredClone(result);
  }

  private dispatch(command: string, args: Record<string, unknown>): unknown {
    switch (command) {
      case "get_platform_capabilities": return { os: "linux", systemProxy: false, wireguardStandardImport: false, managedXrayInstall: true, elevationRelaunch: false, appUpdates: false, executableExtensions: [] };
      case "get_profiles": return this.profiles;
      case "get_interfaces": return this.interfaces();
      case "get_routes": return this.routes();
      case "get_tunnel_statuses": return this.statuses();
      case "daemon_status": return { state: "ready", message: "Simulated daemon: host network is never modified." };
      case "system_proxy_status": {
        const owner = this.profiles.find((p) => this.running.has(p.id) && p.useSystemProxy);
        return { ownerProfileId: owner?.id ?? null, ownerName: owner?.name ?? null };
      }
      case "is_elevated": return false;
      case "get_auto_connect_result": return null;
      case "get_always_on_profiles": return this.enrollment;
      case "set_always_on_profile": {
        const p = this.find(args.id);
        if (!["wireGuard", "none"].includes(p.backend)) throw new Error("This backend does not support always-on");
        this.enrollment.profiles = this.enrollment.profiles.filter((e) => e.profileId !== p.id);
        this.enrollment.profiles.push({ kind: p.backend === "none" ? "staticRoutes" : "wireGuard", profileId: p.id, enabled: true });
        return { stored: true, active: this.running.has(p.id) };
      }
      case "remove_always_on_profile": this.enrollment.profiles = this.enrollment.profiles.filter((e) => e.profileId !== args.profileId || e.kind !== args.kind); return { removed: true };
      case "resume_always_on": this.enrollment.paused = false; return { resumed: true };
      case "get_login_autostart": return this.loginAutostart;
      case "set_login_autostart": this.loginAutostart = Boolean(args.enabled); return this.loginAutostart;
      case "get_vpn_auth_mode": return this.authMode;
      case "set_vpn_auth_mode": this.authMode = args.mode as VpnAuthMode; return this.authMode;
      case "get_recovery_report": return { issues: this.recovered ? [] : [{ kind: "ownedRoutes", profileId: "static", message: "Synthetic stale route from a previous sandbox session." }], requiresElevation: false };
      case "cleanup_recovery": this.recovered = true; return { issues: [], requiresElevation: false };
      case "connect_profile":
      case "connect_openvpn_with_credentials": {
        const p = this.find(args.id);
        if (this.running.has(p.id)) throw new Error("Profile is already running");
        if (p.backend === "none" && !p.routes.length) throw new Error("Static-routes profile has no routes");
        if (p.backend === "openVpn" && command === "connect_profile") throw "OpenVPN credentials required";
        this.running.add(p.id);
        this.resetServiceWorker(p);
        return this.statuses().find((s) => s.profileId === p.id);
      }
      case "disconnect_profile": {
        const p = this.find(args.id);
        this.running.delete(p.id);
        this.clearServiceState(p.id);
        return this.statuses().find((status) => status.profileId === p.id);
      }
      case "save_profile":
      case "save_vless_profile":
      case "save_wireguard_profile": {
        const p = structuredClone(args.profile) as Profile;
        if (!p.id || !p.name?.trim()) throw new Error("Profile name is required");
        const existing = this.profiles.find((e) => e.id === p.id);
        if (existing) this.stopped(existing);
        // Mirrors the Tauri command: failover settings are owned by their own
        // commands, a generic form save never drops them.
        p.subscription = existing?.subscription ?? p.subscription;
        p.pinnedPolicies = existing?.pinnedPolicies ?? p.pinnedPolicies;
        p.xrayServiceChecks = p.backend === "xray"
          ? structuredClone(existing?.backend === "xray" ? existing.xrayServiceChecks ?? [] : p.xrayServiceChecks ?? [])
          : [];
        this.validateServiceSpecs(p, p.xrayServiceChecks);
        if (command === "save_vless_profile") { p.configPath = `/sandbox/${p.id}.json`; this.allocateProxyPorts(p); }
        if (command === "save_wireguard_profile") p.configPath = `/sandbox/${p.id}.conf`;
        this.profiles = [...this.profiles.filter((e) => e.id !== p.id), p];
        this.resetServiceWorker(p);
        return this.profiles;
      }
      case "delete_profile": {
        const p = this.find(args.id);
        this.stopped(p);
        this.clearServiceState(p.id);
        this.profiles = this.profiles.filter((item) => item.id !== p.id);
        return this.profiles;
      }
      case "inspect_profiles": return this.profiles.map((p) => this.inspect(p));
      case "inspect_profile_by_id": return this.inspect(this.find(args.id));
      case "diagnose_profile": {
        const p = this.find(args.id);
        return { profileId: p.id, status: this.statuses().find((s) => s.profileId === p.id), inspection: this.inspect(p), checks: [{ name: "Sandbox isolation", level: "healthy", message: "All actions run in memory. No VPN process is started." }] };
      }
      case "get_route_map": return this.routeMap(args.includeInactive);
      case "lookup_destination": {
        const dest = String(args.dest);
        const ip = dest.split(".").map(Number);
        if (ip.length !== 4 || ip.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) throw new Error("Sandbox lookup supports IPv4 literals only");
        const bits = ip.reduce((n, b) => (n << 8) | b, 0) >>> 0;
        const matched = this.routes().filter((r) => {
          const network = r.destination.split(".").map(Number).reduce((n, b) => (n << 8) | b, 0) >>> 0;
          const mask = r.prefixLen === 0 ? 0 : (0xffffffff << (32 - r.prefixLen)) >>> 0;
          return ((network & mask) >>> 0) === ((bits & mask) >>> 0);
        }).sort((a, b) => b.prefixLen - a.prefixLen || a.metric - b.metric)[0];
        return { destination: dest, matchedRoute: matched, interfaceName: matched.interfaceName, table: "sandbox" };
      }
      case "set_interface_state": {
        // External fixtures may be flipped to demo the bring-down flow; all
        // other interface mutations stay read-only.
        const ext = this.externalIfaces.find((i) => i.name === args.name);
        if (!ext || typeof args.up !== "boolean") throw new Error("Interface mutations are disabled in sandbox");
        ext.state = args.up ? "up" : "down";
        return null;
      }
      case "stop_external_tunnel": {
        // Mirrors the daemon: a foreign WireGuard netdev is deleted, a
        // foreign TUN is only admin-downed (its owner still holds it).
        const ext = this.externalIfaces.find((i) => i.name === args.name);
        if (!ext) throw new Error("Sandbox interface not found");
        if (ext.kind === "wireGuard") {
          this.externalIfaces = this.externalIfaces.filter((i) => i.name !== args.name);
        } else {
          ext.state = "down";
        }
        return null;
      }
      case "get_subscription_endpoints": {
        const p = this.find(args.profileId);
        const backups = new Set((p.subscription?.backupKeys ?? []).map((ref) => ref.key));
        const listed = new Set(this.endpointKeys);
        const missing = (p.subscription?.backupKeys ?? [])
          .filter((ref) => !listed.has(ref.key))
          .map((ref) => ({
            key: ref.key, name: ref.name, active: false,
            protocol: null, isBackup: true, isMissing: true,
          }));
        return [
          ...this.endpoints.map((name, i) => ({
            key: this.endpointKeys[i],
            name,
            active: p.subscription?.activeIndex === i,
            protocol: i === 0 ? "VLESS · Reality" : i === 1 ? "VLESS · TLS" : "Hysteria2",
            isBackup: backups.has(this.endpointKeys[i]),
            isMissing: false,
            inPool: this.poolMembers(p).some((node) => node.key === this.endpointKeys[i]),
          })),
          ...missing,
        ];
      }
      case "switch_subscription_endpoint": {
        const p = this.find(args.profileId); this.stopped(p);
        const index = this.endpointKeys.indexOf(String(args.endpointKey));
        if (!p.subscription || index < 0) throw new Error("Invalid endpoint key");
        p.subscription.activeIndex = index;
        p.subscription.activeKey = this.endpointKeys[index];
        return this.profiles;
      }
      case "set_subscription_backups": {
        const p = this.find(args.profileId);
        if (!p.subscription) throw new Error("Not a subscription profile");
        const keys = (args.backupKeys as string[] ?? []);
        p.subscription.backupKeys = keys.map((key) => {
          const index = this.endpointKeys.indexOf(key);
          const known = p.subscription!.backupKeys?.find((ref) => ref.key === key);
          return { key, name: index >= 0 ? this.endpoints[index] : known?.name ?? key };
        });
        return this.profiles;
      }
      case "set_subscription_auto_return": {
        const p = this.find(args.profileId);
        if (!p.subscription) throw new Error("Not a subscription profile");
        p.subscription.autoReturnPrimary = Boolean(args.enabled);
        return this.profiles;
      }
      case "set_pinned_routes": {
        const p = this.find(args.profileId);
        if (!p.subscription) throw new Error("Not a subscription profile");
        const listed = new Set(this.endpointKeys);
        p.pinnedPolicies = ((args.routes as PinnedRoute[]) ?? []).map((route) => ({
          ...route,
          missing: !listed.has(route.endpointKey),
        }));
        this.resetServiceWorker(p);
        return this.profiles;
      }
      case "set_xray_service_checks": {
        const p = this.find(args.profileId);
        const checks = this.validateServiceSpecs(p, args.checks);
        const bound = this.serviceBindings(p);
        if (checks.some((check) => !bound.has(check.endpointKey) &&
          !p.xrayServiceChecks?.some((old) => old.id === check.id && old.endpointKey === check.endpointKey))) {
          throw new Error("The selected endpoint is not explicitly pinned");
        }
        p.xrayServiceChecks = checks;
        this.resetServiceWorker(p);
        return this.profiles;
      }
      case "run_xray_service_checks": {
        return this.runServiceChecks(this.find(args.profileId), args.checkIds);
      }
      case "set_subscription_node_pool": {
        const p = this.find(args.profileId);
        if (!p.subscription) throw new Error("Not a subscription profile");
        const pool = (args.pool ?? null) as NodePoolSettings | null;
        if (pool && (pool.filters.length < 1 || pool.filters.length > 8 ||
          pool.filters.some((filter) => filter.nameContains.length > 4 ||
            filter.nameContains.some((term) => !term.trim() || Array.from(term).length > 64) ||
            (pool.verifyExitCountry ? !/^[A-Za-z]{2}$/.test(filter.exitCountry ?? "")
              : Boolean(filter.exitCountry) || filter.nameContains.length === 0)))) {
          throw new Error("Invalid pool filters");
        }
        if (JSON.stringify(pool) !== JSON.stringify(p.subscription.nodePool ?? null)) {
          p.subscription.poolKeys = [];
        }
        p.subscription.nodePool = pool;
        if (!pool) p.subscription.poolKeys = [];
        return this.profiles;
      }
      case "rebuild_subscription_node_pool":
        return this.rebuildPool(this.find(args.profileId));
      case "verify_subscription_exits": {
        const p = this.find(args.profileId);
        const sub = p.subscription;
        if (!sub) throw new Error("Not a subscription profile");
        const chain = [...new Set([
          sub.activeKey ?? this.endpointKeys[sub.activeIndex],
          ...(sub.backupKeys ?? []).map((node) => node.key),
          ...this.poolMembers(p).map((node) => node.key),
        ])].filter((key) => this.endpointKeys.includes(key)).slice(0, 8);
        return chain.map((key) => {
          const index = this.endpointKeys.indexOf(key);
          const name = this.endpoints[index];
          const named = this.flagCountry(name);
          const exit = this.exitCountries[index];
          return {
            key, name, role: key === (sub.activeKey ?? this.endpointKeys[sub.activeIndex])
              ? "primary" : sub.backupKeys?.some((node) => node.key === key) ? "backup" : "pool",
            namedCountry: named, exitCountry: exit, exitIp: `198.51.100.${10 + index}`,
            mismatch: named !== null && named !== exit, error: null,
          };
        });
      }
      case "preview_xray_policy_migration": {
        const p = this.find(args.profileId); this.stopped(p);
        if (p.backend !== "xray") throw new Error("Policy migration requires an Xray profile");
        return this.migrationPreview(p, String(args.path ?? ""));
      }
      case "apply_xray_policy_migration": {
        const p = this.find(args.profileId); this.stopped(p);
        if (p.backend !== "xray") throw new Error("Policy migration requires an Xray profile");
        const preview = this.migrationPreview(p, String(args.path ?? ""));
        if (preview.refused.length) throw new Error("Policy migration refused unsupported or conflicting settings");
        p.domainPolicies = [
          { domains: ["domain:home.example", "domain:gov.example"], target: "direct" },
          { domains: ["domain:video.example"], target: "proxy" },
        ];
        p.privateLanDirect = false;
        p.xrayQuicReject = true;
        p.xrayDomainStrategy = "ipIfNonMatch";
        p.xraySockopts = { tcpKeepAliveIdle: 30, tcpKeepAliveInterval: 10,
          tcpUserTimeout: 20000, tcpNoDelay: true };
        p.xrayTrafficRules = [
          { ips: ["203.0.113.53"], port: 53, network: "tcp,udp", target: "direct" },
          { ips: ["203.0.113.54"], port: 853, network: "tcp", target: "direct" },
        ];
        p.xrayInterfaceRoutes = [{ selectors: ["domain:mesh.example", "10.9.0.0/16"],
          interfaceName: "qa-mesh", domainStrategy: "ForceIPv4" }];
        p.xrayConnectionIdleSecs = 120;
        p.xrayTunMtu = 8500;
        p.xrayTunDnsServers = ["1.1.1.1", "8.8.8.8"];
        p.xrayDirectDomainStrategy = "ForceIPv4";
        p.endpointBypasses = ["10.8.0.20"];
        p.xrayGeoipUrl = "https://example.invalid/synthetic/geoip.dat";
        p.xrayGeositeUrl = "https://example.invalid/synthetic/geosite.dat";
        p.xrayDns = {
          servers: [{ address: "1.1.1.1", port: null, domains: [], skipFallback: false, route: "proxy" }],
          hosts: { "synthetic.test": ["203.0.113.80"] }, fakeDns: false,
          queryStrategy: "useIpv4", enableParallelQuery: false,
          outboundKey: p.subscription ? this.endpointKeys[1] : null,
          outbound: { rewriteAddress: "9.9.9.9", rewriteNetwork: "udp", rewritePort: 53,
            rules: [{ action: "return", qType: "65,28", rCode: 5 },
              { action: "hijack", qType: "1", domain: ["domain:synthetic.test"] },
              { action: "direct" }] },
        };
        if (p.subscription) {
          p.subscription.backupKeys = [2, 7].map((index) => ({
            key: this.endpointKeys[index], name: this.endpoints[index],
          }));
          const route = { selectors: ["domain:ai.example"], endpointKey: this.endpointKeys[0] };
          if (!p.pinnedPolicies?.some((existing) => existing.endpointKey === route.endpointKey &&
            existing.selectors.includes("domain:ai.example"))) {
            p.pinnedPolicies = [...(p.pinnedPolicies ?? []), route];
          }
        }
        return this.profiles;
      }
      case "set_subscription_refresh_interval": {
        const p = this.find(args.profileId);
        if (!p.subscription) throw new Error("Not a subscription profile");
        p.subscription.refreshIntervalMinutes = args.refreshIntervalMinutes as number | null; return this.profiles;
      }
      case "refresh_subscription": {
        const p = this.find(args.id); this.stopped(p);
        if (!p.subscription) throw new Error("Not a subscription profile");
        p.subscription.lastRefreshAtUnix = Math.floor(Date.now() / 1000);
        const poolReport = p.subscription.nodePool ? this.rebuildPool(p) : null;
        return { endpointCount: this.endpoints.length, activeIndex: p.subscription.activeIndex, skippedCount: 0, fallbackUsed: false, cleanupFailed: false, poolReport };
      }
      case "measure_subscription_endpoint_delay": {
        // Deterministic synthetic latency with a real wait, so the browser
        // preview shows probes landing one by one; every fourth one times out.
        const index = Number(args.endpointIndex);
        const delayMs = 60 + ((index * 263) % 900);
        const unreachable = index % 4 === 3;
        return new Promise((resolve) =>
          setTimeout(
            () => resolve(unreachable ? { delayMs: null, error: "delay probe timed out" } : { delayMs, error: null }),
            unreachable ? 2500 : delayMs * 2,
          ));
      }
      case "import_share_link": {
        const link = String(args.link ?? "").trim();
        const invalid = () => new Error("Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://.");
        let url: URL;
        try { url = new URL(link); } catch { throw invalid(); }
        if (link.length > 65536 || /[\r\n]/.test(link) || !["vless:", "hysteria2:", "hy2:"].includes(url.protocol) || !url.username || !url.hostname || url.port === "0") throw invalid();
        let name = String(args.name ?? "").trim();
        if (!name) {
          try { name = decodeURIComponent(url.hash.slice(1)).trim(); } catch { name = ""; }
        }
        const p = profile(`link-${this.profiles.length}`, name || "Imported connection", "xray");
        this.allocateProxyPorts(p);
        p.configPath = `/sandbox/${p.id}.json`;
        this.profiles.push(p);
        return { profiles: this.profiles, errors: [] };
      }
      case "import_subscription": {
        const p = profile(`subscription-${this.profiles.length}`, "QA Imported subscription", "xray");
        this.allocateProxyPorts(p);
        p.subscription = structuredClone(this.profiles.find((p) => p.subscription)?.subscription ?? null);
        this.profiles.push(p); return { profiles: [p], errors: [] };
      }
      case "import_configs_batch": {
        const imported = [profile(`import-${this.profiles.length}`, "QA Imported WireGuard", "wireGuard", "10.99.0.0/24")];
        this.profiles.push(...imported); return { profiles: imported, errors: [] };
      }
      case "get_backend_availability": return (["wireGuard", "openVpn", "xray"] as const).map((backend): BackendAvailability => {
        if (backend === "xray" && this.xrayManaged) {
          return { backend, available: true, path: "/usr/lib/network-orchestrator/xray/v26.10.31/xray", source: "managed", version: "v26.10.31", message: "Simulated managed package; nothing is launched." };
        }
        if (backend === "xray") {
          return { backend, available: false, path: this.backendPaths.get(backend) ?? null, source: this.backendPaths.has(backend) ? "configured" : null, version: null, message: "Xray unavailable; TUN requires verified package Xray and network daemon." };
        }
        return { backend, available: true, path: this.backendPaths.get(backend) ?? `/sandbox/bin/${backend}`, source: this.backendPaths.has(backend) ? "configured" : "autoDetected", version: null, message: "Simulated executable; nothing is launched." };
      });
      case "get_managed_xray_offer": return { version: "v26.10.31", sourceUrl: "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip", sha256: "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214", maxDownloadBytes: 64 * 1024 * 1024 };
      case "install_managed_xray": this.xrayManaged = true; return "/usr/lib/network-orchestrator/xray/v26.10.31/xray";
      case "remove_managed_xray": this.xrayManaged = false; this.backendPaths.delete("xray"); return null;
      case "cancel_managed_xray_install": return null;
      case "set_backend_executable": this.backendPaths.set(String(args.backend), String(args.path)); return null;
      case "reset_backend_executable": this.backendPaths.delete(String(args.backend)); return null;
      case "plugin:app|version": return "Sandbox";
      case "plugin:dialog|open": return (args.options as { multiple?: boolean })?.multiple ? ["/sandbox/sample.conf"] : "/sandbox/sample.conf";
      case "plugin:dialog|message": {
        const buttons = args.buttons as string | { OkCancelCustom?: string[]; OkCustom?: string; YesNoCancelCustom?: string[] } | undefined;
        return buttons === "YesNo" ? "Yes" : typeof buttons === "object"
          ? buttons.OkCancelCustom?.[0] ?? buttons.OkCustom ?? buttons.YesNoCancelCustom?.[0] ?? "Ok"
          : "Ok";
      }
      case "list_conditional_rules": return { rules: this.condRules };
      case "put_conditional_rule": {
        const rule = args.rule as ConditionalRouteRule;
        const idx = this.condRules.findIndex((e) => e.rule.id === rule.id);
        const entry: ConditionalRuleEntry = {
          rule,
          status: rule.enabled
            ? { state: "active", matchedInterface: "qa-ethernet", appliedRoutes: rule.routes.length, detail: null }
            : { state: "disabled", matchedInterface: null, appliedRoutes: 0, detail: null },
        };
        if (idx >= 0) this.condRules[idx] = entry; else this.condRules.push(entry);
        return { stored: true, status: entry.status };
      }
      case "remove_conditional_rule": {
        const idx = this.condRules.findIndex((e) => e.rule.id === args.ruleId);
        if (idx >= 0) this.condRules.splice(idx, 1);
        return { removed: idx >= 0 };
      }
      case "parse_happ_routing": {
        // Sandbox preview only understands raw JSON — base64/deeplink
        // inputs are a native-parser feature.
        const raw = JSON.parse(String(args.payload)) as Record<string, unknown>;
        const pick = (key: string) =>
          Object.entries(raw).find(([k]) => k.toLowerCase() === key.toLowerCase())?.[1];
        const list = (v: unknown) =>
          Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [];
        const policies: DomainPolicy[] = [];
        for (const [target, sites, ips] of [
          ["block", "BlockSites", "BlockIp"],
          ["proxy", "ProxySites", "ProxyIp"],
          ["direct", "DirectSites", "DirectIp"],
        ] as const) {
          const domains = [...list(pick(sites)), ...list(pick(ips))];
          if (domains.length) policies.push({ domains, target });
        }
        if (policies.length === 0) throw new Error("invalid Happ routing profile: no recognizable fields");
        return {
          name: typeof pick("Name") === "string" ? pick("Name") : null,
          domainPolicies: policies,
          privateLanDirect: typeof pick("bypassPrivateIPs") === "boolean" ? pick("bypassPrivateIPs") : null,
          domainStrategy: null,
          domainMatcher: null,
          dns: { servers: [], hosts: {}, fakeDns: false, queryStrategy: null },
          geoipUrl: null,
          geositeUrl: null,
          warnings: [],
        };
      }
      case "xray_test_route": {
        // Lite simulator: literal domain/keyword selectors only — geo
        // lookups and DNS pins are native-side.
        const req = args.request as {
          target: string;
          domainPolicies: DomainPolicy[];
          privateLanDirect: boolean;
        };
        const host = String(req.target).split("://").pop()!.split("/")[0].split("@").pop()!;
        const bare = host.replace(/^\[|\].*$/g, "").split(":")[0].toLowerCase();
        const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(bare) || bare.includes(":") || /^[0-9a-f:]+$/i.test(bare) && bare.includes(":");
        const matchSel = (sel: string): boolean | null => {
          if (sel.startsWith("geosite:") || sel.startsWith("geoip:") || sel.startsWith("regexp:")) return null;
          if (sel.startsWith("keyword:")) return !isIp && bare.includes(sel.slice(8));
          if (sel.startsWith("full:")) return !isIp && bare === sel.slice(5);
          const pat = sel.startsWith("domain:") ? sel.slice(7) : sel;
          if (isIp) {
            if (pat.includes("/")) {
              const [net, bits] = pat.split("/");
              const toInt = (s: string) => s.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
              if (!/^\d+\.\d+\.\d+\.\d+$/.test(net)) return false;
              const mask = bits === "0" ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
              return (toInt(bare) & mask) === (toInt(net) & mask);
            }
            return bare === pat;
          }
          return bare === pat || bare.endsWith(`.${pat}`);
        };
        let outcome: { outbound: string; source: string; policyIndex?: number; selector?: string } =
          { outbound: "proxy", source: "default" };
        let sawUnknown = false;
        const steps: { label: string; selector?: string; outcome: string }[] = [];
        outer: for (const [index, policy] of (req.domainPolicies ?? []).entries()) {
          let unknown = false;
          for (const raw of policy.domains) {
            const sel = raw.trim();
            if (!sel || sel.startsWith("#")) continue;
            const hit = matchSel(sel);
            if (hit === true) {
              steps.push({ label: `${policy.target} rules #${index + 1}`, selector: sel, outcome: "match" });
              outcome = { outbound: policy.target, source: "policy", policyIndex: index, selector: sel };
              break outer;
            }
            if (hit === null) { unknown = true; sawUnknown = true; }
          }
          steps.push({ label: `${policy.target} rules #${index + 1}`, outcome: unknown ? "unknown" : "miss" });
        }
        if (outcome.source === "default") {
          if (req.privateLanDirect && isIp && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(bare)) {
            outcome = { outbound: "direct", source: "privateLan", selector: "privateLanDirect" };
          }
          steps.push({ label: "default", outcome: "match" });
        }
        return {
          target: bare,
          targetKind: isIp ? "ip" : "domain",
          outbound: outcome.outbound,
          source: outcome.source,
          policyIndex: outcome.policyIndex,
          matchedSelector: outcome.selector,
          certainty: sawUnknown ? "probable" : "certain",
          steps,
          notes: sawUnknown ? ["geoip/geosite selectors could not be evaluated: no geo assets on disk"] : [],
        };
      }
      case "get_net_tables": return {
        available: true,
        routes: [
          { family: "ipv4", destination: "0.0.0.0/0", table: 254, routeType: "unicast", scope: "universe", protocol: 16, managed: false, gateway: "192.168.1.1", interfaceIndex: 23, interfaceName: "enp59s0u2", metric: 100, prefSource: null, nexthops: [] },
          { family: "ipv4", destination: "0.0.0.0/1", table: 254, routeType: "unicast", scope: "universe", protocol: 3, managed: false, gateway: null, interfaceIndex: 91, interfaceName: "tun-happ", metric: 0, prefSource: null, nexthops: [] },
          { family: "ipv4", destination: "128.0.0.0/1", table: 254, routeType: "unicast", scope: "universe", protocol: 3, managed: false, gateway: null, interfaceIndex: 91, interfaceName: "tun-happ", metric: 0, prefSource: null, nexthops: [] },
          { family: "ipv4", destination: "198.51.100.88/32", table: 254, routeType: "unicast", scope: "universe", protocol: 79, managed: true, gateway: "192.168.1.1", interfaceIndex: 23, interfaceName: "enp59s0u2", metric: 51, prefSource: null, nexthops: [] },
          { family: "ipv4", destination: "0.0.0.0/1", table: 2022, routeType: "unicast", scope: "universe", protocol: 3, managed: false, gateway: "198.18.0.2", interfaceIndex: 132, interfaceName: "Mihomo", metric: 0, prefSource: null, nexthops: [] },
        ],
        rules: [
          { family: "ipv4", priority: 0, action: "lookup", table: 255, goto: null, from: null, to: null, fwmark: null, fwmask: null, iifname: null, oifname: null, uidRange: null, sourcePortRange: null, destinationPortRange: null, ipProtocol: null, suppressPrefixLength: null, suppressIfGroup: null, tunId: null, tos: 0, invert: false, protocol: 0, managed: false },
          { family: "ipv4", priority: 32766, action: "lookup", table: 254, goto: null, from: null, to: null, fwmark: null, fwmask: null, iifname: null, oifname: null, uidRange: null, sourcePortRange: null, destinationPortRange: null, ipProtocol: null, suppressPrefixLength: null, suppressIfGroup: null, tunId: null, tos: 0, invert: false, protocol: 0, managed: false },
        ],
      };
      case "net_explain": return {
        available: true,
        entries: [
          { owner: "manual", state: "applied", kind: "route", subject: "198.51.100.88/32 dev enp59s0u2 table main", status: "effective", detail: "installed" },
        ],
      };
      case "net_intent_list": return { intents: this.intents };
      case "net_intent_set": {
        const p = args.params as {
          id: string; destinations: string[];
          path: { kind: string; interface?: string };
          metric?: number; enabled?: boolean;
        };
        const wanted = p.destinations.length;
        const enabled = p.enabled !== false;
        const effective = p.path.kind === "direct" || p.path.interface === "Mihomo";
        const view: NetIntentView = {
          id: p.id,
          destinations: p.destinations,
          path: p.path,
          metric: p.metric ?? 100,
          enabled,
          status: !enabled ? "disabled" : effective ? "effective" : "deferred",
          detail: !enabled
            ? "disabled — routes are withdrawn"
            : effective
              ? `${wanted} route(s) enforced`
              : `interface ${p.path.interface ?? ""} is absent; armed until it appears`,
          installed: enabled && effective ? wanted : 0,
          wanted,
        };
        this.intents = [...this.intents.filter((i) => i.id !== p.id), view];
        return { id: p.id };
      }
      case "net_intent_del": {
        this.intents = this.intents.filter((i) => i.id !== args.id);
        return { id: args.id };
      }
      case "net_dns_status": return {
        available: true,
        resolvConf: ["127.0.0.53"],
        links: [
          { interfaceIndex: 132, interfaceName: "Mihomo", servers: ["198.18.0.2", "fdfe:dcba:9876::2"], currentServer: "198.18.0.2", defaultRoute: true, domains: [{ domain: ".", routeOnly: true }] },
          { interfaceIndex: 5, interfaceName: "tailscale0", servers: ["100.100.100.100"], currentServer: "100.100.100.100", defaultRoute: false, domains: [{ domain: "tailfa4e85.ts.net", routeOnly: false }, { domain: "ts.net", routeOnly: true }] },
          { interfaceIndex: 23, interfaceName: "enp59s0u2", servers: ["192.168.1.1"], currentServer: "192.168.1.1", defaultRoute: true, domains: [] },
        ],
      };
      case "net_dns_probe": return {
        server: "198.18.0.2", source: "198.18.0.1", interfaceIndex: 132, interfaceName: "Mihomo",
        gateway: "198.18.0.2", answers: ["example.com 1 A 198.18.0.226"], status: "NOERROR", rttMs: 12,
      };
      case "plugin:dialog|ask":
      case "plugin:dialog|confirm": return true;
      default: throw new Error(`Command is disabled in sandbox: ${command}`);
    }
  }
}
