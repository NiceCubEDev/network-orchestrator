import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import Modal from "./Modal";
import {
  AnalyzedRoute,
  DomainPolicy,
  DomainRouteTarget,
  HappRoutingImport,
  NetworkInterface,
  PinnedRoute,
  PolicyRoute,
  Profile,
  ProfileInspection,
  RouteCheckOutbound,
  RouteCheckResult,
  RouteCheckSource,
  TunnelBackend,
  WireGuardFields,
  XrayDnsConfig,
  XrayDomainMatcher,
  XrayDomainStrategy,
  XrayMode,
} from "../types";
import { usePlatformCapabilities } from "../platform";
import { ChevronIcon } from "../icons";
import { t, useT, type TranslationKey } from "../i18n";
import { BACKEND_LABEL_KEYS } from "../i18n/labels";

const BACKEND_EXTENSIONS: Record<TunnelBackend, string[]> = {
  none: [],
  wireGuard: ["conf", "dpapi"],
  openVpn: ["ovpn", "conf"],
  xray: ["json"],
};

const PROXY_BYPASS_PLACEHOLDER = "10.*, *.corp.local";

const RULE_SETS = [
  {
    id: "proxy",
    field: "rulesProxy",
    titleKey: "rules.proxy",
    placeholder: "geosite:youtube\ndomain:example.com",
  },
  {
    id: "direct",
    field: "rulesDirect",
    titleKey: "rules.direct",
    placeholder: "geosite:private\n# my services\n10.0.0.0/8",
  },
  {
    id: "block",
    field: "rulesBlock",
    titleKey: "rules.block",
    placeholder: "geosite:category-ads\ndomain:tracker.io",
  },
] as const;

type RulesSetId = (typeof RULE_SETS)[number]["id"];

const ROUTE_CHECK_OUTBOUND_KEYS: Record<RouteCheckOutbound, TranslationKey> = {
  proxy: "rules.proxy",
  direct: "rules.direct",
  block: "rules.block",
  dns: "rules.outboundDns",
};

const ROUTE_CHECK_SOURCE_KEYS: Record<RouteCheckSource, TranslationKey> = {
  dnsCapture: "rules.srcDnsCapture",
  policy: "rules.srcPolicy",
  resolverPin: "rules.srcResolverPin",
  multicast: "rules.srcMulticast",
  privateLan: "rules.srcPrivateLan",
  default: "rules.srcDefault",
};

/** Selector lines only — blank lines and # comments don't count. */
function countRuleLines(text: string): number {
  return text
    .split("\n")
    .filter((l) => l.trim() !== "" && !l.trim().startsWith("#")).length;
}

const EMPTY_WG_FIELDS: WireGuardFields = {
  privateKey: "",
  address: "",
  dns: "",
  peerPublicKey: "",
  peerEndpoint: "",
  allowedIps: "0.0.0.0/0",
  presharedKey: "",
  persistentKeepalive: 25,
};

function newProfileId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function clampMetric(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(9999, Math.trunc(value)));
}

function parseBypass(text: string): string[] {
  return text
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export interface ProfileFormState {
  /** Preserve settings owned by dedicated editors, not this form. */
  preservedProfile: Profile | null;
  expectedRevision: string | null;
  id: string;
  name: string;
  backend: TunnelBackend;
  configPath: string;
  interfaceName: string;
  routes: PolicyRoute[];
  autoConnect: boolean;
  xraySource: "json" | "vless";
  vlessUrl: string;
  wgSource: "file" | "fields";
  wgFields: WireGuardFields;
  xraySocksPort: number | null;
  xrayHttpPort: number | null;
  /** One selector per line per target; `#` lines are comments. */
  rulesProxy: string;
  rulesDirect: string;
  rulesBlock: string;
  privateLanDirect: boolean;
  useSystemProxy: boolean;
  proxyBypass: string;
  isNew: boolean;
  subscription: import("../types").SubscriptionMeta | null;
  xrayMode: XrayMode;
  xrayTunInterface: string;
  xrayTunIp: string;
  xrayGeoipUrl: string;
  xrayGeositeUrl: string;
  /** "" keeps the generated default. */
  xrayDomainStrategy: XrayDomainStrategy | "";
  xrayDomainMatcher: XrayDomainMatcher | "";
  /** Opaque pass-through: no editor yet, but a save must not wipe it. */
  xrayDns: XrayDnsConfig | null;
  /** Opaque pass-through: the failover editor owns node pins; a form save
   * carries them back unchanged. */
  pinnedPolicies: PinnedRoute[];
  /** Linux TUN: def1 halves (0.0.0.0/1 + 128.0.0.0/1) instead of 0.0.0.0/0. */
  xraySplitDefault: boolean;
  /** Linux TUN: kernel-level UDP/443 reject so QUIC falls back to TCP fast. */
  xrayQuicReject: boolean;
  /** staticRoutes: keep routes armed until the target interface appears. */
  waitForInterface: boolean;
  /** staticRoutes: comma-separated endpoint IPs/hostnames routed via the
   * physical gateway so another tunnel cannot swallow the handshake. */
  endpointBypasses: string;
}

/** Group a profile's policies into per-target text (comments preserved). */
function policiesToText(policies: DomainPolicy[], target: DomainRouteTarget): string {
  return policies
    .filter((p) => p.target === target)
    .flatMap((p) => p.domains)
    .join("\n");
}

/** Build policies from textarea content; ordering matches Happ's
 * block → proxy → direct precedence (first match wins in xray). */
function textToPolicies(
  rulesBlock: string,
  rulesProxy: string,
  rulesDirect: string,
): DomainPolicy[] {
  const parse = (text: string) =>
    text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  const policies: DomainPolicy[] = [];
  for (const [text, target] of [
    [rulesBlock, "block"],
    [rulesProxy, "proxy"],
    [rulesDirect, "direct"],
  ] as const) {
    const domains = parse(text);
    if (domains.length > 0) policies.push({ domains, target });
  }
  return policies;
}

export function newFormState(
  backend: TunnelBackend = "wireGuard",
  os?: string,
): ProfileFormState {
  return {
    preservedProfile: null,
    expectedRevision: null,
    id: newProfileId(),
    name: "",
    backend,
    configPath: "",
    interfaceName: "",
    routes: [],
    autoConnect: false,
    xraySource: "json",
    vlessUrl: "",
    wgSource: "fields",
    wgFields: { ...EMPTY_WG_FIELDS },
    xraySocksPort: null,
    xrayHttpPort: null,
    rulesProxy: "",
    rulesDirect: "",
    rulesBlock: "",
    privateLanDirect: false,
    useSystemProxy: false,
    proxyBypass: "",
    isNew: true,
    subscription: null,
    // On Linux a SOCKS listener captures no system traffic, so TUN is the
    // mode that actually tunnels; the backend import defaults match this.
    xrayMode: os === "linux" ? "tun" : "socks",
    xrayTunInterface: "",
    xrayTunIp: "172.19.0.1/30",
    xrayGeoipUrl: "",
    xrayGeositeUrl: "",
    xrayDomainStrategy: "",
    xrayDomainMatcher: "",
    xrayDns: null,
    xraySplitDefault: false,
    xrayQuicReject: false,
    waitForInterface: false,
    endpointBypasses: "",
    pinnedPolicies: [],
  };
}

export function editFormState(profile: Profile, revision: string): ProfileFormState {
  return {
    preservedProfile: structuredClone(profile),
    expectedRevision: revision,
    id: profile.id,
    name: profile.name,
    backend: profile.backend,
    configPath: profile.configPath,
    interfaceName: profile.interfaceName,
    routes: profile.routes.map((r) => ({ ...r })),
    autoConnect: profile.autoConnect,
    xraySource: "json",
    vlessUrl: "",
    wgSource: "file",
    wgFields: { ...EMPTY_WG_FIELDS },
    xraySocksPort: profile.xraySocksPort,
    xrayHttpPort: profile.xrayHttpPort,
    rulesProxy: policiesToText(profile.domainPolicies, "proxy"),
    rulesDirect: policiesToText(profile.domainPolicies, "direct"),
    rulesBlock: policiesToText(profile.domainPolicies, "block"),
    privateLanDirect: profile.privateLanDirect,
    useSystemProxy: profile.useSystemProxy,
    proxyBypass: profile.proxyBypass.join(", "),
    isNew: false,
    subscription: profile.subscription,
    xrayMode: profile.xrayMode ?? "socks",
    xrayTunInterface: profile.xrayTunInterface ?? "",
    xrayTunIp: profile.xrayTunIp ?? "172.19.0.1/30",
    xrayGeoipUrl: profile.xrayGeoipUrl ?? "",
    xrayGeositeUrl: profile.xrayGeositeUrl ?? "",
    xrayDomainStrategy: profile.xrayDomainStrategy ?? "",
    xrayDomainMatcher: profile.xrayDomainMatcher ?? "",
    xrayDns: profile.xrayDns ? structuredClone(profile.xrayDns) : null,
    xraySplitDefault: profile.xraySplitDefault ?? false,
    xrayQuicReject: profile.xrayQuicReject ?? false,
    waitForInterface: profile.waitForInterface ?? false,
    endpointBypasses: (profile.endpointBypasses ?? []).join(", "),
    pinnedPolicies: profile.pinnedPolicies ?? [],
  };
}

interface ProfileFormModalProps {
  open: boolean;
  editing: ProfileFormState | null;
  interfaces: NetworkInterface[];
  initialTab?: FormTab;
  onClose: () => void;
  onSaved: (profiles: Profile[], inspection: ProfileInspection | null) => void;
  onError: (message: string) => void;
}

type FormTab = "general" | "connection" | "routing";

export default function ProfileFormModal({
  open,
  editing,
  interfaces,
  initialTab = "general",
  onClose,
  onSaved,
  onError,
}: ProfileFormModalProps) {
  const [form, setForm] = useState<ProfileFormState | null>(editing);
  const [formError, setFormError] = useState<string | null>(null);
  const caps = usePlatformCapabilities();
  const [saving, setSaving] = useState(false);
  const [probing, setProbing] = useState(false);
  const [probeResults, setProbeResults] = useState<AnalyzedRoute[] | null>(null);
  const [probeNotice, setProbeNotice] = useState<string | null>(null);
  const [bulkCidrs, setBulkCidrs] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [happOpen, setHappOpen] = useState(false);
  const [happPayload, setHappPayload] = useState("");
  const [happBusy, setHappBusy] = useState(false);
  const [happNotice, setHappNotice] = useState<string | null>(null);
  const [routeCheckTarget, setRouteCheckTarget] = useState("");
  const [routeCheckBusy, setRouteCheckBusy] = useState(false);
  const [routeCheckResult, setRouteCheckResult] = useState<RouteCheckResult | null>(null);
  const [routeCheckError, setRouteCheckError] = useState<string | null>(null);
  const [tab, setTab] = useState<FormTab>("general");
  const [rulesEditor, setRulesEditor] = useState<RulesSetId | null>(null);
  const tr = useT();

  useEffect(() => {
    if (open) {
      setForm(editing);
      setFormError(null);
      setBulkCidrs("");
      setBulkOpen(false);
      setHappPayload("");
      setHappOpen(false);
      setHappNotice(null);
      setRouteCheckTarget("");
      setRouteCheckResult(null);
      setRouteCheckError(null);
      setTab(initialTab);
      setRulesEditor(null);
      setProbeResults(null);
      setProbeNotice(null);
    }
  }, [open, editing?.id, initialTab]);

  const current = form ?? editing;
  if (!current) return null;

  const targetable = interfaces.filter((i) => i.category !== "filter");
  const systemProxyAvailable =
    current.xrayMode === "socks" &&
    (current.xraySocksPort !== null ||
      (current.isNew && current.xraySource === "vless"));
  const daemonManagedInterface = caps?.os === "linux" && (
    current.backend === "wireGuard" ||
    current.backend === "openVpn" ||
    (current.backend === "xray" && current.xrayMode === "tun")
  );

  const update = (patch: Partial<ProfileFormState>) =>
    setForm({ ...current, ...patch });

  /** Show a validation error and jump to the tab that contains the field. */
  const fail = (message: string, targetTab: FormTab) => {
    setFormError(message);
    setTab(targetTab);
  };

  const policyRuleCount =
    textToPolicies(current.rulesBlock, current.rulesProxy, current.rulesDirect)
      .reduce((n, p) => n + p.domains.length, 0);
  const routingCount = current.routes.length + policyRuleCount;
  const rulesEditorSet =
    RULE_SETS.find((s) => s.id === rulesEditor) ?? null;

  const browseConfig = async () => {
    try {
      const selected = await openDialog({
        multiple: false,
        directory: false,
        filters: [
          {
            name: tr("form.configFilter", { backend: tr(BACKEND_LABEL_KEYS[current.backend]) }),
            extensions: BACKEND_EXTENSIONS[current.backend],
          },
        ],
      });
      if (typeof selected === "string") {
        update({ configPath: selected });
      }
    } catch (err) {
      setFormError(String(err));
    }
  };

  const probeRoutes = async () => {
    if (!current.configPath.trim()) {
      setProbeNotice(tr("form.probeSetConfig"));
      return;
    }
    setProbing(true);
    setProbeNotice(null);
    setProbeResults(null);
    try {
      const routes = await invoke<AnalyzedRoute[]>("probe_openvpn_routes", {
        id: current.id,
      });
      setProbeResults(routes);
      setProbeNotice(
        routes.length === 0
          ? tr("form.probeNone")
          : tr("form.probeFound", { count: routes.length }),
      );
    } catch (err) {
      setProbeNotice(String(err));
    } finally {
      setProbing(false);
    }
  };

  const addProbedRoutes = () => {
    if (!probeResults) return;
    const existing = new Set(current.routes.map((r) => r.destination));
    const toAdd = probeResults
      .filter((r) => !existing.has(r.destination))
      .map((r) => ({
        destination: r.destination,
        metric: 5,
      }));
    if (toAdd.length === 0) {
      setProbeNotice(tr("form.probeAllAdded"));
      return;
    }
    update({ routes: [...current.routes, ...toAdd] });
    setProbeNotice(tr("form.probeAdded", { count: toAdd.length }));
  };

  const updateRoute = (index: number, patch: Partial<PolicyRoute>) =>
    update({
      routes: current.routes.map((r, i) =>
        i === index ? { ...r, ...patch } : r,
      ),
    });

  const addBulkCidrs = async () => {
    if (!bulkCidrs.trim()) return;
    setBulkBusy(true);
    setFormError(null);
    try {
      const cidrs = await invoke<string[]>("parse_bulk_cidrs", { input: bulkCidrs });
      if (cidrs.length === 0) {
        setFormError(tr("form.errNoCidrs"));
        return;
      }
      const existing = new Set(current.routes.map((route) => route.destination.trim()));
      update({
        routes: [
          ...current.routes,
          ...cidrs.filter((cidr) => !existing.has(cidr)).map((destination) => ({ destination, metric: 5 })),
        ],
      });
      setBulkCidrs("");
    } catch (err) {
      setFormError(String(err));
    } finally {
      setBulkBusy(false);
    }
  };

  const applyHappImport = async () => {
    if (!happPayload.trim()) return;
    setHappBusy(true);
    setHappNotice(null);
    setFormError(null);
    try {
      const imported = await invoke<HappRoutingImport>("parse_happ_routing", {
        payload: happPayload,
      });
      const dns = imported.dns;
      const hasDns =
        dns.servers.length > 0 ||
        Object.keys(dns.hosts).length > 0 ||
        dns.fakeDns ||
        dns.queryStrategy != null ||
        dns.enableParallelQuery != null ||
        dns.outboundKey != null ||
        dns.outbound != null;
      update({
        // A profile with any lists replaces all three buckets — absent
        // buckets are empty in Happ semantics. A DNS-only import leaves
        // the rule text alone.
        ...(imported.domainPolicies.length > 0
          ? {
              rulesBlock: policiesToText(imported.domainPolicies, "block"),
              rulesProxy: policiesToText(imported.domainPolicies, "proxy"),
              rulesDirect: policiesToText(imported.domainPolicies, "direct"),
            }
          : {}),
        privateLanDirect: imported.privateLanDirect ?? current.privateLanDirect,
        xrayDomainStrategy:
          imported.domainStrategy ?? current.xrayDomainStrategy,
        xrayDomainMatcher: imported.domainMatcher ?? current.xrayDomainMatcher,
        xrayDns: hasDns ? { ...current.xrayDns, ...dns } : current.xrayDns,
        xrayGeoipUrl: imported.geoipUrl ?? current.xrayGeoipUrl,
        xrayGeositeUrl: imported.geositeUrl ?? current.xrayGeositeUrl,
      });
      setHappPayload("");
      setHappNotice(
        imported.warnings.length > 0
          ? imported.warnings.join("\n")
          : tr("rules.happApplied"),
      );
    } catch (err) {
      setHappNotice(String(err));
    } finally {
      setHappBusy(false);
    }
  };

  const runRouteCheck = async () => {
    const target = routeCheckTarget.trim();
    if (!target) return;
    setRouteCheckBusy(true);
    setRouteCheckError(null);
    try {
      const result = await invoke<RouteCheckResult>("xray_test_route", {
        request: {
          target,
          domainPolicies: textToPolicies(
            current.rulesBlock,
            current.rulesProxy,
            current.rulesDirect,
          ),
          privateLanDirect: current.privateLanDirect,
          domainStrategy: current.xrayDomainStrategy || null,
          dns: current.xrayDns ?? {
            servers: [],
            hosts: {},
            fakeDns: false,
            queryStrategy: null,
          },
          geoipUrl: current.xrayGeoipUrl || null,
          geositeUrl: current.xrayGeositeUrl || null,
        },
      });
      setRouteCheckResult(result);
    } catch (err) {
      setRouteCheckResult(null);
      setRouteCheckError(String(err));
    } finally {
      setRouteCheckBusy(false);
    }
  };

  const save = async () => {
    for (const route of current.routes) {
      if (!route.destination.trim()) {
        fail(tr("form.errRouteBlank"), "routing");
        return;
      }
    }
    if (current.routes.length > 0 && !current.interfaceName.trim()
      && !daemonManagedInterface) {
      fail(tr("form.errIfaceRequired"), "routing");
      return;
    }
    const endpointBypasses = parseBypass(current.endpointBypasses);
    if (
      current.backend === "none" &&
      current.routes.length === 0 &&
      endpointBypasses.length === 0
    ) {
      fail(tr("form.errStaticRoute"), "routing");
      return;
    }
    const isXray = current.backend === "xray";
    const isVlessImport =
      isXray && current.isNew && current.xraySource === "vless";
    const isWgFields =
      current.backend === "wireGuard" &&
      current.isNew &&
      current.wgSource === "fields";
    const proxyBypass = parseBypass(current.proxyBypass);
    if (isXray && current.useSystemProxy) {
      for (const entry of proxyBypass) {
        if (entry.includes(";")) {
          fail(tr("form.errBypassSemicolon"), "connection");
          return;
        }
      }
    }
    const domainPolicies = textToPolicies(
      current.rulesBlock,
      current.rulesProxy,
      current.rulesDirect,
    );
    if (isVlessImport) {
      if (!current.vlessUrl.trim()) {
        fail(tr("form.errShareRequired"), "connection");
        return;
      }
      if (
        current.xraySocksPort !== null &&
        (!Number.isInteger(current.xraySocksPort) ||
          current.xraySocksPort < 1 ||
          current.xraySocksPort > 65535)
      ) {
        fail(tr("form.errSocksPort"), "connection");
        return;
      }
    }
    if (isWgFields) {
      const f = current.wgFields;
      if (!f.privateKey.trim()) {
        fail(tr("form.errWgPrivKey"), "connection");
        return;
      }
      if (!f.address.trim()) {
        fail(tr("form.errWgAddr"), "connection");
        return;
      }
      if (!f.peerPublicKey.trim()) {
        fail(tr("form.errWgPeerKey"), "connection");
        return;
      }
      if (!f.peerEndpoint.trim()) {
        fail(tr("form.errWgEndpoint"), "connection");
        return;
      }
      if (!f.allowedIps.trim()) {
        fail(tr("form.errWgAllowed"), "connection");
        return;
      }
    }
    const payload: Profile = {
      ...(current.preservedProfile ?? {}),
      id: current.id,
      name: current.name.trim(),
      backend: current.backend,
      configPath: current.configPath.trim(),
      interfaceName: current.interfaceName.trim(),
      routes: current.routes.map((r) => ({
        destination: r.destination.trim(),
        metric: clampMetric(r.metric),
        via: r.via?.trim() || null,
      })),
      autoConnect: current.autoConnect,
      domainPolicies: isXray ? domainPolicies : [],
      privateLanDirect: isXray && current.privateLanDirect,
      xraySocksPort: !isXray
        ? null
        : isVlessImport
          ? current.xraySocksPort
          : current.isNew
            ? null
            : current.xraySocksPort,
      xrayHttpPort: isXray && !current.isNew ? current.xrayHttpPort : null,
      useSystemProxy: isXray && current.useSystemProxy && current.xrayMode === "socks",
      proxyBypass: isXray ? proxyBypass : [],
      subscription: current.isNew ? null : current.subscription ?? null,
      xrayMode: isXray ? current.xrayMode : "socks",
      xrayTunInterface: isXray
        ? current.xrayMode === "tun" && caps?.os === "windows"
          ? current.xrayTunInterface.trim() || null
          : current.preservedProfile?.xrayTunInterface ?? null
        : null,
      xrayTunIp: isXray
        ? current.xrayMode === "tun" && caps?.os === "windows"
          ? current.xrayTunIp.trim() || null
          : current.preservedProfile?.xrayTunIp ?? null
        : null,
      xrayGeoipUrl: isXray ? current.xrayGeoipUrl.trim() || null : null,
      xrayGeositeUrl: isXray ? current.xrayGeositeUrl.trim() || null : null,
      xrayDomainStrategy: isXray && current.xrayDomainStrategy ? current.xrayDomainStrategy : null,
      xrayDomainMatcher: isXray && current.xrayDomainMatcher ? current.xrayDomainMatcher : null,
      xrayDns: isXray ? (current.xrayDns ?? undefined) : undefined,
      xraySplitDefault: isXray && current.xrayMode === "tun" && current.xraySplitDefault,
      // Linux TUN only: edited on Linux; a save made elsewhere keeps the
      // stored flag, non-Xray backends never carry it.
      xrayQuicReject:
        isXray && caps?.os === "linux" && current.xrayMode === "tun"
          ? current.xrayQuicReject
          : isXray
            ? (current.xrayQuicReject ?? false)
            : false,
      waitForInterface: current.backend === "none" && current.waitForInterface,
      endpointBypasses:
        current.backend === "none" || isXray ? endpointBypasses : [],
      // Linux multinode: the failover editor owns these; carry them back so a
      // form save cannot drop them (the backend re-restores either way).
      pinnedPolicies: isXray ? current.pinnedPolicies : [],
      xrayServiceChecks: isXray ? current.preservedProfile?.xrayServiceChecks ?? [] : [],
      // `netorch proxy` owns named exits; carry them back unchanged.
      xrayProxyExits: isXray ? current.preservedProfile?.xrayProxyExits ?? [] : [],
    };
    setSaving(true);
    try {
      let updated: Profile[];
      if (isVlessImport) {
        updated = await invoke<Profile[]>("save_vless_profile", {
          profile: payload,
          expectedRevision: current.expectedRevision,
          vlessUrl: current.vlessUrl.trim(),
        });
      } else if (isWgFields) {
        updated = await invoke<Profile[]>("save_wireguard_profile", {
          profile: payload,
          expectedRevision: current.expectedRevision,
          fields: current.wgFields,
        });
      } else {
        updated = await invoke<Profile[]>("save_profile", { profile: payload, expectedRevision: current.expectedRevision });
      }
      let inspection: ProfileInspection | null = null;
      try {
        inspection = await invoke<ProfileInspection>(
          "inspect_profile_by_id",
          { id: current.id },
        );
      } catch (err) {
        onError(t("form.errAnalysis", { err: String(err) }));
      }
      onSaved(updated, inspection);
      setForm(null);
      setFormError(null);
    } catch (err) {
      setFormError(String(err).includes("profile changed; close and reopen the editor to reload")
        ? tr("form.profileConflict") : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      title={current.isNew ? tr("form.newTitle") : tr("form.editTitle")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose} disabled={saving}>
            {tr("common.cancel")}
          </button>
          <button
            type="button"
            className="btn-primary"
            onClick={save}
            disabled={saving}
          >
            {saving ? tr("common.saving") : tr("common.save")}
          </button>
        </>
      }
    >
      <div className="modal-tabs" role="tablist" aria-label={tr("form.tabsAria")}>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "general"}
          className={`modal-tab ${tab === "general" ? "active" : ""}`}
          onClick={() => setTab("general")}
        >
          {tr("form.tabGeneral")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "connection"}
          className={`modal-tab ${tab === "connection" ? "active" : ""}`}
          onClick={() => setTab("connection")}
        >
          {tr("form.tabConnection")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "routing"}
          className={`modal-tab ${tab === "routing" ? "active" : ""}`}
          onClick={() => setTab("routing")}
        >
          {tr("form.tabRouting")}
          {routingCount > 0 && (
            <span className="modal-tab-count">{routingCount}</span>
          )}
        </button>
      </div>

      {formError && <p className="error">{formError}</p>}

      {tab === "general" && (
      <div className="modal-tab-body" role="tabpanel">
      <label>
        {tr("form.name")}
        <input
          type="text"
          value={current.name}
          onChange={(e) => update({ name: e.target.value })}
          placeholder={tr("form.namePh")}
          autoFocus={initialTab === "general"}
        />
      </label>
      <label>
        {tr("detail.backend")}
        <select
          className="filter-select"
          value={current.backend}
          onChange={(e) => {
            const backend = e.target.value as TunnelBackend;
            update({
              backend,
              configPath: "",
              rulesProxy: backend === "xray" ? current.rulesProxy : "",
              rulesDirect: backend === "xray" ? current.rulesDirect : "",
              rulesBlock: backend === "xray" ? current.rulesBlock : "",
              privateLanDirect: backend === "xray" && current.privateLanDirect,
              xraySource: "json",
              xraySocksPort:
                backend === "xray"
                  ? current.isNew
                    ? null
                    : (current.xraySocksPort ?? 10808)
                  : null,
              xrayHttpPort: backend === "xray" ? current.xrayHttpPort : null,
            });
          }}
        >
          <option value="none">{tr("form.staticNoTunnel")}</option>
          <option value="wireGuard">WireGuard</option>
          <option value="openVpn">OpenVPN</option>
          <option value="xray">Xray</option>
        </select>
      </label>
      {caps?.os === "linux" && (
        <label className="profile-proxy-toggle">
          <input
            type="checkbox"
            checked={current.autoConnect}
            onChange={(e) => update({ autoConnect: e.target.checked })}
          />
          {tr("form.autoConnect")}
        </label>
      )}
      </div>
      )}

      {tab === "connection" && (
      <div className="modal-tab-body" role="tabpanel">
      {current.backend !== "none" && current.backend === "xray" && current.isNew && (
        <label>
          {tr("form.configSource")}
          <select
            className="filter-select"
            value={current.xraySource}
            onChange={(e) =>
              update({ xraySource: e.target.value as "json" | "vless" })
            }
          >
            <option value="json">{tr("form.xrayJson")}</option>
            <option value="vless">{tr("form.shareLink")}</option>
          </select>
        </label>
      )}
      {current.backend === "wireGuard" && current.isNew && (
        <label>
          {tr("form.configSource")}
          <select
            className="filter-select"
            value={current.wgSource}
            onChange={(e) =>
              update({ wgSource: e.target.value as "file" | "fields" })
            }
          >
            <option value="fields">{tr("form.wgFields")}</option>
            <option value="file">{tr("form.wgFile")}</option>
          </select>
        </label>
      )}
      {current.backend === "xray" &&
      current.isNew &&
      current.xraySource === "vless" ? (
        <>
          <label>
            {tr("form.shareLink")}
            <input
              type="password"
              value={current.vlessUrl}
              onChange={(e) => update({ vlessUrl: e.target.value })}
              placeholder="vless:// or hysteria2://…"
              autoComplete="off"
            />
          </label>
          <span className="profile-help">
            {tr("form.socksAuto")}
          </span>
        </>
      ) : current.backend === "wireGuard" &&
        current.isNew &&
        current.wgSource === "fields" ? (
        <div className="profile-wg-fields">
          <label>
            {tr("form.privKey")}
            <input
              type="password"
              value={current.wgFields.privateKey}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, privateKey: e.target.value },
                })
              }
              placeholder={tr("form.privKeyPh")}
              autoComplete="off"
            />
          </label>
          <label>
            {tr("form.ifaceAddr")}
            <input
              type="text"
              value={current.wgFields.address}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, address: e.target.value },
                })
              }
              placeholder="10.0.0.2/24"
            />
          </label>
          <label>
            {tr("form.dnsOpt")}
            <input
              type="text"
              value={current.wgFields.dns}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, dns: e.target.value },
                })
              }
              placeholder="1.1.1.1"
            />
          </label>
          <label>
            {tr("form.peerKey")}
            <input
              type="text"
              value={current.wgFields.peerPublicKey}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    peerPublicKey: e.target.value,
                  },
                })
              }
              placeholder={tr("form.peerKeyPh")}
            />
          </label>
          <label>
            {tr("form.peerEndpoint")}
            <input
              type="text"
              value={current.wgFields.peerEndpoint}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    peerEndpoint: e.target.value,
                  },
                })
              }
              placeholder="vpn.example.com:51820"
            />
          </label>
          <label>
            {tr("form.allowedIps")}
            <input
              type="text"
              value={current.wgFields.allowedIps}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, allowedIps: e.target.value },
                })
              }
              placeholder="0.0.0.0/0"
            />
          </label>
          <label>
            {tr("form.psk")}
            <input
              type="password"
              value={current.wgFields.presharedKey}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    presharedKey: e.target.value,
                  },
                })
              }
              placeholder={tr("form.pskPh")}
              autoComplete="off"
            />
          </label>
          <label>
            {tr("form.keepalive")}
            <input
              type="number"
              min={0}
              max={65535}
              value={current.wgFields.persistentKeepalive ?? ""}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    persistentKeepalive:
                      e.target.value === "" ? null : e.target.valueAsNumber,
                  },
                })
              }
              placeholder="25"
            />
          </label>
        </div>
      ) : current.backend !== "none" ? (
        <label>
          {tr("form.configFile")}
          <div className="profile-config-row">
            <input
              type="text"
              value={current.configPath}
              onChange={(e) => update({ configPath: e.target.value })}
              placeholder={
                current.backend === "wireGuard"
                  ? "C:\\path\\tunnel.conf"
                  : current.backend === "openVpn"
                    ? "C:\\path\\client.ovpn"
                    : "C:\\path\\config.json"
              }
            />
            <button type="button" onClick={browseConfig}>
              {tr("form.browse")}
            </button>
          </div>
        </label>
      ) : (
        <span className="profile-help">
          {tr("form.staticHelp")}
        </span>
      )}
      {current.backend === "openVpn" && caps?.os !== "linux" && !current.isNew && current.configPath.trim() && (
        <div className="profile-probe">
          <button
            type="button"
            className="profile-probe-btn"
            onClick={probeRoutes}
            disabled={probing}
          >
            {probing ? tr("form.probing") : tr("form.probe")}
          </button>
          <span className="profile-help">
            {tr("form.probeHelpA")} <code>--route-nopull</code> {tr("form.probeHelpB")}
          </span>
          {probeNotice && (
            <p className={`probe-notice ${probeResults && probeResults.length > 0 ? "ok" : ""}`}>
              {probeNotice}
            </p>
          )}
          {probeResults && probeResults.length > 0 && (
            <div className="probe-results">
              <div className="probe-results-head">
                <span>{tr("form.probeDiscovered", { n: probeResults.length })}</span>
                <button type="button" className="profile-probe-add" onClick={addProbedRoutes}>
                  {tr("form.probeAddAll")}
                </button>
              </div>
              <ul className="probe-route-list">
                {probeResults.map((r, i) => (
                  <li key={i}>
                    <span className="mono">{r.destination}</span>
                    <span className="probe-route-source">{r.source}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
      {current.backend === "xray" && (
        <label>
          {tr("form.xrayMode")}
          <select
            className="filter-select"
            value={current.xrayMode}
            onChange={(e) =>
              update({ xrayMode: e.target.value as XrayMode })
            }
          >
            <option value="socks">{tr("form.socksMode")}</option>
            <option value="tun" disabled={caps?.os === "linux" && current.xraySource !== "vless" && current.xraySocksPort === null}>
              {caps?.os === "linux" ? tr("form.tunLinux") : tr("form.tunWin")}
            </option>
          </select>
        </label>
      )}
      {current.backend === "xray" &&
        current.xrayMode === "tun" && (
          <div className="profile-tun-fields">
            {caps?.os === "linux" ? (
              <>
              <span className="profile-help">
                {tr("form.tunHelpLinux")}
              </span>
              <label className="profile-proxy-toggle">
                <input
                  type="checkbox"
                  checked={current.xraySplitDefault}
                  onChange={(e) =>
                    update({ xraySplitDefault: e.target.checked })
                  }
                />
                <span>{tr("form.splitDefault")}</span>
              </label>
              <span className="profile-help">
                {tr("form.splitDefaultHint")}
              </span>
              <label className="profile-proxy-toggle">
                <input
                  type="checkbox"
                  checked={current.xrayQuicReject}
                  onChange={(e) =>
                    update({ xrayQuicReject: e.target.checked })
                  }
                />
                <span>{tr("form.quicReject")}</span>
              </label>
              <span className="profile-help">
                {tr("form.quicRejectHint")}
              </span>
              </>
            ) : (
            <>
            <label>
              {tr("form.tunIface")}
              <input
                type="text"
                value={current.xrayTunInterface}
                onChange={(e) =>
                  update({ xrayTunInterface: e.target.value })
                }
                placeholder="xray-tun"
              />
            </label>
            <label>
              {tr("form.tunIp")}
              <input
                type="text"
                value={current.xrayTunIp}
                onChange={(e) => update({ xrayTunIp: e.target.value })}
                placeholder="172.19.0.1/30"
              />
            </label>
            <span className="profile-help">
              {tr("form.tunHelpWin")}
            </span>
            </>
            )}
          </div>
        )}
      {current.backend === "xray" &&
        !current.isNew &&
        current.xrayMode === "socks" &&
        current.xraySocksPort !== null && (
          <div className="interface-row">
            <span className="row-label">SOCKS5</span>
            <span className="row-value mono">
              127.0.0.1:{current.xraySocksPort}
            </span>
          </div>
        )}
      {current.backend === "xray" &&
        !current.isNew &&
        current.xrayMode === "socks" &&
        current.xrayHttpPort !== null && (
          <div className="interface-row">
            <span className="row-label">HTTP CONNECT</span>
            <span className="row-value mono">
              127.0.0.1:{current.xrayHttpPort}
            </span>
          </div>
        )}
      {current.backend === "xray" &&
        current.xrayMode === "socks" &&
        caps?.systemProxy && (
        <div className="profile-proxy">
          <label className="profile-proxy-toggle">
            <input
              type="checkbox"
              checked={current.useSystemProxy}
              disabled={!systemProxyAvailable}
              onChange={(e) =>
                update({ useSystemProxy: e.target.checked })
              }
            />
            {tr("form.sysProxy")}
          </label>
          {!systemProxyAvailable ? (
            <span className="profile-help">
              {tr("form.sysProxyUnavailable")}
            </span>
          ) : (
            <span className="profile-help">
              {tr("form.sysProxyHelp")}
            </span>
          )}
          {current.useSystemProxy && systemProxyAvailable && (
            <label>
              {tr("form.bypassLabel")}
              <input
                type="text"
                value={current.proxyBypass}
                onChange={(e) => update({ proxyBypass: e.target.value })}
                placeholder={PROXY_BYPASS_PLACEHOLDER}
              />
            </label>
          )}
        </div>
      )}
      </div>
      )}

      {tab === "routing" && rulesEditorSet !== null && (
      <div className="modal-tab-body rules-editor" role="tabpanel">
        <div className="rules-editor-head">
          <button
            type="button"
            className="rules-back"
            onClick={() => setRulesEditor(null)}
          >
            <span className="rules-back-icon">
              <ChevronIcon size={13} />
            </span>
            {tr("rules.back")}
          </button>
          <span className={`rules-editor-title rules-fg-${rulesEditorSet.id}`}>
            {tr(rulesEditorSet.titleKey)}
          </span>
          <span className="rules-summary-count">
            {tr("rules.entryCount", {
              count: countRuleLines(current[rulesEditorSet.field]),
            })}
          </span>
        </div>
        <span className="profile-routes-hint">{tr("form.rulesHint")}</span>
        <textarea
          className="rules-editor-textarea"
          value={current[rulesEditorSet.field]}
          onChange={(e) =>
            update({ [rulesEditorSet.field]: e.target.value } as Partial<ProfileFormState>)
          }
          placeholder={rulesEditorSet.placeholder}
          spellCheck={false}
        />
      </div>
      )}

      {tab === "routing" && rulesEditorSet === null && (
      <div className="modal-tab-body" role="tabpanel">
      {!daemonManagedInterface && <label>
        {tr("form.targetIface")}
        <input
          type="text"
          list="profile-target-interfaces"
          value={current.interfaceName}
          onChange={(e) => update({ interfaceName: e.target.value })}
          placeholder={tr("form.targetIfacePh")}
        />
        <datalist id="profile-target-interfaces">
          {targetable.map((i) => (
            <option
              key={i.ifIndex}
              value={i.friendlyName}
              label={i.description || i.name}
            />
          ))}
        </datalist>
      </label>}
      <div className="profile-routes">
        <div className="profile-routes-head">
          <span>{tr("form.policyRoutes")}</span>
          <button
            type="button"
            onClick={() =>
              update({
                routes: [
                  ...current.routes,
                  { destination: "10.0.0.0/24", metric: 5 },
                ],
              })
            }
          >
            {tr("form.addRoute")}
          </button>
        </div>
        <button
          type="button"
          className="connection-detail-toggle"
          onClick={() => setBulkOpen((v) => !v)}
          aria-expanded={bulkOpen}
        >
          <ChevronIcon size={13} collapsed={!bulkOpen} />
          {tr("form.bulkToggle")}
        </button>
        {bulkOpen && (
          <div className="profile-bulk-cidrs">
            <label>
              {tr("form.bulkLabel")}
              <textarea
                value={bulkCidrs}
                onChange={(event) => setBulkCidrs(event.target.value)}
                rows={3}
                placeholder={"10.0.0.0/24\n2001:db8::/32"}
              />
            </label>
            <div className="profile-bulk-actions">
              <input
                type="file"
                accept=".txt,.csv,text/plain,text/csv"
                aria-label={tr("form.bulkFileAria")}
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  if (!file) return;
                  if (file.size > 1024 * 1024) {
                    setFormError(tr("form.bulkTooBig"));
                    return;
                  }
                  try {
                    setBulkCidrs(await file.text());
                  } catch {
                    setFormError(tr("form.bulkReadFailed"));
                  }
                }}
              />
              <button type="button" onClick={addBulkCidrs} disabled={bulkBusy || !bulkCidrs.trim()}>
                {bulkBusy ? tr("form.adding") : tr("form.addCidrs")}
              </button>
            </div>
          </div>
        )}
        {current.routes.length === 0 && (
          <span className="profile-routes-empty">
            {tr("form.noRoutes")}
          </span>
        )}
        {current.routes.map((route, index) => (
          <div className="profile-route-row" key={index}>
            <input
              type="text"
              value={route.destination}
              onChange={(e) =>
                updateRoute(index, { destination: e.target.value })
              }
              placeholder="10.0.0.0/24"
            />
            <input
              type="text"
              value={route.via ?? ""}
              onChange={(e) => updateRoute(index, { via: e.target.value })}
              placeholder={tr("form.gwPh")}
              aria-label={tr("form.gwPh")}
            />
            <input
              type="number"
              min={0}
              max={9999}
              value={route.metric}
              onChange={(e) =>
                updateRoute(index, {
                  metric: clampMetric(e.target.valueAsNumber),
                })
              }
            />
            <button
              type="button"
              onClick={() =>
                update({
                  routes: current.routes.filter((_, i) => i !== index),
                })
              }
            >
              {tr("common.remove")}
            </button>
          </div>
        ))}
      </div>
      {current.backend === "none" && (
        <div className="profile-routes">
          <div className="profile-routes-head">
            <span>{tr("form.externalAttach")}</span>
          </div>
          <label className="profile-proxy-toggle">
            <input
              type="checkbox"
              checked={current.waitForInterface}
              onChange={(e) =>
                update({ waitForInterface: e.target.checked })
              }
            />
            {tr("form.waitForInterface")}
          </label>
          <span className="profile-routes-hint">
            {tr("form.waitForInterfaceHint")}
          </span>
          <label>
            {tr("form.endpointBypasses")}
            <input
              type="text"
              value={current.endpointBypasses}
              onChange={(e) =>
                update({ endpointBypasses: e.target.value })
              }
              placeholder={tr("form.endpointBypassesPh")}
              spellCheck={false}
            />
          </label>
          <span className="profile-routes-hint">
            {tr("form.endpointBypassesHint")}
          </span>
        </div>
      )}
      {current.backend === "xray" && (
        <div className="profile-routes">
          <div className="profile-routes-head">
            <span>{tr("form.domainRouting")}</span>
          </div>
          <span className="profile-routes-hint">
            {tr("form.rulesHint")}
          </span>
          <div className="rules-summary">
            {RULE_SETS.map((set) => (
              <button
                type="button"
                key={set.id}
                className="rules-summary-row"
                onClick={() => setRulesEditor(set.id)}
              >
                <span className={`rules-dot rules-dot-${set.id}`} />
                <span className="rules-summary-title">{tr(set.titleKey)}</span>
                <span className="rules-summary-count">
                  {tr("rules.entryCount", {
                    count: countRuleLines(current[set.field]),
                  })}
                </span>
                <ChevronIcon size={13} collapsed />
              </button>
            ))}
          </div>
          <label className="profile-proxy-toggle">
            <input
              type="checkbox"
              checked={current.privateLanDirect}
              onChange={(e) => update({ privateLanDirect: e.target.checked })}
            />
            {tr("form.privateLanDirect")}
          </label>
          <div className="route-check">
            <div className="route-check-row">
              <input
                type="text"
                value={routeCheckTarget}
                onChange={(e) => setRouteCheckTarget(e.target.value)}
                placeholder={tr("rules.testPlaceholder")}
                spellCheck={false}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void runRouteCheck();
                  }
                }}
              />
              <button
                type="button"
                onClick={() => void runRouteCheck()}
                disabled={routeCheckBusy || !routeCheckTarget.trim()}
              >
                {routeCheckBusy ? tr("rules.testChecking") : tr("rules.testCheck")}
              </button>
            </div>
            {routeCheckError && (
              <span className="profile-routes-hint">{routeCheckError}</span>
            )}
            {routeCheckResult && (
              <div className="route-check-result">
                <span
                  className={`route-check-verdict rules-fg-${routeCheckResult.outbound}`}
                >
                  {routeCheckResult.target}
                  {routeCheckResult.port != null
                    ? `:${routeCheckResult.port}`
                    : ""}
                  {" → "}
                  {tr(ROUTE_CHECK_OUTBOUND_KEYS[routeCheckResult.outbound])}
                </span>
                <span className="profile-routes-hint">
                  {routeCheckResult.source === "policy" &&
                  routeCheckResult.policyIndex != null
                    ? tr("rules.srcPolicy", {
                        index: routeCheckResult.policyIndex + 1,
                      })
                    : tr(ROUTE_CHECK_SOURCE_KEYS[routeCheckResult.source])}
                  {routeCheckResult.matchedSelector
                    ? ` · ${routeCheckResult.matchedSelector}`
                    : ""}
                </span>
                {routeCheckResult.certainty === "probable" && (
                  <span className="profile-routes-hint">
                    {tr("rules.testProbable")}
                  </span>
                )}
                {routeCheckResult.notes.map((note, index) => (
                  <span key={index} className="profile-routes-hint">
                    {note}
                  </span>
                ))}
              </div>
            )}
          </div>
          <button
            type="button"
            className="connection-detail-toggle"
            onClick={() => setHappOpen((v) => !v)}
            aria-expanded={happOpen}
          >
            <ChevronIcon size={13} collapsed={!happOpen} />
            {tr("rules.importHapp")}
          </button>
          {happOpen && (
            <div className="profile-bulk-cidrs">
              <label>
                {tr("rules.happHint")}
                <textarea
                  value={happPayload}
                  onChange={(event) => setHappPayload(event.target.value)}
                  rows={4}
                  placeholder='{"Name":"…","DirectSites":[…]}'
                  spellCheck={false}
                />
              </label>
              <div className="profile-bulk-actions">
                <button
                  type="button"
                  onClick={applyHappImport}
                  disabled={happBusy || !happPayload.trim()}
                >
                  {happBusy ? tr("rules.happApplying") : tr("rules.happApply")}
                </button>
              </div>
              {happNotice && (
                <span className="profile-routes-hint">{happNotice}</span>
              )}
            </div>
          )}
          <label>
            {tr("rules.domainStrategy")}
            <select
              value={current.xrayDomainStrategy}
              onChange={(e) =>
                update({
                  xrayDomainStrategy: e.target.value as XrayDomainStrategy | "",
                })
              }
            >
              <option value="">{tr("rules.strategyDefault")}</option>
              <option value="asIs">AsIs</option>
              <option value="ipIfNonMatch">IPIfNonMatch</option>
              <option value="ipOnDemand">IPOnDemand</option>
            </select>
          </label>
          <label>
            {tr("rules.domainMatcher")}
            <select
              value={current.xrayDomainMatcher}
              onChange={(e) =>
                update({
                  xrayDomainMatcher: e.target.value as XrayDomainMatcher | "",
                })
              }
            >
              <option value="">{tr("rules.matcherDefault")}</option>
              <option value="mph">mph</option>
              <option value="hybrid">hybrid</option>
              <option value="linear">linear</option>
            </select>
          </label>
          {current.xrayDns &&
            (current.xrayDns.servers.length > 0 ||
              Object.keys(current.xrayDns.hosts).length > 0 ||
              current.xrayDns.fakeDns) && (
              <span className="profile-routes-hint">
                {tr("rules.dnsSummary", {
                  servers: current.xrayDns.servers.length,
                  hosts: Object.keys(current.xrayDns.hosts).length,
                })}
                {current.xrayDns.fakeDns ? " · fakeDNS" : ""}
              </span>
            )}
          {current.xrayMode === "tun" && (
            <div className="geo-override">
              <span className="profile-routes-hint">
                {tr("form.geoHint")}
              </span>
              <div className="geo-override-fields">
                <input
                  type="text"
                  value={current.xrayGeoipUrl}
                  onChange={(e) => update({ xrayGeoipUrl: e.target.value })}
                  placeholder="https://…/geoip.dat"
                  spellCheck={false}
                />
                <input
                  type="text"
                  value={current.xrayGeositeUrl}
                  onChange={(e) => update({ xrayGeositeUrl: e.target.value })}
                  placeholder="https://…/geosite.dat"
                  spellCheck={false}
                />
              </div>
            </div>
          )}
        </div>
      )}
      </div>
      )}
    </Modal>
  );
}
