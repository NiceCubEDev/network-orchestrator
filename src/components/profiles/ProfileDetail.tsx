import { useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  backendIcon,
  CloseIcon,
  PlusIcon,
  SpinnerIcon,
} from "../../icons";
import { formatBytes } from "../../format";
import { TranslationKey, useT } from "../../i18n";
import { providerPrefix } from "../../subscriptions";
import {
  AlwaysOnKind,
  AlwaysOnListResult,
  DomainPolicy,
  DomainRouteTarget,
  PinnedRoute,
  Profile,
  ProfileInspection,
  SubscriptionDelayResult,
  SubscriptionEndpointInfo,
  TunnelStatus,
} from "../../types";
import OverflowMenu from "../ui/OverflowMenu";
import RateText from "../ui/RateText";
import ToggleSwitch from "../ui/ToggleSwitch";
import LinuxXrayPolicySection from "./LinuxXrayPolicySection";
import TunnelRoleSection, { supportsRole } from "./TunnelRoleSection";

const CONFIG_FIELD_LABEL_KEYS: Record<string, TranslationKey> = {
  address: "detail.cfg.address",
  dns: "detail.cfg.dns",
  mtu: "detail.cfg.mtu",
  listenPort: "detail.cfg.listenPort",
  protocol: "detail.cfg.protocol",
  device: "detail.cfg.device",
  cipher: "detail.cfg.cipher",
  authUserPass: "detail.cfg.authUserPass",
};

export const DOMAIN_TARGET_LABEL_KEYS: Record<
  DomainRouteTarget,
  "rules.block" | "rules.proxy" | "rules.direct"
> = {
  block: "rules.block",
  proxy: "rules.proxy",
  direct: "rules.direct",
};

/** Counts real selectors; `#` comment lines are stored in `domains` for
 * round-trip through the editor but are not rules. */
function countPolicyRules(
  policies: DomainPolicy[],
  target?: DomainRouteTarget,
): number {
  return policies
    .filter((p) => target === undefined || p.target === target)
    .flatMap((p) => p.domains)
    .filter((d) => !d.trimStart().startsWith("#")).length;
}

/** Same thresholds as the native client: <300 ms good, <800 ms fair. */
function delayClass(
  result: SubscriptionDelayResult | undefined,
  measuring: boolean,
): string {
  if (measuring || !result) return "";
  if (result.delayMs === null) return "delay-bad";
  return result.delayMs < 300
    ? "delay-good"
    : result.delayMs < 800
      ? "delay-fair"
      : "delay-bad";
}

interface ProfileDetailProps {
  profile: Profile;
  status: TunnelStatus;
  rate: { rxRate: number; txRate: number } | null;
  isBusy: boolean;
  backendLabel: string;
  managedConfig: boolean | undefined;
  inspection: ProfileInspection | null;
  alwaysOn: AlwaysOnListResult | null;
  os: string | undefined;
  endpoints: SubscriptionEndpointInfo[] | undefined;
  delayResults: Record<number, SubscriptionDelayResult> | undefined;
  measuringEndpoints: Set<string>;
  measuringAll: boolean;
  cancellingMeasurement: boolean;
  switching: boolean;
  refreshingSubscription: boolean;
  settingRefreshInterval: boolean;
  diagBusy: boolean;
  canMoveUp: boolean;
  canMoveDown: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onEdit: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onToggleAlwaysOn: (kind: AlwaysOnKind, enrolled: boolean) => void;
  onCredentials: () => void;
  onRefreshSubscription: () => void;
  onDiagnose: () => void;
  onDelete: () => void;
  onSwitchEndpoint: (key: string) => void;
  onMeasureAllEndpoints: () => void;
  onSetRefreshInterval: (minutes: number | null) => void;
  onCopyTerminalProxy: () => void;
  onRoleChanged: () => void;
  /** Linux failover: replace the ordered backup chain with these keys. */
  onSetBackups: (keys: string[]) => void;
  onSetAutoReturn: (enabled: boolean) => void;
  onSetPinnedRoutes: (routes: PinnedRoute[]) => void;
  /** One failover save in flight (backups, auto-return or pins). */
  failoverBusy: boolean;
  /** Edits were saved while the tunnel ran: they apply on reconnect. */
  applyOnReconnect: boolean;
  onPolicySaved: (profileId: string, profiles: Profile[]) => Promise<void>;
}

export default function ProfileDetail({
  profile,
  status,
  rate,
  isBusy: profileBusy,
  backendLabel,
  managedConfig,
  inspection,
  alwaysOn,
  os,
  endpoints,
  delayResults,
  measuringEndpoints,
  measuringAll,
  cancellingMeasurement,
  switching,
  refreshingSubscription,
  settingRefreshInterval,
  diagBusy,
  canMoveUp,
  canMoveDown,
  onConnect,
  onDisconnect,
  onEdit,
  onMoveUp,
  onMoveDown,
  onToggleAlwaysOn,
  onCredentials,
  onRefreshSubscription,
  onDiagnose,
  onDelete,
  onSwitchEndpoint,
  onMeasureAllEndpoints,
  onSetRefreshInterval,
  onCopyTerminalProxy,
  onRoleChanged,
  onSetBackups,
  onSetAutoReturn,
  onSetPinnedRoutes,
  failoverBusy,
  applyOnReconnect,
  onPolicySaved,
}: ProfileDetailProps) {
  const t = useT();
  const [pinVia, setPinVia] = useState("");
  const [pinSelectors, setPinSelectors] = useState("");
  const [policyBusy, setPolicyBusy] = useState(false);
  const isBusy = profileBusy || policyBusy;

  const alwaysOnKind: AlwaysOnKind | null =
    profile.backend === "wireGuard"
      ? "wireGuard"
      : profile.backend === "none"
        ? "staticRoutes"
        : null;
  const alwaysOnEntry = alwaysOn?.profiles.find(
    (item) => item.profileId === profile.id && item.kind === alwaysOnKind,
  );
  const canEnableAlwaysOn =
    alwaysOnKind !== null &&
    alwaysOn?.supportedKinds.includes(alwaysOnKind) === true &&
    (alwaysOnKind === "wireGuard" ||
      (profile.interfaceName.length > 0 && profile.routes.length > 0));
  const ruleCount = countPolicyRules(profile.domainPolicies);
  const detailCount = profile.routes.length + ruleCount;
  const isWireGuard = profile.backend === "wireGuard";
  const showConfig =
    isWireGuard || profile.backend === "openVpn";
  const configDetails = showConfig
    ? (inspection?.analysis.interfaceDetails ?? [])
    : [];
  // WireGuard peers own their routes; OpenVPN routes/endpoints render flat.
  const peers = isWireGuard ? (inspection?.analysis.peers ?? []) : [];
  const configRoutes =
    showConfig && !isWireGuard ? (inspection?.analysis.osRoutes ?? []) : [];
  const configEndpoints =
    showConfig && !isWireGuard ? (inspection?.analysis.endpoints ?? []) : [];
  const endpointDisplay = endpoints
    ? providerPrefix(endpoints.map((e) => e.name))
    : null;
  const subscription = profile.subscription;
  const trafficUsed =
    subscription?.userInfo !== null && subscription?.userInfo !== undefined
      ? subscription.userInfo.uploadBytes + subscription.userInfo.downloadBytes
      : null;
  const limitExhausted =
    trafficUsed !== null &&
    subscription?.userInfo?.totalBytes !== null &&
    subscription?.userInfo?.totalBytes !== undefined &&
    trafficUsed >= subscription.userInfo.totalBytes;
  const expiresDaysLeft =
    subscription?.userInfo?.expiresAtUnix != null
      ? Math.ceil((subscription.userInfo.expiresAtUnix * 1000 - Date.now()) / 86_400_000)
      : null;

  // Linux multinode: ordered backups, auto-return and fail-closed node pins.
  const multinode = os === "linux" && Boolean(profile.subscription) && endpoints !== undefined;
  const backupRefs = subscription?.backupKeys ?? [];
  const backupOrder = new Map(backupRefs.map((ref, i) => [ref.key, i]));
  const endpointName = (key: string): string => {
    const index = endpoints?.findIndex((e) => e.key === key) ?? -1;
    if (index >= 0) {
      return endpointDisplay?.names[index] ?? endpoints![index].name;
    }
    return [...backupRefs, ...(subscription?.poolKeys ?? [])]
      .find((ref) => ref.key === key)?.name ?? key;
  };
  const failover = status.failover ?? null;
  const pinnedRoutes = profile.pinnedPolicies ?? [];
  const liveEndpoints = endpoints?.filter((e) => !e.isMissing) ?? [];

  const moveBackup = (key: string, delta: number) => {
    const keys = backupRefs.map((ref) => ref.key);
    const index = keys.indexOf(key);
    const target = index + delta;
    if (index < 0 || target < 0 || target >= keys.length) return;
    [keys[index], keys[target]] = [keys[target], keys[index]];
    onSetBackups(keys);
  };
  const setBackupMembership = (key: string, member: boolean) => {
    onSetBackups(
      member
        ? [...backupRefs.map((ref) => ref.key), key]
        : backupRefs.map((ref) => ref.key).filter((k) => k !== key),
    );
  };
  const addPinnedRoute = () => {
    const selectors = pinSelectors
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("#"));
    if (!pinVia || selectors.length === 0) return;
    const routes = pinnedRoutes.map((route) => ({
      ...route,
      selectors: [...route.selectors],
    }));
    const existing = routes.find((route) => route.endpointKey === pinVia);
    if (existing) {
      for (const selector of selectors) {
        if (!existing.selectors.includes(selector)) existing.selectors.push(selector);
      }
    } else {
      routes.push({ selectors, endpointKey: pinVia });
    }
    onSetPinnedRoutes(routes);
    setPinSelectors("");
  };
  const removePinnedRoute = (key: string) => {
    onSetPinnedRoutes(pinnedRoutes.filter((route) => route.endpointKey !== key));
  };

  const openExternal = (url: string) => {
    if (isTauri()) {
      void openUrl(url);
    } else {
      window.open(url, "_blank", "noopener");
    }
  };

  return (
    <div className="profile-detail">
      <div className="profile-detail-head">
        <span
          className={`backend-avatar backend-avatar-lg backend-avatar-${profile.backend}`}
        >
          {backendIcon(profile.backend, 20)}
        </span>
        <div className="profile-detail-title">
          <div className="connection-card-name-row">
            <span className="profile-detail-name">{profile.name}</span>
            {managedConfig === true && (
              <span className="badge badge-managed">{t("detail.managed")}</span>
            )}
            {profile.useSystemProxy && (
              <span className="badge badge-managed">{t("detail.proxy")}</span>
            )}
            {alwaysOnEntry && (
              <span className="badge badge-managed">
                {alwaysOnEntry.enabled
                  ? alwaysOn?.paused
                    ? t("detail.alwaysOnPaused")
                    : t("detail.alwaysOn")
                  : t("detail.alwaysOnPending")}
              </span>
            )}
            {managedConfig === false && (
              <span className="badge badge-external">{t("detail.external")}</span>
            )}
          </div>
          <span
            className={`profile-detail-meta ${
              status.state === "failed" ? "failed" : ""
            }`}
            title={
              status.state === "failed" && status.message
                ? status.message
                : undefined
            }
          >
            {status.state === "failed"
              ? (status.message ?? t("detail.failed"))
              : status.state === "running"
                ? t("detail.runningOn", {
                    iface:
                      status.interfaceName || profile.interfaceName || "tunnel",
                  })
                : t("detail.stopped")}
          </span>
        </div>
        <ToggleSwitch
          checked={status.state === "running"}
          onChange={() =>
            status.state === "running" ? onDisconnect() : onConnect()
          }
          disabled={isBusy}
          busy={isBusy}
          title={status.state === "running" ? t("common.disconnect") : t("common.connect")}
        />
        <OverflowMenu
          title={t("detail.actions")}
          items={[
            { label: t("common.edit"), onClick: onEdit, disabled: isBusy },
            {
              label: t("detail.moveUp"),
              onClick: onMoveUp,
              disabled: isBusy || !canMoveUp,
            },
            {
              label: t("detail.moveDown"),
              onClick: onMoveDown,
              disabled: isBusy || !canMoveDown,
            },
            ...(os === "linux" &&
            alwaysOnKind &&
            (alwaysOnEntry || canEnableAlwaysOn)
              ? [
                  {
                    label: alwaysOnEntry
                      ? t("detail.disableAlwaysOn")
                      : t("detail.enableAlwaysOn"),
                    onClick: () =>
                      onToggleAlwaysOn(alwaysOnKind, Boolean(alwaysOnEntry)),
                    disabled: isBusy,
                  },
                ]
              : []),
            ...(os === "linux" && profile.backend === "openVpn"
              ? [
                  {
                    label: t("detail.credentials"),
                    onClick: onCredentials,
                    disabled: isBusy,
                  },
                ]
              : []),
            ...(profile.subscription && endpoints
              ? [
                  {
                    label: refreshingSubscription
                      ? t("detail.refreshing")
                      : t("detail.refreshSub"),
                    onClick: onRefreshSubscription,
                    disabled:
                      refreshingSubscription ||
                      switching ||
                      isBusy ||
                      status.state === "running",
                  },
                ]
              : []),
            {
              label: diagBusy ? t("detail.runningDiag") : t("detail.diagnostics"),
              onClick: onDiagnose,
              disabled: isBusy || diagBusy,
            },
            {
              label: t("common.delete"),
              onClick: onDelete,
              disabled: isBusy,
              danger: true,
            },
          ]}
        />
      </div>

      <div className="profile-detail-body">
        <div className="interface-row">
          <span className="row-label">{t("detail.backend")}</span>
          <span className="row-value">{backendLabel}</span>
        </div>
        <div className="interface-row">
          <span className="row-label">{t("detail.interface")}</span>
          <span className="row-value mono">
            {profile.interfaceName || t("detail.notAssigned")}
          </span>
        </div>
        {os === "linux" && supportsRole(profile) && (
          <TunnelRoleSection
            profile={profile}
            disabled={isBusy || status.state === "running"}
            onChanged={onRoleChanged}
          />
        )}
        {rate && (
          <div className="interface-row">
            <span className="row-label">{t("detail.rate")}</span>
            <span className="row-value">
              <RateText rx={rate.rxRate} tx={rate.txRate} live />
            </span>
          </div>
        )}

        {(configDetails.length > 0 ||
          configEndpoints.length > 0 ||
          configRoutes.length > 0 ||
          peers.length > 0) && (
          <div className="interface-section">
            <span className="section-label">{t("detail.tunnelConfig")}</span>
            {configDetails.map((d, i) => (
              <div className="interface-row" key={i}>
                <span className="row-label">
                  {t(CONFIG_FIELD_LABEL_KEYS[d.field] ?? "detail.tunnelConfig")}
                </span>
                <span className="row-value mono">{d.value}</span>
              </div>
            ))}
            {peers.map((peer, pi) => (
              <div className="peer-block" key={pi}>
                <div className="interface-row">
                  <span className="row-label">
                    {t("detail.peerN", { n: pi + 1 })}
                  </span>
                  <span className="row-value mono">
                    {peer.endpoint
                      ? `${peer.endpoint.address}${peer.endpoint.port !== null ? `:${peer.endpoint.port}` : ""}`
                      : "—"}
                  </span>
                </div>
                {peer.routes.length > 0 && (
                  <ul className="profile-route-list">
                    {peer.routes.map((route, i) => (
                      <li key={i}>
                        <span className="mono">{route.destination}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
            {configEndpoints.map((ep, i) => (
              <div className="interface-row" key={i}>
                <span className="row-label">{t("detail.peerEndpoint")}</span>
                <span className="row-value mono">
                  {ep.address}
                  {ep.port !== null ? `:${ep.port}` : ""}
                </span>
              </div>
            ))}
            {configRoutes.length > 0 && (
              <ul className="profile-route-list">
                {configRoutes.map((route, i) => (
                  <li key={i}>
                    <span className="mono">{route.destination}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {profile.backend === "xray" &&
          profile.xrayMode === "socks" &&
          profile.xraySocksPort !== null && (
            <div className="interface-row">
              <span className="row-label">SOCKS5</span>
              <span className="row-value mono">
                127.0.0.1:{profile.xraySocksPort}
              </span>
            </div>
          )}
        {profile.backend === "xray" &&
          profile.xrayMode === "socks" &&
          profile.xrayHttpPort !== null && (
            <div className="interface-row">
              <span className="row-label">HTTP CONNECT</span>
              <span className="row-value mono">
                127.0.0.1:{profile.xrayHttpPort}
              </span>
            </div>
          )}
        {profile.backend === "xray" &&
          profile.xrayMode === "socks" &&
          profile.xraySocksPort !== null &&
          status.state === "running" && (
            <div className="sub-links">
              <button
                type="button"
                className="btn-sm"
                onClick={onCopyTerminalProxy}
              >
                {t("native.copyTerminal")}
              </button>
            </div>
          )}
        {profile.subscription && (
          <div className="interface-row">
            <span className="row-label">{t("detail.autoRefresh")}</span>
            <span className="row-value">
              <select
                value={profile.subscription.refreshIntervalMinutes ?? ""}
                onChange={(event) =>
                  onSetRefreshInterval(
                    event.target.value ? Number(event.target.value) : null,
                  )
                }
                disabled={settingRefreshInterval || isBusy}
              >
                <option value="">{t("common.off")}</option>
                <option value="15">{t("detail.every15")}</option>
                <option value="60">{t("detail.everyHour")}</option>
                <option value="360">{t("detail.every6h")}</option>
              </select>
              {subscription?.updateIntervalHours &&
                subscription.refreshIntervalMinutes === null && (
                  <span className="row-hint">
                    {t("detail.providerInterval", {
                      hours: subscription.updateIntervalHours,
                    })}
                  </span>
                )}
            </span>
          </div>
        )}

        {(detailCount > 0 ||
          profile.subscription !== null ||
          (profile.backend === "xray" && profile.privateLanDirect) ||
          profile.useSystemProxy) && (
          <div className="connection-card-details">
            {subscription?.announce && (
              <div className="sub-announce">{subscription.announce}</div>
            )}
            {(subscription?.supportUrl || subscription?.webPageUrl) && (
              <div className="sub-links">
                {subscription?.webPageUrl && (
                  <button
                    type="button"
                    className="btn-sm"
                    onClick={() => openExternal(subscription.webPageUrl!)}
                  >
                    {t("detail.cabinet")}
                  </button>
                )}
                {subscription?.supportUrl && (
                  <button
                    type="button"
                    className="btn-sm"
                    onClick={() => openExternal(subscription.supportUrl!)}
                  >
                    {t("detail.support")}
                  </button>
                )}
              </div>
            )}
            {(profile.subscription?.providerTitle ?? endpointDisplay?.provider) && (
              <div className="interface-row">
                <span className="row-label">{t("detail.provider")}</span>
                <span className="row-value">
                  {profile.subscription?.providerTitle ?? endpointDisplay?.provider}
                </span>
              </div>
            )}
            {subscription?.userInfo && (
              <div className="interface-row">
                <span className="row-label">{t("detail.traffic")}</span>
                <span className="row-value">
                  {formatBytes(trafficUsed ?? 0)}
                  {" / "}
                  {subscription.userInfo.totalBytes !== null
                    ? formatBytes(subscription.userInfo.totalBytes)
                    : "∞"}
                  {limitExhausted && (
                    <span className="warn-text">
                      {" · "}
                      {t("detail.limitExhausted")}
                    </span>
                  )}
                </span>
              </div>
            )}
            {subscription?.userInfo?.expiresAtUnix != null && (
              <div className="interface-row">
                <span className="row-label">{t("detail.expires")}</span>
                <span className="row-value">
                  {new Date(
                    subscription.userInfo.expiresAtUnix * 1000,
                  ).toLocaleDateString()}
                  {expiresDaysLeft !== null && expiresDaysLeft <= 7 && (
                    <span className="warn-text">
                      {" · "}
                      {t("detail.expiresInDays", { count: Math.max(expiresDaysLeft, 0) })}
                    </span>
                  )}
                </span>
              </div>
            )}
            {subscription && subscription.skippedProtocols.length > 0 && (
              <div className="interface-row">
                <span className="row-label">{t("detail.unsupported")}</span>
                <span className="row-value">
                  {subscription.skippedProtocols
                    .map((p) => p[0].toUpperCase() + p.slice(1))
                    .join(", ")}
                </span>
              </div>
            )}
            {profile.subscription &&
              profile.subscription.lastRefreshAtUnix !== null && (
                <div className="interface-row">
                  <span className="row-label">{t("detail.lastChecked")}</span>
                  <span className="row-value">
                    {new Date(
                      profile.subscription.lastRefreshAtUnix * 1000,
                    ).toLocaleString()}
                  </span>
                </div>
              )}
            {profile.subscription?.lastRefreshError && (
              <div className="interface-row">
                <span className="row-label">{t("detail.refreshLabel")}</span>
                <span className="row-value">
                  {profile.subscription.lastRefreshError}
                </span>
              </div>
            )}
            {profile.backend === "xray" && profile.privateLanDirect && (
              <div className="interface-row">
                <span className="row-label">{t("detail.privateLan")}</span>
                <span className="row-value">{t("detail.privateLanValue")}</span>
              </div>
            )}
            {profile.useSystemProxy && (
              <div className="interface-row">
                <span className="row-label">{t("detail.proxyBypass")}</span>
                <span className="row-value mono">
                  {profile.proxyBypass.join("; ") || t("detail.bypassDefault")}
                </span>
              </div>
            )}
            {ruleCount > 0 && (
              <div className="interface-row">
                <span className="row-label">{t("detail.domainRules")}</span>
                <span className="row-value">
                  {(["block", "proxy", "direct"] as const)
                    .map((target) => ({
                      target,
                      count: countPolicyRules(
                        profile.domainPolicies,
                        target,
                      ),
                    }))
                    .filter((entry) => entry.count > 0)
                    .map(
                      (entry) =>
                        `${t(DOMAIN_TARGET_LABEL_KEYS[entry.target])} ${entry.count}`,
                    )
                    .join(" · ")}
                </span>
              </div>
            )}
            {profile.routes.length > 0 && (
              <div className="interface-section">
                <span className="section-label">{t("detail.routes")}</span>
                <ul className="profile-route-list">
                  {profile.routes.map((route, i) => (
                    <li key={i}>
                      <span className="mono">{route.destination}</span>
                      <span className="family-tag">{t("detail.metric", { n: route.metric })}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {os === "linux" && profile.backend === "xray" && (
          <LinuxXrayPolicySection
            profile={profile}
            status={status}
            endpoints={endpoints}
            busy={profileBusy || failoverBusy || switching || refreshingSubscription}
            onBusyChange={setPolicyBusy}
            onSaved={onPolicySaved}
          />
        )}

        {profile.subscription && endpoints && (
          <div className="endpoint-section">
            <div className="endpoint-section-head">
              <span className="section-label">
                {t("detail.endpoints")} · {liveEndpoints.length}
                {switching && <span className="endpoint-note">{t("detail.switching")}</span>}
              </span>
              <button
                type="button"
                className="btn-sm btn-with-icon"
                onClick={onMeasureAllEndpoints}
                disabled={
                  cancellingMeasurement ||
                  (!measuringAll && (switching || refreshingSubscription || isBusy))
                }
                title={measuringAll ? t("Cancel measurement") : t("detail.testAllTitle")}
              >
                {measuringAll && <SpinnerIcon size={12} />}
                {measuringAll
                  ? t("Cancel measurement")
                  : t("detail.testAll")}
              </button>
            </div>
            {multinode && failover && (
              <div className="endpoint-failover">
                {failover.activeKey === "unavailable"
                  ? t("All nodes are unavailable; traffic is blocked")
                  : failover.failoverActive
                    ? t("detail.onBackup", { name: endpointName(failover.activeKey) })
                    : t("detail.onPrimary", { name: endpointName(failover.activeKey) })}
                {failover.autoReturnPrimary &&
                  ` · ${t("detail.autoReturnArmed")}`}
              </div>
            )}
            <ul className="endpoint-list">
              {endpoints.map((ep, i) => {
                const active = !ep.isMissing && i === subscription?.activeIndex;
                const res = delayResults?.[i];
                const measuring = measuringEndpoints.has(`${profile.id}:${i}`);
                const order = backupOrder.get(ep.key);
                const live = failover?.nodes.find((n) => n.key === ep.key);
                return (
                  <li key={`${ep.key}:${i}`} className="endpoint-row">
                    <button
                      type="button"
                      className={`endpoint-item ${active ? "active" : ""}`}
                      onClick={() => onSwitchEndpoint(ep.key)}
                      disabled={
                        ep.isMissing ||
                        switching ||
                        refreshingSubscription ||
                        isBusy ||
                        active
                      }
                      title={
                        ep.isMissing
                          ? t("detail.missingEndpoint")
                          : active
                            ? t("detail.activeEndpoint")
                            : status.state === "running"
                              ? t("detail.switchEndpointReconnect")
                              : t("detail.switchEndpoint")
                      }
                    >
                      <span
                        className={`endpoint-item-dot ${active ? "on" : ""}`}
                      />
                      <span className="endpoint-item-name">
                        {endpointDisplay?.names[i] ?? ep.name}
                      </span>
                      {ep.isMissing && (
                        <span className="badge badge-external">{t("detail.missing")}</span>
                      )}
                      {multinode && ep.isBackup && !ep.isMissing && (
                        <span className="endpoint-proto">
                          {t("detail.backupN", { n: (order ?? 0) + 1 })}
                        </span>
                      )}
                      {multinode && ep.inPool && (
                        <span className="endpoint-proto">{t("Backup pool")}</span>
                      )}
                      {ep.protocol && (
                        <span className="endpoint-proto">{ep.protocol}</span>
                      )}
                      <span
                        className={`endpoint-item-delay ${delayClass(res, measuring)}`}
                        aria-busy={measuring || undefined}
                      >
                        {measuring ? (
                          <SpinnerIcon size={12} />
                        ) : res ? (
                          res.delayMs !== null ? (
                            t("detail.delayMs", { ms: res.delayMs })
                          ) : (
                            t("detail.unreachable")
                          )
                        ) : ep.isMissing ? (
                          t("detail.unreachable")
                        ) : live?.healthy === false ? (
                          t("detail.nodeDown")
                        ) : live?.latencyMs != null ? (
                          t("detail.delayMs", { ms: live.latencyMs })
                        ) : (
                          "—"
                        )}
                      </span>
                    </button>
                    {multinode && !ep.active && (
                      <span className="endpoint-actions">
                        {order !== undefined && order > 0 && (
                          <button
                            type="button"
                            className="btn-ghost icon-btn"
                            onClick={() => moveBackup(ep.key, -1)}
                            disabled={failoverBusy || isBusy}
                            title={t("detail.backupSooner")}
                          >
                            <ArrowUpIcon size={12} />
                          </button>
                        )}
                        {order !== undefined &&
                          order < backupRefs.length - 1 && (
                            <button
                              type="button"
                              className="btn-ghost icon-btn"
                              onClick={() => moveBackup(ep.key, 1)}
                              disabled={failoverBusy || isBusy}
                              title={t("detail.backupLater")}
                            >
                              <ArrowDownIcon size={12} />
                            </button>
                          )}
                        <button
                          type="button"
                          className="btn-ghost icon-btn"
                          onClick={() =>
                            setBackupMembership(ep.key, order === undefined)
                          }
                          disabled={failoverBusy || isBusy}
                          title={
                            order === undefined
                              ? t("detail.addBackup")
                              : t("detail.removeBackup")
                          }
                        >
                          {order === undefined ? (
                            <PlusIcon size={12} />
                          ) : (
                            <CloseIcon size={12} />
                          )}
                        </button>
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
            {multinode && (backupRefs.length > 0 ||
              (subscription?.poolKeys?.length ?? 0) > 0) && (
              <div className="interface-row">
                <span className="row-label">{t("detail.autoReturn")}</span>
                <span className="row-value">
                  <ToggleSwitch
                    checked={subscription?.autoReturnPrimary ?? true}
                    onChange={() =>
                      onSetAutoReturn(!(subscription?.autoReturnPrimary ?? true))
                    }
                    disabled={failoverBusy || isBusy}
                    title={t("detail.autoReturnTitle")}
                  />
                  <span className="row-hint">{t("detail.autoReturnHint")}</span>
                </span>
              </div>
            )}
            {multinode && applyOnReconnect && (
              <div className="runtime-notice">{t("detail.applyOnReconnect")}</div>
            )}
            {multinode && (
              <div className="pinned-section">
                <span className="section-label">{t("detail.pinnedRoutes")}</span>
                {pinnedRoutes.length === 0 && (
                  <span className="row-hint">{t("detail.pinnedEmpty")}</span>
                )}
                <ul className="pinned-list">
                  {pinnedRoutes.map((route) => (
                    <li key={route.endpointKey}>
                      <span className="pinned-node">
                        {endpointName(route.endpointKey)}
                        {route.missing && (
                          <span className="badge badge-external">
                            {t("detail.missing")}
                          </span>
                        )}
                      </span>
                      <span className="pinned-selectors mono">
                        {route.selectors.join(", ")}
                      </span>
                      <button
                        type="button"
                        className="btn-ghost icon-btn"
                        onClick={() => removePinnedRoute(route.endpointKey)}
                        disabled={failoverBusy || isBusy}
                        title={t("detail.unpinTitle")}
                      >
                        <CloseIcon size={12} />
                      </button>
                    </li>
                  ))}
                </ul>
                <div className="pinned-add">
                  <select
                    aria-label={t("detail.pinVia")}
                    value={pinVia}
                    onChange={(e) => setPinVia(e.target.value)}
                    disabled={failoverBusy || isBusy}
                  >
                    <option value="">{t("detail.pinVia")}</option>
                    {liveEndpoints
                      .filter((e) => !e.active)
                      .map((e, i) => (
                        <option key={e.key} value={e.key}>
                          {endpointDisplay?.names[endpoints.indexOf(e)] ?? (e.name || `#${i + 1}`)}
                        </option>
                      ))}
                  </select>
                  <input
                    type="text"
                    value={pinSelectors}
                    onChange={(e) => setPinSelectors(e.target.value)}
                    placeholder={t("detail.pinSelectorsPlaceholder")}
                    disabled={failoverBusy || isBusy}
                  />
                  <button
                    type="button"
                    className="btn-sm btn-with-icon"
                    onClick={addPinnedRoute}
                    disabled={failoverBusy || isBusy || !pinVia || !pinSelectors.trim()}
                  >
                    <PlusIcon size={12} />
                    {t("detail.pinAdd")}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
