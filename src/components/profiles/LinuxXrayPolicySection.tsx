import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { SpinnerIcon } from "../../icons";
import { useT, type TranslationKey } from "../../i18n";
import type {
  NodePoolReport,
  NodePoolSettings,
  PoolProbeEntry,
  Profile,
  SubscriptionEndpointInfo,
  SubscriptionExitCheck,
  TunnelStatus,
  XrayPolicyPreview,
} from "../../types";
import Modal from "../Modal";
import { useToast } from "../ui/Toast";
import ServiceChecksSection from "./ServiceChecksSection";

interface Props {
  profile: Profile;
  status: TunnelStatus;
  endpoints: SubscriptionEndpointInfo[] | undefined;
  busy: boolean;
  onBusyChange: (busy: boolean) => void;
  onSaved: (profileId: string, profiles: Profile[]) => Promise<void>;
}

type Draft = { country: string; names: string };
type Operation = "save" | "clear" | "rebuild" | "verify" | "preview" | "apply";

const VERDICT_KEYS: Record<PoolProbeEntry["verdict"], TranslationKey> = {
  member: "pool member",
  explicit: "explicit choice",
  unreachable: "Could not verify",
  wrongCountry: "wrong exit country",
  skipped: "Not selected: pool or probe limit",
};

const ANOMALY_KEYS: Record<string, TranslationKey> = {
  "uplink-offline": "No physical default route is available.",
  "egress-observation-unavailable": "Physical uplink observation is unavailable.",
  "https-stalled": "HTTPS through the tunnel has stalled.",
  "dns-stalled": "DNS through the tunnel has stalled.",
  "udp-socket-limit": "The owned Xray process exceeded its UDP socket limit.",
  "connection-storm": "An application is opening an unusual number of connections.",
  "socket-observation-unavailable": "The owned process socket inventory is unavailable.",
  "watchdog-unavailable": "Recovery diagnostics are unavailable.",
};

export default function LinuxXrayPolicySection({
  profile, status, endpoints, busy, onBusyChange, onSaved,
}: Props) {
  const t = useT();
  const toast = useToast();
  const savedPool = profile.subscription?.nodePool ?? null;
  const [operation, setOperation] = useState<Operation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reconnect, setReconnect] = useState(false);
  const [editing, setEditing] = useState(false);
  const [enabled, setEnabled] = useState(savedPool !== null);
  const [verifyCountry, setVerifyCountry] = useState(
    savedPool?.verifyExitCountry ?? true,
  );
  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [report, setReport] = useState<NodePoolReport | null>(null);
  const [checks, setChecks] = useState<SubscriptionExitCheck[] | null>(null);
  const [migration, setMigration] = useState<{
    path: string;
    preview: XrayPolicyPreview;
  } | null>(null);
  const [serviceBusy, setServiceBusy] = useState(false);
  const blocked = busy || operation !== null || serviceBusy;
  const stopped = status.state === "stopped";
  const watchdog = status.watchdog;
  useEffect(() => { if (status.state === "stopped") setReconnect(false); }, [status.state]);

  const nameOf = (key: string) =>
    endpoints?.find((endpoint) => endpoint.key === key)?.name ??
    [
      ...(profile.subscription?.backupKeys ?? []),
      ...(profile.subscription?.poolKeys ?? []),
    ].find((reference) => reference.key === key)?.name ??
    key;

  const row = (label: TranslationKey, value: ReactNode) => (
    <div className="interface-row" key={label}>
      <span className="row-label">{t(label)}</span>
      <span className="row-value num">{value}</span>
    </div>
  );
  const unknown = t("Not reported");
  const date = (value: number | null | undefined) =>
    value == null ? unknown : new Date(value * 1000).toLocaleString();

  const run = async (next: Operation, work: () => Promise<void>) => {
    if (blocked) return;
    setOperation(next);
    onBusyChange(true);
    setError(null);
    try {
      await work();
    } catch (failure) {
      setError(String(failure));
    } finally {
      setOperation(null);
      onBusyChange(false);
    }
  };

  const publish = async (updated: Profile[]) => {
    try {
      await onSaved(profile.id, updated);
    } catch {
      // The native save already succeeded. Do not describe this as a failed save.
      throw new Error(t("The change was saved, but refreshing the displayed profile or endpoints failed. Refresh the profile before making another change."));
    }
  };

  const beginEdit = () => {
    setEnabled(savedPool !== null);
    setVerifyCountry(savedPool?.verifyExitCountry ?? true);
    setDrafts(savedPool?.filters.map((filter) => ({
      country: savedPool?.verifyExitCountry ? filter.exitCountry ?? "" : "",
      names: filter.nameContains.join(" | "),
    })) ?? [{ country: "", names: "" }]);
    setError(null);
    setEditing(true);
  };

  const save = () => run("save", async () => {
    let pool: NodePoolSettings | null = null;
    if (enabled) {
      const filters = drafts.map((draft) => ({
        nameContains: draft.names.split("|").map((word) => word.trim()).filter(Boolean),
        exitCountry: draft.country.trim().toUpperCase() || null,
      }));
      const invalid = filters.length === 0 || filters.length > 8 ||
        filters.some((filter) =>
          filter.nameContains.length > 4 ||
          filter.nameContains.some((word) => [...word].length > 64) ||
          (verifyCountry
            ? !/^[A-Z]{2}$/.test(filter.exitCountry ?? "")
            : filter.exitCountry !== null || filter.nameContains.length === 0)
        );
      if (invalid) throw new Error(t("Use 1–8 filters, at most 4 name terms of 1–64 characters each. Every verified filter needs a two-letter country. Every unverified filter needs names and no country."));
      pool = { filters, verifyExitCountry: verifyCountry };
    }
    const updated = await invoke<Profile[]>("set_subscription_node_pool", {
      profileId: profile.id, pool,
    });
    setEditing(false);
    setReport(null);
    setChecks(null);
    setReconnect(status.state === "running");
    await publish(updated);
    toast("success", t("Pool settings saved"));
  });

  const clear = () => run("clear", async () => {
    const updated = await invoke<Profile[]>("set_subscription_node_pool", {
      profileId: profile.id, pool: null,
    });
    setEditing(false);
    setEnabled(false);
    setReport(null);
    setChecks(null);
    setReconnect(status.state === "running");
    await publish(updated);
    toast("success", t("Pool disabled; explicit backups and pins are unchanged"));
  });

  const rebuild = () => run("rebuild", async () => {
    setReport(null);
    setChecks(null);
    const result = await invoke<NodePoolReport>("rebuild_subscription_node_pool", {
      profileId: profile.id,
    });
    setReport(result);
    if (result.poolChanged) setReconnect(status.state === "running");
    await publish(await invoke<Profile[]>("get_profiles"));
  });

  const verify = () => run("verify", async () => {
    setChecks(null);
    setChecks(await invoke<SubscriptionExitCheck[]>(
      "verify_subscription_exits", { profileId: profile.id },
    ));
  });

  const choose = () => run("preview", async () => {
    if (!stopped) throw new Error(t("Disconnect this profile before previewing or applying policy."));
    setMigration(null);
    const path = await openDialog({
      multiple: false,
      directory: false,
      filters: [{ name: t("Xray JSON configuration"), extensions: ["json"] }],
    });
    if (typeof path !== "string") return;
    const preview = await invoke<XrayPolicyPreview>(
      "preview_xray_policy_migration", { profileId: profile.id, path },
    );
    setMigration({ path, preview });
  });

  const apply = () => run("apply", async () => {
    if (!stopped) throw new Error(t("Disconnect this profile before previewing or applying policy."));
    if (!migration || migration.preview.refused.length > 0) return;
    const updated = await invoke<Profile[]>("apply_xray_policy_migration", {
      profileId: profile.id, path: migration.path,
    });
    setMigration(null);
    setReport(null);
    setChecks(null);
    await publish(updated);
    toast("success", t("Xray policy applied"));
  });

  const preview = migration?.preview;

  return (
    <div className="interface-section">
      {profile.subscription && (
        <>
          <span className="section-label">{t("Backup pool")}</span>
          <div className="runtime-notice">{t("Rebuild and exit verification start temporary local Xray processes and contact external country services through each candidate. No host routes are changed. Enabled pools are also rebuilt after subscription refresh. Server names are not country proof.")}</div>
          {row("Pool", savedPool
            ? t("{count} saved members", {
                count: profile.subscription.poolKeys?.length ?? 0,
              })
            : t("common.off"))}
          {savedPool && (
            <>
              <span className="row-hint">
                {t(savedPool.verifyExitCountry
                  ? "Members require real exit-country verification." : "Name matching only; exit country is not verified.")}
              </span>
              <ul className="profile-route-list">
                {savedPool.filters.map((filter, index) => (
                  <li key={index}>
                    <span>{filter.exitCountry ?? t("No country constraint")} · </span>
                    <span>{filter.nameContains.join(" | ") || t("Any name")}</span>
                  </li>
                ))}
              </ul>
              <ul className="profile-route-list">
                {(profile.subscription.poolKeys ?? []).map((member) => (
                  <li key={member.key}>
                    <span>{nameOf(member.key)} · </span>
                    <span>{t("pool member")}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
          <div className="pinned-add">
            <button type="button" className="btn-sm"
              disabled={blocked} onClick={beginEdit}>
              {t("Configure pool")}
            </button>
            <button type="button" className="btn-sm"
              disabled={blocked || (!savedPool &&
                !(profile.subscription.poolKeys?.length))}
              onClick={() => void clear()}>
              {t("common.clear")}
            </button>
          </div>
          <div className="pinned-add">
            <button type="button" className="btn-sm"
              disabled={blocked || !savedPool} onClick={() => void rebuild()}>
              {t("Rebuild pool")}
            </button>
            <button type="button" className="btn-sm"
              disabled={blocked} onClick={() => void verify()}>
              {t("Verify exit countries")}
            </button>
          </div>

          {editing && (
            <div className="profile-tun-fields">
              <label className="profile-proxy-toggle">
                <input type="checkbox" checked={enabled} disabled={blocked}
                  onChange={(event) => setEnabled(event.target.checked)} />
                {t("Enable the filtered backup pool")}
              </label>
              {enabled && (
                <>
                  <label className="profile-proxy-toggle">
                    <input type="checkbox" checked={verifyCountry} disabled={blocked}
                      onChange={(event) => {
                        const next = event.target.checked;
                        setVerifyCountry(next);
                        if (!next) setDrafts((current) =>
                          current.map((draft) => ({ ...draft, country: "" })));
                      }} />
                    {t("Require verified exit country")}
                  </label>
                  <span className="row-hint">{t("Up to 8 filters and 4 name terms per filter, separated by |. Verified filters each need a two-letter country; names may be empty. Unverified filters each need names and cannot specify a country.")}</span>
                  {drafts.map((draft, index) => (
                    <div className="interface-section" key={index}>
                      {verifyCountry && (
                        <label className="pinned-add">
                          <span className="row-label">{t("Exit country")}</span>
                          <input type="text" maxLength={2}
                            value={draft.country} disabled={blocked}
                            onChange={(event) => setDrafts((current) =>
                              current.map((item, n) => n === index
                                ? { ...item, country: event.target.value.toUpperCase() }
                                : item))} />
                        </label>
                      )}
                      <label className="pinned-add">
                        <span className="row-label">{t("Name terms")}</span>
                        <input type="text" value={draft.names} disabled={blocked}
                          onChange={(event) => setDrafts((current) =>
                            current.map((item, n) => n === index
                              ? { ...item, names: event.target.value } : item))} />
                      </label>
                      <button type="button" className="btn-ghost btn-sm"
                        disabled={blocked}
                        onClick={() => setDrafts((current) =>
                          current.filter((_, n) => n !== index))}>
                        {t("common.remove")}
                      </button>
                    </div>
                  ))}
                  <button type="button" className="btn-sm"
                    disabled={blocked || drafts.length >= 8}
                    onClick={() => setDrafts((current) =>
                      [...current, { country: "", names: "" }])}>
                    {t("Add filter")}
                  </button>
                </>
              )}
              <div className="pinned-add">
                <button type="button" className="btn-sm"
                  disabled={blocked} onClick={() => void save()}>
                  {t("common.save")}
                </button>
                <button type="button" className="btn-sm"
                  disabled={blocked} onClick={() => setEditing(false)}>
                  {t("common.cancel")}
                </button>
              </div>
            </div>
          )}

          {report && (
            <>
              <div className="runtime-notice">
                {t(report.keptPrevious ? "No usable replacements were found; the previous pool was kept."
                  : report.poolChanged ? "Pool rebuilt"
                  : "Pool membership unchanged")}
              </div>
              <ul className="profile-route-list">
                {report.entries.slice(0, 32).map((entry, index) => (
                  <li key={`${entry.key}:${index}`}>
                    <span>{nameOf(entry.key)} · </span>
                    <span className="num">
                      {t(VERDICT_KEYS[entry.verdict])}
                      {entry.exitCountry ? ` · ${entry.exitCountry}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
              {report.entries.length > 32 && (
                <span className="row-hint">
                  {t("Showing 32 of {count} candidate results.", { count: report.entries.length })}
                </span>
              )}
            </>
          )}
          {checks && (
            <>
              <span className="section-label">{t("Verify exit countries")}</span>
              {checks.length === 0 && (
                <div className="runtime-notice">{t("No verification results were returned.")}</div>
              )}
              <ul className="profile-route-list">
                {checks.map((check) => (
                  <li key={check.key}>
                    <span>{nameOf(check.key)} · </span>
                    <span className={check.mismatch ? "warn-text" : ""}>
                      {check.error ?? check.exitCountry ?? unknown}
                      {check.mismatch && ` · ${t("Name claims {named}; actual exit differs", {
                        named: check.namedCountry ?? unknown,
                      })}`}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      )}
      {profile.subscription && (
        <ServiceChecksSection profile={profile} status={status} endpoints={endpoints}
          busy={busy || operation !== null} onSaved={onSaved}
          onBusyChange={(next) => { setServiceBusy(next); onBusyChange(next); }} />
      )}

      <span className="section-label">{t("Import local Xray policy")}</span>
      <span className="row-hint">{t("Choose a local Xray JSON file. Preview reads it without changing the source or starting a tunnel. Unsupported semantics block apply. No raw config or credentials are displayed.")}</span>
      {!stopped && (
        <span className="row-hint">{t("Disconnect this profile before previewing or applying policy.")}</span>
      )}
      <button type="button" className="btn-sm"
        disabled={blocked || !stopped} onClick={() => void choose()}>
        {t("Choose file and preview")}
      </button>

      {(watchdog || (profile.xrayMode === "tun" && status.state === "running")) && (
        <div className="interface-section">
          <span className="section-label">{t("Recovery diagnostics")}</span>
          {!watchdog ? (
            <span className="row-hint">{t("The core has not provided recovery diagnostics.")}</span>
          ) : (
            <>
              {row("Physical uplink", watchdog.uplink == null ? unknown
                : t(watchdog.uplink ? "Route available" : "No physical route"))}
              {row("HTTPS latency", watchdog.httpsLatencyMs == null ? unknown
                : t("detail.delayMs", { ms: watchdog.httpsLatencyMs }))}
              {row("Consecutive stalls", t("HTTPS {https} · DNS {dns}", {
                https: watchdog.httpsStallStreak, dns: watchdog.dnsStallStreak,
              }))}
              {row("Xray UDP sockets", watchdog.anomalies.includes("socket-observation-unavailable")
                ? unknown : watchdog.xrayUdpSockets)}
              {row("Last recovery", date(watchdog.lastRecoveryUnix))}
              {watchdog.connStorm && (
                <div className="runtime-notice">
                  {t("{count} connections to {destination} · process {process}", {
                    count: watchdog.connStorm.count,
                    destination: watchdog.connStorm.destination,
                    process: watchdog.connStorm.process ?? unknown,
                  })}
                </div>
              )}
              {watchdog.anomalies.slice(0, 8).map((notice, index) => (
                <div className="runtime-notice" key={index}>
                  {t(ANOMALY_KEYS[notice] ?? "Recovery diagnostics reported an unrecognized condition.")}
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {operation && (
        <div className="runtime-notice" role="status">
          <SpinnerIcon size={12} /> {t("Working…")}
        </div>
      )}
      {reconnect && !stopped && (
        <div className="runtime-notice">{t("detail.applyOnReconnect")}</div>
      )}
      {error && !migration && (
        <div className="save-notice" role="alert">{error}</div>
      )}

      {migration && preview && createPortal(
        <Modal open={true} title={t("Import local Xray policy")}
          onClose={() => { if (!blocked) setMigration(null); }}
          footer={
            <>
              <button type="button" disabled={blocked}
                onClick={() => setMigration(null)}>{t("common.cancel")}</button>
              <button type="button" className="btn-primary"
                disabled={blocked || !stopped || preview.refused.length > 0}
                onClick={() => void apply()}>
                {operation === "apply" && <SpinnerIcon size={12} />}
                {t("Apply policy")}
              </button>
            </>
          }>
          {row("Selectors", t("{direct} direct · {proxy} proxy · {block} blocked · {pinned} pins", {
            direct: preview.direct, proxy: preview.proxy, block: preview.block,
            pinned: preview.pinnedCount,
          }))}
          {row("Interface-bound routes", preview.interfaceRouteCount ?? unknown)}
          {row("IP/port guards", preview.trafficRuleCount ?? unknown)}
          {row("DNS policy", t("{servers} resolvers · {hosts} hosts · {rewrites} rewrites · {tun} TUN resolvers", {
            servers: preview.dnsServerCount ?? unknown,
            hosts: preview.dnsHostCount ?? unknown,
            rewrites: preview.dnsRewriteRuleCount ?? unknown,
            tun: preview.tunDnsServerCount ?? unknown,
          }))}
          {row("DNS outbound policy", t(preview.hasDnsOutbound ? "Yes" : "No"))}
          {row("Parallel DNS queries", preview.dnsEnableParallelQuery == null
            ? t("Default") : t(preview.dnsEnableParallelQuery ? "Yes" : "No"))}
          {row("TUN MTU", preview.tunMtu ?? t("Default"))}
          {row("Connection idle timeout", preview.connectionIdleSecs == null
            ? t("Default")
            : t("{count} s", { count: preview.connectionIdleSecs }))}
          {row("Imported backups", preview.backupCount ?? t("Unchanged"))}
          {row("Endpoint bypasses", preview.endpointBypassCount)}
          {row("Custom GeoIP data", t(preview.hasGeoipOverride ? "Yes" : "No"))}
          {row("Custom GeoSite data", t(preview.hasGeositeOverride ? "Yes" : "No"))}
          {row("Socket policy", t(preview.hasSockopts ? "Yes" : "No"))}
          {row("QUIC rejection", t(preview.quicReject ? "Yes" : "No"))}
          {row("Private LAN direct", t(preview.privateLanDirect ? "Yes" : "No"))}
          {row("Routing domain strategy", preview.domainStrategy ?? t("Default"))}
          {row("Domain matcher", preview.domainMatcher ?? t("Default"))}
          {row("Direct outbound strategy", preview.directDomainStrategy ?? t("Default"))}
          <p className="row-hint">{t("Review all mapped settings and exclusions. Apply reparses and validates the chosen file. Unsupported or conflicting explicit choices must be resolved before applying.")}</p>
          {preview.skipped.map((item, index) => (
            <div className="runtime-notice" key={`skip:${index}`}>
              {t("Excluded")}: {item}
            </div>
          ))}
          {preview.refused.map((item, index) => (
            <div className="save-notice" key={`refuse:${index}`}>
              {t("Cannot import")}: {item}
            </div>
          ))}
          {!stopped && (
            <div className="runtime-notice">{t("Disconnect this profile before previewing or applying policy.")}</div>
          )}
          {error && <div className="save-notice" role="alert">{error}</div>}
        </Modal>,
        document.body,
      )}
    </div>
  );
}
