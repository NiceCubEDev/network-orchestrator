import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useT, type TranslationKey } from "../../i18n";
import { SpinnerIcon } from "../../icons";
import type { Profile, ServiceCheck, ServiceCheckResult, SubscriptionEndpointInfo, TunnelStatus } from "../../types";
import { useToast } from "../ui/Toast";

interface Props {
  profile: Profile;
  status: TunnelStatus;
  endpoints: SubscriptionEndpointInfo[] | undefined;
  busy: boolean;
  onBusyChange: (busy: boolean) => void;
  onSaved: (profileId: string, profiles: Profile[]) => Promise<void>;
}

const EMPTY_CHECKS: ServiceCheck[] = [];
const OUTCOME_KEYS: Record<ServiceCheckResult["outcome"], TranslationKey> = {
  http: "HTTP response received",
  timeout: "Service check timed out",
  tlsError: "Service check TLS failure",
  transportError: "Service check transport failure",
  unavailable: "Service check unavailable",
};

function validDraft(draft: ServiceCheck): boolean {
  if (!draft.name.trim() || [...draft.name].length > 80 || /\p{Cc}/u.test(draft.name)
    || new TextEncoder().encode(draft.url).length > 2048 || /[\s\\]/u.test(draft.url)) return false;
  try {
    const url = new URL(draft.url);
    const authority = draft.url.split("://")[1]?.split(/[/?#]/u)[0];
    return url.protocol === "https:" && Boolean(url.hostname) && Boolean(authority)
      && !authority.includes("@") && !draft.url.includes("#") && url.port !== "0"
      && !url.username && !url.password && /^[0-9a-f]{16}$/u.test(draft.endpointKey);
  } catch {
    return false;
  }
}

export default function ServiceChecksSection({ profile, status, endpoints, busy, onBusyChange, onSaved }: Props) {
  const t = useT();
  const toast = useToast();
  const checks = profile.xrayServiceChecks ?? EMPTY_CHECKS;
  const signature = JSON.stringify(checks);
  const [draft, setDraft] = useState<ServiceCheck | null>(null);
  const [operation, setOperation] = useState<"save" | "check" | "refresh" | null>(null);
  const [manual, setManual] = useState<ServiceCheckResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState(0);
  const generation = useRef(0);
  const blocked = busy || operation !== null;
  const boundKeys = [...new Set([
    ...(profile.pinnedPolicies ?? []).filter((pin) => pin.selectors.length > 0).map((pin) => pin.endpointKey),
    profile.xrayDns?.outboundKey,
  ].filter((key): key is string => Boolean(key)))];
  const activeTun = profile.xrayMode === "tun" && status.state === "running";

  useEffect(() => {
    generation.current++;
    setManual([]);
    setDraft(null);
    setError(null);
  }, [profile.id, signature]);

  const available = (check: ServiceCheck) => boundKeys.includes(check.endpointKey)
    && (endpoints === undefined || endpoints.some((endpoint) => endpoint.key === check.endpointKey && !endpoint.isMissing));
  const nodeName = (key: string) => endpoints?.find((endpoint) => endpoint.key === key)?.name ?? key;

  const renderResult = (result: ServiceCheckResult) => (
    <span className={result.degraded ? "warn-text" : ""}>
      {t(OUTCOME_KEYS[result.outcome])}
      {result.httpStatus !== null && ` · ${t("HTTP {status}", { status: result.httpStatus })}`}
      {result.latencyMs !== null && ` · ${t("detail.delayMs", { ms: result.latencyMs })}`}
      {result.consecutiveFailures > 0 && ` · ${t("{count} consecutive failures", { count: result.consecutiveFailures })}`}
      {result.degraded && ` · ${t("Service degraded")}`}
      {` · ${new Date(result.checkedAtUnix * 1000).toLocaleTimeString()}`}
    </span>
  );

  const save = async (next: ServiceCheck[]) => {
    if (blocked) return;
    setOperation("save");
    onBusyChange(true);
    setError(null);
    try {
      const updated = await invoke<Profile[]>("set_xray_service_checks", { profileId: profile.id, checks: next });
      setSavedAt(Math.floor(Date.now() / 1000));
      setDraft(null);
      setManual([]);
      try {
        await onSaved(profile.id, updated);
        toast("success", t("Service checks saved without probing."));
      } catch {
        setError(t("Checks were saved, but refreshing the display failed. Refresh before editing again."));
      }
    } catch {
      setError(t("Could not save service checks. The daemon must confirm background changes."));
    } finally {
      setOperation(null);
      onBusyChange(false);
    }
  };

  const run = async (ids: string[] | null) => {
    if (blocked) return;
    const current = generation.current;
    setOperation("check");
    onBusyChange(true);
    setError(null);
    try {
      const results = await invoke<ServiceCheckResult[]>("run_xray_service_checks", { profileId: profile.id, checkIds: ids });
      if (generation.current === current) {
        setManual((previous) => [...previous.filter((old) => !results.some((result) => result.id === old.id)), ...results]);
      }
    } catch {
      if (generation.current === current) setError(t("Service checks could not be completed. Refresh and try again."));
    } finally {
      setOperation(null);
      onBusyChange(false);
    }
  };

  const refresh = async () => {
    if (blocked) return;
    setOperation("refresh");
    onBusyChange(true);
    try {
      await onSaved(profile.id, await invoke<Profile[]>("get_profiles"));
      setError(null);
    } catch {
      setError(t("Service checks could not be completed. Refresh and try again."));
    } finally {
      setOperation(null);
      onBusyChange(false);
    }
  };

  return (
    <section className="interface-section" aria-label={t("Service availability")}>
      <span className="section-label">{t("Service availability")}</span>
      <span className="row-hint">{t("Only user-supplied HTTPS HEAD checks through explicit pins. No credentials, cookies, redirects or response bodies. Never use URLs containing secrets or webhook endpoints. Failures do not change nodes, routes or restart the tunnel.")}</span>
      <span className="row-hint">{t("Background is off by default: every 60 seconds while this TUN connection is active, starting one minute after enabling. Three consecutive network failures mark degradation. Any HTTP response resets the streak; it does not prove authenticated API success.")}</span>
      <div className="pinned-add">
        <button type="button" className="btn-sm" disabled={blocked || draft !== null || checks.length >= 16 || boundKeys.length === 0}
          onClick={() => setDraft({ id: crypto.randomUUID(), name: "", url: "", endpointKey: "", background: false })}>
          {t("Add service check")}
        </button>
        <button type="button" className="btn-sm" disabled={blocked || draft !== null || checks.length === 0} onClick={() => void run(null)}>
          {t("Check saved services")}
        </button>
      </div>
      {boundKeys.length === 0 && <span className="row-hint">{t("Pin a subscription node in domain or DNS policy before adding a service check.")}</span>}
      {checks.length === 0 && <span className="row-hint">{t("No service checks configured. No service requests are sent.")}</span>}
      {checks.map((check) => {
        const lastManual = manual.find((result) => result.id === check.id && result.endpointKey === check.endpointKey);
        const background = status.watchdog?.serviceChecks?.find((result) => result.id === check.id
          && result.endpointKey === check.endpointKey && result.checkedAtUnix >= savedAt);
        return (
          <div className="interface-section" key={check.id}>
            <div className="interface-row"><span className="service-check-name">{check.name}</span><span className="row-value">{nodeName(check.endpointKey)}</span></div>
            {!available(check) ? <span className="row-hint">{t("Service check unavailable")}</span> : (
              <>
                <div className="interface-row"><span className="row-label">{t("Manual check")}</span><span className="row-value num">{lastManual ? renderResult(lastManual) : t("Not checked")}</span></div>
                {check.background && <div className="interface-row"><span className="row-label">{t("Background check")}</span><span className="row-value num">{
                  !activeTun ? t("Inactive outside a running TUN connection") : background ? renderResult(background) : t("Waiting for the next background check")
                }</span></div>}
              </>
            )}
            {!check.background && <span className="row-hint">{t("Background checks off")}</span>}
            <div className="pinned-add">
              <button type="button" className="btn-sm" disabled={blocked || draft !== null} onClick={() => void run([check.id])}>{t("Check now")}</button>
              <button type="button" className="btn-sm" disabled={blocked || draft !== null} onClick={() => setDraft({ ...check })}>{t("common.edit")}</button>
              <button type="button" className="btn-ghost btn-sm" disabled={blocked || draft !== null} onClick={() => void save(checks.filter((item) => item.id !== check.id))}>{t("common.remove")}</button>
            </div>
          </div>
        );
      })}
      {draft && <form className="profile-tun-fields" onSubmit={(event) => {
        event.preventDefault();
        if (!validDraft(draft)) {
          setError(t("Use a name of 1–80 characters, an HTTPS URL of at most 2048 bytes without credentials or fragments, and an explicit pinned node."));
          return;
        }
        const exists = checks.some((check) => check.id === draft.id);
        void save(exists ? checks.map((check) => check.id === draft.id ? draft : check) : [...checks, draft]);
      }}>
        <label className="pinned-add"><span className="row-label">{t("Service check name")}</span><input required type="text" value={draft.name} disabled={blocked} autoComplete="off" onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label>
        <label className="pinned-add"><span className="row-label">{t("HTTPS check URL")}</span><input required type="url" value={draft.url} disabled={blocked} autoComplete="off" spellCheck={false} onChange={(event) => setDraft({ ...draft, url: event.target.value })} /></label>
        <label className="pinned-add"><span className="row-label">{t("Pinned node")}</span><select required value={draft.endpointKey} disabled={blocked} onChange={(event) => setDraft({ ...draft, endpointKey: event.target.value })}>
          <option value="" disabled>{t("Choose a pinned node")}</option>
          {draft.endpointKey && !boundKeys.includes(draft.endpointKey) && <option value={draft.endpointKey} disabled>{t("Service check unavailable")}</option>}
          {boundKeys.map((key) => <option key={key} value={key}>{nodeName(key)}</option>)}
        </select></label>
        <label className="profile-proxy-toggle"><input type="checkbox" checked={draft.background} disabled={blocked} onChange={(event) => setDraft({ ...draft, background: event.target.checked })} />{t("Enable background service checks")}</label>
        <div className="pinned-add"><button type="submit" className="btn-sm" disabled={blocked}>{t("common.save")}</button><button type="button" className="btn-sm" disabled={blocked} onClick={() => { setDraft(null); setError(null); }}>{t("common.cancel")}</button></div>
      </form>}
      {operation && <div className="runtime-notice" role="status"><SpinnerIcon />{t(operation === "check" ? "Checking saved services" : "Updating service checks")}</div>}
      {error && <div className="save-notice" role="alert">{error}<button type="button" className="btn-sm" disabled={blocked} onClick={() => void refresh()}>{t("common.refresh")}</button></div>}
    </section>
  );
}
