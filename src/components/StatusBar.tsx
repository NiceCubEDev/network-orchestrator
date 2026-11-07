import { useCallback, useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { TranslationKey, useT } from "../i18n";
import type {
  BackendAvailability,
  DaemonStatus,
  NetworkInterface,
  Profile,
  SystemProxyStatus,
  TunnelStatus,
} from "../types";

const DAEMON_STATE_UI: Record<
  DaemonStatus["state"],
  { dot: string; key: TranslationKey }
> = {
  ready: { dot: "state-running", key: "statusbar.state.ready" },
  notRequired: { dot: "state-unknown", key: "statusbar.state.inProcess" },
  notInstalled: { dot: "state-unknown", key: "statusbar.state.absent" },
  notRunning: { dot: "state-stopped", key: "statusbar.state.stopped" },
  incompatible: { dot: "state-failed", key: "statusbar.state.incompatible" },
  error: { dot: "state-failed", key: "statusbar.state.error" },
};

interface StatusBarProps {
  activeCount: number;
}

export default function StatusBar({ activeCount }: StatusBarProps) {
  const t = useT();
  const [daemon, setDaemon] = useState<DaemonStatus | null>(null);
  const [backends, setBackends] = useState<BackendAvailability[]>([]);
  const [proxy, setProxy] = useState<SystemProxyStatus | null>(null);
  const [primaryIface, setPrimaryIface] = useState<string | null>(null);
  const [activeName, setActiveName] = useState<string | null>(null);

  const poll = useCallback(async () => {
    if (!isTauri()) return;
    const safe = <T,>(p: Promise<T>) => p.catch(() => null);
    const [daemonStatus, availability, proxyStatus, ifaces, profileList, statusList] =
      await Promise.all([
        safe(invoke<DaemonStatus>("daemon_status")),
        safe(invoke<BackendAvailability[]>("get_backend_availability")),
        safe(invoke<SystemProxyStatus>("system_proxy_status")),
        safe(invoke<NetworkInterface[]>("get_interfaces")),
        safe(invoke<Profile[]>("get_profiles")),
        safe(invoke<TunnelStatus[]>("get_tunnel_statuses")),
      ]);
    setDaemon(daemonStatus);
    setBackends(availability ?? []);
    setProxy(proxyStatus);
    const primary = (ifaces ?? [])
      .filter((i) => i.state === "up" && i.gateway !== null && i.physical)
      .sort((a, b) => a.ifIndex - b.ifIndex)[0];
    setPrimaryIface(primary?.friendlyName ?? primary?.name ?? null);
    const active = statusList?.find((s) => s.state === "running");
    setActiveName(
      active
        ? (profileList?.find((p) => p.id === active.profileId)?.name ?? null)
        : null,
    );
  }, []);

  useEffect(() => {
    void poll();
    const onChanged = () => void poll();
    window.addEventListener("route-changed", onChanged);
    const interval = setInterval(() => void poll(), 10000);
    return () => {
      window.removeEventListener("route-changed", onChanged);
      clearInterval(interval);
    };
  }, [poll]);

  const daemonUi = daemon ? DAEMON_STATE_UI[daemon.state] : null;
  const xray = backends.find((b) => b.backend === "xray");

  return (
    <div className="status-bar">
      {daemon && daemonUi && (
        <span
          className="status-bar-cell"
          title={daemon.message || undefined}
        >
          <span className={`status-dot ${daemonUi.dot}`} />
          {t("statusbar.daemon")}:{" "}
          <span className="status-bar-mono">{t(daemonUi.key)}</span>
        </span>
      )}
      {xray && (
        <span className="status-bar-cell" title={xray.message || undefined}>
          <span
            className={`status-dot ${xray.available ? "state-running" : "state-unknown"}`}
          />
          Xray:{" "}
          <span className="status-bar-mono">
            {xray.available
              ? xray.version || t("statusbar.state.ready")
              : t("statusbar.state.absent")}
          </span>
        </span>
      )}
      {proxy && (
        <span className="status-bar-cell">
          <span
            className={`status-dot ${proxy.ownerProfileId ? "state-running" : "state-unknown"}`}
          />
          {t("native.systemProxy")}:{" "}
          <span className="status-bar-mono">
            {proxy.ownerName ?? t("common.off")}
          </span>
        </span>
      )}
      {primaryIface && (
        <span className="status-bar-cell">
          <span className="status-dot state-running" />
          {t("native.primaryRoute", { iface: primaryIface })}
        </span>
      )}
      <span className="status-bar-right">
        {activeName && (
          <span className="status-bar-cell" title={activeName}>
            <span className="status-dot state-running" />
            <span className="status-bar-active-name">{activeName}</span>
          </span>
        )}
        <span className="status-bar-cell">
          {t("statusbar.active", { count: activeCount })}
        </span>
      </span>
    </div>
  );
}
