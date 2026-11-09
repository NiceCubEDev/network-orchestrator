import { useCallback, useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { VpnIcon } from "../icons";
import { NetBirdState } from "../types";
import { useT } from "../i18n";
import Modal from "./Modal";
import OverflowMenu from "./ui/OverflowMenu";
import ToggleSwitch from "./ui/ToggleSwitch";
import { useToast } from "./ui/Toast";

const POLL_MS = 15000;

/** NetBird status plus the on/off action; polls while the Profiles page is open. */
export function useNetBird(enabled: boolean) {
  const toast = useToast();
  const [state, setState] = useState<NetBirdState | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!enabled || !isTauri()) return;
    try {
      setState(await invoke<NetBirdState>("netbird_status"));
    } catch {
      setState(null);
    }
  }, [enabled]);

  useEffect(() => {
    void refresh();
    const interval = setInterval(() => void refresh(), POLL_MS);
    window.addEventListener("route-changed", refresh);
    return () => {
      clearInterval(interval);
      window.removeEventListener("route-changed", refresh);
    };
  }, [refresh]);

  const isOn = state?.state === "connected" || state?.state === "connecting";

  /** Turns NetBird on (optionally with a server and setup key) or off. */
  const toggle = async (managementUrl?: string, setupKey?: string) => {
    if (busy || !state) return;
    setBusy(true);
    try {
      setState(
        isOn && !managementUrl
          ? await invoke<NetBirdState>("netbird_down")
          : await invoke<NetBirdState>("netbird_up", {
              managementUrl: managementUrl ?? null,
              setupKey: setupKey ?? null,
            }),
      );
    } catch (err) {
      toast("error", String(err));
    } finally {
      setBusy(false);
    }
  };

  return { state, busy, isOn, toggle };
}

export type NetBirdController = ReturnType<typeof useNetBird>;

/** "09:10" for a session ending within a day and a half; nothing otherwise. */
function sessionEnd(iso?: string | null): string | null {
  if (!iso) return null;
  const end = new Date(iso);
  const ahead = end.getTime() - Date.now();
  if (Number.isNaN(ahead) || ahead < 0 || ahead > 36 * 3600 * 1000) return null;
  return end.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function subtitle(state: NetBirdState, t: ReturnType<typeof useT>): string {
  switch (state.state) {
    case "connected": {
      const parts = [state.ip?.split("/")[0] ?? ""];
      if (state.peersConnected !== undefined && state.peersTotal !== undefined) {
        parts.push(
          t("native.netbird.peers", {
            connected: state.peersConnected,
            total: state.peersTotal,
          }),
        );
      }
      const until = sessionEnd(state.sessionExpiresAt);
      if (until) parts.push(t("native.netbird.session", { time: until }));
      return parts.filter(Boolean).join(" · ");
    }
    case "connecting":
      return t("native.netbird.connecting");
    case "needsLogin":
      return t("native.netbird.needsLogin");
    case "daemonStopped":
      return t("native.netbird.stopped");
    case "unavailable":
      return t("native.netbird.unavailable");
    default:
      return t("native.netbird.disconnected");
  }
}

/** A service row for the user's own NetBird daemon; nothing when it is absent. */
export default function NetBirdRow({
  netbird,
  interfaceNames,
}: {
  netbird: NetBirdController;
  interfaceNames: readonly string[];
}) {
  const t = useT();
  const [setupOpen, setSetupOpen] = useState(false);
  const { state, busy, isOn, toggle } = netbird;
  if (!state?.installed) return null;
  const canToggle = state.state !== "daemonStopped" && state.state !== "unavailable";
  const dot = isOn
    ? "running"
    : state.state === "needsLogin"
      ? "failed"
      : "stopped";
  const details = [...interfaceNames, subtitle(state, t)].filter(Boolean).join(" · ");

  return (
    <>
      <div className="profile-row">
        <span className={`status-dot state-${dot}`} />
        <span className="backend-avatar backend-avatar-service">
          <VpnIcon size={14} />
        </span>
        <span className="profile-row-name">NetBird</span>
        <span
          className={`profile-row-meta${state.state === "needsLogin" ? " warn" : ""}`}
          title={details}
        >
          {details}
        </span>
        <OverflowMenu
          items={[
            {
              label: t("native.netbird.setup"),
              onClick: () => setSetupOpen(true),
            },
          ]}
        />
        <ToggleSwitch
          checked={isOn}
          onChange={() => void toggle()}
          disabled={!canToggle}
          busy={busy || state.state === "connecting"}
          title={isOn ? t("common.disconnect") : t("common.connect")}
        />
      </div>
      <NetBirdSetupModal
        open={setupOpen}
        initialUrl={state.managementUrl ?? ""}
        onClose={() => setSetupOpen(false)}
        onSubmit={(url, key) => {
          setSetupOpen(false);
          void toggle(url, key);
        }}
      />
    </>
  );
}

/** Management address and optional one-time setup key; without a key the CLI
 * opens the browser for SSO. The key is never stored. */
function NetBirdSetupModal({
  open,
  initialUrl,
  onClose,
  onSubmit,
}: {
  open: boolean;
  initialUrl: string;
  onClose: () => void;
  onSubmit: (url: string, key: string) => void;
}) {
  const t = useT();
  const [url, setUrl] = useState(initialUrl);
  const [key, setKey] = useState("");

  useEffect(() => {
    if (open) {
      setUrl(initialUrl);
      setKey("");
    }
  }, [open, initialUrl]);

  const submit = () => onSubmit(url.trim(), key.trim());

  return (
    <Modal
      open={open}
      title="NetBird"
      onClose={onClose}
      maxWidth="420px"
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn-primary" onClick={submit}>
            {t("common.connect")}
          </button>
        </>
      }
    >
      <form
        className="profile-form"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <label>
          {t("native.netbird.url")}
          <input
            type="text"
            placeholder="https://netbird.example.com"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
          />
        </label>
        <label>
          {t("native.netbird.key")}
          <input
            type="password"
            autoComplete="off"
            value={key}
            onChange={(event) => setKey(event.target.value)}
          />
        </label>
        <span className="profile-help">{t("native.netbird.setupHint")}</span>
      </form>
    </Modal>
  );
}
