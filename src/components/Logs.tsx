import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Page from "./Page";
import { LogEvent, LogLevel, LoggingVerbosity } from "../types";
import { useT } from "../i18n";
import { usePlatformCapabilities } from "../platform";

const POLL_MS = 2000;
const MAX_RENDERED = 1000;

function formatTime(tsUnix: number): string {
  const d = new Date(tsUnix * 1000);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export default function Logs() {
  const t = useT();
  const caps = usePlatformCapabilities();
  const [verbosity, setVerbosity] = useState<LoggingVerbosity | null>(null);
  const [verbosityBusy, setVerbosityBusy] = useState(false);
  const [verbosityReadError, setVerbosityReadError] = useState(false);
  const [verbositySaveError, setVerbositySaveError] = useState(false);
  const verbositySaving = useRef(false);
  const verbosityRequest = useRef(0);
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [daemonLines, setDaemonLines] = useState<LogEvent[]>([]);
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState<"all" | LogLevel>("all");
  const [daemonOpen, setDaemonOpen] = useState(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const stickToBottom = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const data = await invoke<LogEvent[]>("get_logs");
      setEvents(data);
    } catch {
      // Log view must never break the UI; a failed fetch just keeps stale data.
    }
  }, []);

  const refreshVerbosity = useCallback(async () => {
    if (caps?.os !== "linux" || verbositySaving.current) return;
    const request = ++verbosityRequest.current;
    try {
      const current = await invoke<LoggingVerbosity | null>("get_logging_verbosity");
      if (request !== verbosityRequest.current) return;
      setVerbosity(current);
      setVerbosityReadError(current === null);
    } catch {
      if (request === verbosityRequest.current) setVerbosityReadError(true);
    }
  }, [caps?.os]);

  const changeVerbosity = async (value: LoggingVerbosity) => {
    verbositySaving.current = true;
    ++verbosityRequest.current;
    setVerbosityBusy(true);
    setVerbositySaveError(false);
    try {
      await invoke("set_logging_verbosity", { verbosity: value });
      const current = await invoke<LoggingVerbosity | null>("get_logging_verbosity");
      setVerbosity(current);
      setVerbosityReadError(current === null);
    } catch {
      setVerbositySaveError(true);
    } finally {
      verbositySaving.current = false;
      setVerbosityBusy(false);
    }
  };

  const refreshDaemon = useCallback(async () => {
    try {
      const lines = await invoke<LogEvent[]>("daemon_log_tail", { lines: 200 });
      setDaemonLines(lines);
    } catch (e) {
      setDaemonLines([
        {
          tsUnix: Math.floor(Date.now() / 1000),
          level: "warn",
          source: "app",
          message: t("logs.daemonUnavailable", { err: String(e) }),
        },
      ]);
    }
  }, [t]);

  useEffect(() => {
    void refresh();
    void refreshVerbosity();
    const id = setInterval(() => {
      void refresh();
      void refreshVerbosity();
    }, POLL_MS);
    return () => {
      clearInterval(id);
      ++verbosityRequest.current;
    };
  }, [refresh, refreshVerbosity]);

  useEffect(() => {
    if (daemonOpen) void refreshDaemon();
  }, [daemonOpen, refreshDaemon]);

  useEffect(() => {
    if (stickToBottom.current) {
      bottomRef.current?.scrollIntoView({ block: "end" });
    }
  }, [events, daemonLines]);

  const query = search.trim().toLowerCase();
  const filtered = events.filter((e) => {
    if (levelFilter !== "all" && e.level !== levelFilter) return false;
    if (query && !e.message.toLowerCase().includes(query)) return false;
    return true;
  });
  const shown = filtered.slice(-MAX_RENDERED);

  const clear = async () => {
    try {
      await invoke("clear_logs");
      setEvents([]);
    } catch {
      // keep the stale list visible
    }
  };

  return (
    <Page width="wide">
      <div className="filter-bar">
        <input
          className="filter-search"
          type="text"
          placeholder={t("logs.filterPlaceholder")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="filter-select"
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value as "all" | LogLevel)}
        >
          <option value="all">{t("logs.allLevels")}</option>
          <option value="info">{t("logs.levelInfo")}</option>
          <option value="warn">{t("logs.levelWarn")}</option>
          <option value="error">{t("logs.levelError")}</option>
        </select>
        <button className="btn-sm" onClick={() => void refresh()}>
          {t("common.refresh")}
        </button>
        <button className="btn-sm" onClick={() => void clear()}>
          {t("common.clear")}
        </button>
      </div>

      {caps?.os === "linux" && (
        <>
          <div className="settings-row">
            <div className="settings-row-main">
              <span className="settings-row-label">{t("Daemon diagnostic verbosity")}</span>
              <span className="settings-row-sub">{t("Debug and trace add diagnostic metadata and can increase journal volume and overhead. These diagnostics omit secrets.")}</span>
            </div>
            <select
              aria-label={t("Daemon diagnostic verbosity")}
              value={verbosity ?? ""}
              disabled={verbosity === null || verbosityBusy}
              onChange={(e) => void changeVerbosity(e.target.value as LoggingVerbosity)}
            >
              {verbosity === null && <option value="">{verbosityReadError ? t("Unavailable") : t("Loading…")}</option>}
              <option value="normal">{t("Normal")}</option>
              <option value="debug">{t("Debug")}</option>
              <option value="trace">{t("Trace")}</option>
            </select>
          </div>
          {verbosityReadError && <div className="save-notice" role="alert">{t("Could not read daemon diagnostic verbosity. Retrying automatically.")}</div>}
          {verbositySaveError && <div className="save-notice" role="alert">{t("Could not change or confirm daemon diagnostic verbosity. The setting may have changed; it will be refreshed automatically.")}</div>}
        </>
      )}

      <div
        className="log-view"
        onScroll={(e) => {
          const el = e.currentTarget;
          stickToBottom.current =
            el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
      >
        {shown.length === 0 ? (
          <div className="log-empty">
            {events.length === 0
              ? t("logs.empty")
              : t("logs.noMatch")}
          </div>
        ) : (
          shown.map((e, i) => (
            <div key={`${e.tsUnix}-${i}`} className={`log-line log-${e.level}`}>
              <span className="log-ts">{formatTime(e.tsUnix)}</span>
              <span className={`log-level log-level-${e.level}`}>{e.level}</span>
              <span className="log-msg">{e.message}</span>
            </div>
          ))
        )}
        {filtered.length > MAX_RENDERED && (
          <div className="log-empty">
            {t("logs.showingLast", {
              shown: MAX_RENDERED,
              total: filtered.length,
            })}
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="daemon-log">
        <button
          className="filter-btn daemon-log-toggle"
          onClick={() => setDaemonOpen((v) => !v)}
        >
          {daemonOpen ? t("logs.hideDaemon") : t("logs.showDaemon")}
        </button>
        {daemonOpen && (
          <div className="log-view log-view-daemon">
            {daemonLines.map((e, i) => (
              <div key={`d-${e.tsUnix}-${i}`} className={`log-line log-${e.level}`}>
                <span className="log-ts">{formatTime(e.tsUnix)}</span>
                <span className={`log-level log-level-${e.level}`}>{e.level}</span>
                <span className="log-msg">{e.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Page>
  );
}
