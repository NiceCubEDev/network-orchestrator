import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import Modal from "./Modal";
import { ensureElevation } from "../elevation";
import { BatchImportResult, TunnelBackend } from "../types";
import { usePlatformCapabilities } from "../platform";
import { tr, useT } from "../i18n";

type ImportTab = "files" | "link" | "subscription" | "wireguard";

const REFRESH_OPTIONS: { minutes: number | null; label: () => string }[] = [
  { minutes: null, label: () => "" },
  { minutes: 15, label: () => tr("15 min") },
  { minutes: 60, label: () => tr("1 hour") },
  { minutes: 360, label: () => tr("6 hours") },
];

const isSubscriptionUrl = (text: string) => /^https?:\/\//i.test(text.trim());

const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

interface ImportModalProps {
  open: boolean;
  onClose: () => void;
  onImported: (result: BatchImportResult) => void;
  onError: (message: string) => void;
}

export default function ImportModal({
  open,
  onClose,
  onImported,
  onError,
}: ImportModalProps) {
  const [tab, setTab] = useState<ImportTab>("files");
  const caps = usePlatformCapabilities();
  const [busy, setBusy] = useState(false);
  const [files, setFiles] = useState<string[]>([]);
  const [fileBackend, setFileBackend] = useState<TunnelBackend | "">("");
  const [shareLink, setShareLink] = useState("");
  const [linkName, setLinkName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [subHwid, setSubHwid] = useState("");
  const [generatingHwid, setGeneratingHwid] = useState(false);
  const [subRefreshMinutes, setSubRefreshMinutes] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const t = useT();

  const switchTab = (next: ImportTab) => {
    setTab(next);
    setError(null);
  };

  const run = async (job: () => Promise<BatchImportResult | null>) => {
    setBusy(true);
    setError(null);
    try {
      const result = await job();
      if (!result) return;
      onImported(result);
      setFiles([]);
      setShareLink("");
      setLinkName("");
      setSubUrl("");
      setSubHwid("");
      setSubRefreshMinutes(null);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const chooseFiles = async () => {
    try {
      const selected = await openDialog({
        multiple: true,
        directory: false,
        filters: [
          {
            name: t("import.filesFilter"),
            extensions: ["conf", "dpapi", "ovpn", "json"],
          },
          { name: tr("All files"), extensions: ["*"] },
        ],
      });
      const paths = Array.isArray(selected) ? selected : selected ? [selected] : [];
      if (paths.length > 0) {
        setFiles(paths);
        setError(null);
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const submit = () => {
    if (busy || generatingHwid) return;
    if (tab === "files") {
      if (files.length === 0) return;
      void run(() =>
        invoke<BatchImportResult>("import_configs_batch", {
          paths: files,
          defaultBackend: fileBackend || null,
        }),
      );
    } else if (tab === "link") {
      const link = shareLink.trim();
      if (!link) return;
      // A pasted http(s) URL is a subscription, like in the native client.
      if (isSubscriptionUrl(link)) {
        void run(() =>
          invoke<BatchImportResult>("import_subscription", {
            url: link,
            hwid: subHwid.trim(),
            refreshIntervalMinutes: null,
          }),
        );
      } else {
        void run(() =>
          invoke<BatchImportResult>("import_share_link", {
            link,
            name: linkName.trim(),
          }),
        );
      }
    } else if (tab === "subscription") {
      if (!subUrl.trim()) return;
      void run(() =>
        invoke<BatchImportResult>("import_subscription", {
          url: subUrl.trim(),
          hwid: subHwid.trim(),
          refreshIntervalMinutes: subRefreshMinutes,
        }),
      );
    } else {
      void run(async () => {
        if (!(await ensureElevation(t("elev.actImportWg")))) return null;
        const paths = await invoke<string[]>("discover_wireguard_configs");
        if (paths.length === 0) {
          onError(t("import.noWgConfigs"));
          return null;
        }
        return invoke<BatchImportResult>("import_configs_batch", {
          paths,
          defaultBackend: "wireGuard",
        });
      });
    }
  };

  const generateHwid = async () => {
    if (busy || generatingHwid) return;
    setGeneratingHwid(true);
    setError(null);
    try {
      setSubHwid(await invoke<string>("generate_subscription_hwid"));
    } catch {
      setError("Could not generate a device ID. Enter an HWID manually.");
    } finally {
      setGeneratingHwid(false);
    }
  };

  const hwidField = (
    <>
      <label>
        {t("import.hwid")}
        <input
          type="password"
          value={subHwid}
          onChange={(event) => setSubHwid(event.target.value)}
          placeholder="device-hwid"
          autoComplete="off"
          disabled={busy || generatingHwid}
        />
      </label>
      {caps?.os === "windows" && (
        <>
          <div>
            <button type="button" className="btn-sm" onClick={() => void generateHwid()} disabled={busy || generatingHwid}>
              {t("native.hwidAuto")}
            </button>
          </div>
          <p className="profile-help">
            {tr("This app may count as a separate device in your subscription.")}
          </p>
        </>
      )}
    </>
  );

  const canSubmit =
    !busy && !generatingHwid &&
    (tab === "files"
      ? files.length > 0
      : tab === "link"
        ? shareLink.trim() !== ""
        : tab === "subscription"
          ? subUrl.trim() !== ""
          : true);

  const submitLabel = busy
    ? tab === "subscription" || (tab === "link" && isSubscriptionUrl(shareLink))
      ? t("import.fetching")
      : t("import.importing")
    : tab === "subscription"
      ? t("import.fetch")
      : tab === "wireguard"
        ? t("import.wgImport")
        : tr("Import");

  const tabs: { id: ImportTab; label: string }[] = [
    { id: "files", label: t("import.tabFiles") },
    { id: "link", label: tr("Link") },
    { id: "subscription", label: t("import.tabSub") },
    ...(caps?.wireguardStandardImport
      ? [{ id: "wireguard" as const, label: tr("WireGuard location") }]
      : []),
  ];

  return (
    <Modal
      open={open}
      title={t("import.title")}
      onClose={onClose}
      maxWidth="520px"
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" form="import-form" className="btn-primary" disabled={!canSubmit}>
            {submitLabel}
          </button>
        </>
      }
    >
      <div className="modal-tabs">
        {tabs.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`modal-tab ${tab === item.id ? "active" : ""}`}
            onClick={() => switchTab(item.id)}
            disabled={busy || generatingHwid}
          >
            {item.label}
          </button>
        ))}
      </div>

      <form
        id="import-form"
        className="modal-tab-body"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        {tab === "files" && (
          <>
            <p className="profile-help">{t("import.filesHelp")}</p>
            <div>
              <button type="button" onClick={() => void chooseFiles()} disabled={busy}>
                {tr("Choose files…")}
              </button>
            </div>
            {files.length > 0 && (
              <>
                <ul className="import-file-list">
                  {files.map((path) => (
                    <li key={path} title={path}>
                      {baseName(path)}
                    </li>
                  ))}
                </ul>
                <label className="import-row">
                  <span>{tr("Backend")}</span>
                  <select
                    value={fileBackend}
                    onChange={(event) => setFileBackend(event.target.value as TunnelBackend | "")}
                    disabled={busy}
                  >
                    <option value="">{tr("Detect from file")}</option>
                    <option value="wireGuard">{tr("WireGuard")}</option>
                    <option value="openVpn">{tr("OpenVPN")}</option>
                    <option value="xray">{tr("Xray")}</option>
                  </select>
                </label>
              </>
            )}
            <p className="profile-help">
              {tr("A private, managed copy is stored locally. Import does not start a VPN.")}
            </p>
          </>
        )}

        {tab === "link" && (
          <>
            <p className="profile-help">
              {t("native.linkHint")}
            </p>
            <label>
              {tr("Share link")}
              <input
                type="password"
                value={shareLink}
                onChange={(event) => { setShareLink(event.target.value); setError(null); }}
                placeholder={tr("vless:// or hysteria2://…")}
                autoComplete="off"
                spellCheck={false}
                maxLength={65536}
                disabled={busy}
                autoFocus
              />
            </label>
            {!isSubscriptionUrl(shareLink) ? (
              <label>
                {tr("Connection name (optional)")}
                <input
                  type="text"
                  value={linkName}
                  onChange={(event) => setLinkName(event.target.value)}
                  placeholder={tr("Use the name from the link")}
                  disabled={busy}
                />
              </label>
            ) : (
              hwidField
            )}
          </>
        )}

        {tab === "subscription" && (
          <>
            <p className="profile-help">{t("import.subHelp")}</p>
            <label>
              {t("import.subUrl")}
              <input
                type="password"
                value={subUrl}
                onChange={(event) => { setSubUrl(event.target.value); setError(null); }}
                placeholder="https://example.com/sub"
                autoComplete="off"
                spellCheck={false}
                disabled={busy}
                autoFocus
              />
            </label>
            {hwidField}
            <div className="import-row">
              <span>{t("import.autoRefresh")}</span>
              <div className="filter-state" role="radiogroup" aria-label={t("import.autoRefresh")}>
                {REFRESH_OPTIONS.map((option) => (
                  <button
                    key={option.minutes ?? "off"}
                    type="button"
                    role="radio"
                    aria-checked={subRefreshMinutes === option.minutes}
                    className={`filter-btn ${subRefreshMinutes === option.minutes ? "active" : ""}`}
                    onClick={() => setSubRefreshMinutes(option.minutes)}
                    disabled={busy}
                  >
                    {option.minutes === null ? t("common.off") : option.label()}
                  </button>
                ))}
              </div>
            </div>
            <p className="profile-help">
              {tr("Import does not start a VPN.")}
            </p>
          </>
        )}

        {tab === "wireguard" && caps?.wireguardStandardImport && (
          <p className="profile-help">{t("import.wgHelp")}</p>
        )}

        {error && <p role="alert" className="error">{tr(error)}</p>}
      </form>
    </Modal>
  );
}
